"""Audit log (one JSON object per line), the per-session call counter and the decision memo."""
import glob
import hashlib
import json
import os
import re
import stat
import time

try:
    import fcntl  # not on Windows: there the chain is written without a lock
except ImportError:
    fcntl = None

from .redact import redact


def safe_name(session_id):
    return re.sub(r"[^A-Za-z0-9_\-]", "_", str(session_id))[:80] or "unknown"


def _private_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)


def _append(path, line):
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))  # one write call: parallel hooks do not interleave lines
    finally:
        os.close(fd)


GENESIS = "0" * 64


def _line_hash(prev, raw):
    return hashlib.sha256(prev.encode("ascii") + b"\n" + raw).hexdigest()


def _append_chained(folder, day, raw_line):
    """Append the log line and its chain record `<n> <previous hash> <hash>` as one step.

    The chain file is locked for both writes, so two hooks at the same moment cannot cross. When
    the chain cannot be opened or written the log line is still written: a line with no chain
    record shows up in verify_chain, a missing log line would not."""
    log, chain = os.path.join(folder, day + ".jsonl"), os.path.join(folder, day + ".chain")
    try:
        fd = os.open(chain, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    except OSError:
        return _append(log, raw_line)
    try:
        if fcntl:
            fcntl.flock(fd, fcntl.LOCK_EX)
        seq, prev = 1, GENESIS
        try:
            size = os.fstat(fd).st_size
            os.lseek(fd, max(0, size - 200), os.SEEK_SET)
            tail = os.read(fd, 200).splitlines()[-1].split() if size else []
            if len(tail) == 3:
                seq, prev = int(tail[0]) + 1, tail[2].decode("ascii")
        except (OSError, ValueError, IndexError):
            pass  # an unreadable tail starts a new run; verify_chain reports the break
        _append(log, raw_line)
        try:
            digest = _line_hash(prev, raw_line.rstrip("\n").encode("utf-8"))
            os.write(fd, ("%d %s %s\n" % (seq, prev, digest)).encode("ascii"))
        except OSError:
            pass
    finally:
        os.close(fd)  # closing lets the lock go


def verify_chain(data):
    """Check every day's log against its chain. Returns {ok, verified_lines, unchained_lines,
    tampered_file, detail}.

    A chain covers the lines written since it began, so it is matched against the end of its log:
    lines written before the chain existed (an older hook, the day of an update) are counted as
    unchained, not as tampering. A day with no chain file is unchained too.

    What it shows: a logged line was edited, removed or added by something that did not also
    rewrite the chain. It does not stop a program running as this user that rewrites both files.
    """
    folder = os.path.join(data, "audit")
    out = {"ok": True, "verified_lines": 0, "unchained_lines": 0, "tampered_file": None}
    for log in sorted(glob.glob(os.path.join(glob.escape(folder), "*.jsonl"))):
        name = os.path.basename(log)
        try:
            with open(log, "rb") as f:
                lines = f.read().splitlines()
            try:
                with open(log[:-len(".jsonl")] + ".chain", "rb") as f:
                    records = f.read().splitlines()
            except FileNotFoundError:
                out["unchained_lines"] += len(lines)
                continue
        except OSError as e:
            return dict(out, ok=False, tampered_file=name, detail="Cannot read %s: %s" % (name, e))
        if len(records) > len(lines):
            return dict(out, ok=False, tampered_file=name,
                        detail="%s has %d lines but %d chain records: lines were removed"
                               % (name, len(lines), len(records)))
        first = len(lines) - len(records)
        out["unchained_lines"] += first
        prev = GENESIS
        for n, (raw, record) in enumerate(zip(lines[first:], records), 1):
            parts, at = record.decode("ascii", "replace").split(), first + n
            if (len(parts) != 3 or parts[0] != str(n) or parts[1] != prev
                    or parts[2] != _line_hash(prev, raw)):
                return dict(out, ok=False, tampered_file=name,
                            detail="%s line %d does not match its chain record" % (name, at))
            prev = parts[2]
            out["verified_lines"] += 1
    if not out["verified_lines"] and not out["unchained_lines"]:
        return dict(out, detail="No audit log yet")
    return dict(out, detail="%d line(s) match their chain; %d line(s) written before the chain "
                            "began" % (out["verified_lines"], out["unchained_lines"]))


def write_audit(data, record, policy):
    """Append one redacted line to <data>/audit/<UTC date>.jsonl. Returns the record written."""
    cfg = policy.get("audit", {})
    rec = redact(record)
    limit = cfg.get("max_input_chars", 2000)
    text = json.dumps(rec.get("input", {}), ensure_ascii=False)
    if len(text) > limit:
        rec["input"] = {"truncated": text[:limit]}
    rec = dict(ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **rec)
    rec["agent"] = str(rec.get("agent") or "claude-code")[:40]  # which agent made the call
    if cfg.get("otel_field_names", True):  # field names in the style of OpenTelemetry GenAI
        rec["gen_ai.tool.name"] = rec.get("tool_name")
        rec["gen_ai.tool.call.id"] = rec.get("tool_use_id")
        rec["gen_ai.conversation.id"] = rec.get("session_id")
    folder = os.path.join(data, "audit")
    _private_dir(folder)
    day = time.strftime("%Y-%m-%d", time.gmtime())
    # ensure_ascii (the default): the line is ASCII, so a lone surrogate cannot break the write
    _append_chained(folder, day, json.dumps(rec) + "\n")
    return rec


def _state_path(data, session_id, suffix):
    folder = os.path.join(data, "state")
    _private_dir(folder)
    return os.path.join(folder, safe_name(session_id) + suffix)


def next_step(data, session_id, tool_use_id):
    """Count this call and return its step number (1-based).

    shortcut: two hooks racing can get the same number, so the cap is soft. Fine for a
    runaway guard. Upgrade to a file lock if the cap ever needs to be exact.
    """
    path = _state_path(data, session_id, ".calls")
    _append(path, json.dumps({"id": tool_use_id}) + "\n")
    with open(path, "rb") as f:
        return sum(1 for _ in f)


def remember_decision(data, session_id, tool_use_id, decision, rule, step):
    """Tell PostToolUse what PreToolUse decided for this call."""
    row = {"id": tool_use_id, "decision": decision, "rule": rule, "step": step}
    _append(_state_path(data, session_id, ".decisions"), json.dumps(row) + "\n")


def recall_decision(data, session_id, tool_use_id):
    path = _state_path(data, session_id, ".decisions")
    found = {}
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if row.get("id") == tool_use_id:
                    found = row
    return found


def mark_path(data, session_id):
    """Where the session mark lives. It does not create the folder."""
    return os.path.join(os.path.abspath(data), "state", safe_name(session_id) + ".taint")


def mark_session(data, session_id, row):
    """Mark the session: one JSON line per flagged outside-content result."""
    _append(_state_path(data, session_id, ".taint"), json.dumps(row) + "\n")


def mark_row(p, tool, warnings):
    """What marked a session, for the reason text and for the person reading the dashboard: the
    call, when, what it fetched and the phrases that matched. Redacted and cut like a log line."""
    row = redact({"id": p.get("tool_use_id"), "tool": tool,
                  "markers": [w.get("marker") or w["warning"] for w in warnings],
                  "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "agent": str(p.get("agent") or "claude-code")[:40],
                  "input": p.get("tool_input", {}),
                  "excerpts": [str(w.get("excerpt") or "")[:200] for w in warnings]})
    text = json.dumps(row["input"], ensure_ascii=False)
    if len(text) > 500:
        row["input"] = {"truncated": text[:500]}
    return row


def is_marked(data, session_id):
    """True when the mark file is there and not empty. A missing file is False; any other trouble
    (no data folder, a directory in its place, no read permission) is raised, so the caller asks."""
    if not data:
        raise RuntimeError("CLAUDE_PLUGIN_DATA is not set, so the session mark cannot be read")
    try:
        st = os.stat(mark_path(data, session_id))
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(st.st_mode):
        raise OSError("%s is not a file" % mark_path(data, session_id))
    return st.st_size > 0


def first_mark(data, session_id):
    """The first mark row that parses, or None. Only for the reason text, never for the decision."""
    try:
        with open(mark_path(data, session_id), encoding="utf-8") as f:
            for line in f:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict):
                    return row
    except OSError:
        pass
    return None
