"""Audit log (one JSON object per line), the per-session call counter and the decision memo."""
import json
import os
import re
import stat
import time

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
    _append(os.path.join(folder, day + ".jsonl"), json.dumps(rec) + "\n")
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
