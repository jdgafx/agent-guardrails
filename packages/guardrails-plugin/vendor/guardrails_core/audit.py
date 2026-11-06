"""Audit log (one JSON object per line), the per-session call counter and the decision memo."""
import json
import os
import re
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
