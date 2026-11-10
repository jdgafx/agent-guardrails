"""Answers a person gives from the dashboard: one waiting call, or a pass for the session.

A waiting call: an agent that cannot ask (Codex, a shell wrapper, an MCP client) holds an `ask`
and waits for a person to answer it in the dashboard (adapters.check, opt-in with
GUARDRAILS_WEB_APPROVAL=1). No answer in time is a deny.

A session pass: one rule of the policy file, for one tool, is allowed for the rest of one
session. hooks.run_pre decides when a pass counts: only for an `ask` rule of the policy file,
never for a deny rule that asks on a shell, a marked session, or a built-in ask (guard files, the
step cap, a guard error).

Standard library only. Everything lives in <data>/state, which the guard-path check keeps the
agent's file tools out of.
"""
import glob
import json
import os
import secrets
import time

from . import audit
from .redact import redact

ACTIONS = ("allow", "allow-session", "deny")


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _allow_path(data, session_id):
    return os.path.join(os.path.abspath(data), "state", audit.safe_name(session_id) + ".allow")


def _rows(path):
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict):
                    yield row
    except OSError:
        return


def is_session_allowed(data, session_id, rule_id, tool_name):
    """True when a person gave this session a pass for exactly this rule and this tool."""
    if not data or not session_id or not rule_id or not tool_name:
        return False
    return any(row.get("rule") == rule_id and row.get("tool") == tool_name
               for row in _rows(_allow_path(data, session_id)))


def allow_for_session(data, session_id, rule_id, tool_name):
    """Give the session a pass for one rule and one tool, and log that a person did it."""
    sid = audit.safe_name(session_id)
    row = {"ts": _now(), "rule": str(rule_id), "tool": str(tool_name)}
    if not is_session_allowed(data, sid, row["rule"], row["tool"]):
        os.makedirs(os.path.join(data, "state"), mode=0o700, exist_ok=True)
        audit._append(_allow_path(data, sid), json.dumps(row) + "\n")
    audit.write_audit(data, {
        "session_id": sid, "tool_name": row["tool"], "event": "session-allow",
        "decision": "allow", "rule": row["rule"], "input": {},
        "reason": "A person allowed rule %s on %s for the rest of session %s."
                  % (row["rule"], row["tool"], sid), "agent": "dashboard"}, {})
    return dict(row, session_id=sid)


def list_session_allows(data):
    """Every pass in force, as {session_id, rule, tool, ts}."""
    out = []
    for path in sorted(glob.glob(os.path.join(glob.escape(data), "state", "*.allow"))):
        sid = os.path.basename(path)[:-len(".allow")]
        out += [dict(row, session_id=sid) for row in _rows(path)]
    return out


def clear_session_allows(data, session_id):
    """Take back every pass of one session, and log it. Returns (name, whether one was there)."""
    name = audit.safe_name(session_id)
    try:
        os.unlink(_allow_path(data, name))
    except FileNotFoundError:
        return name, False
    audit.write_audit(data, {
        "session_id": name, "tool_name": "dashboard", "event": "session-allow-cleared",
        "decision": "allow", "rule": None, "input": {},
        "reason": "A person took back the passes of session %s." % name, "agent": "dashboard"}, {})
    return name, True


def _pending_dir(data):
    return os.path.join(os.path.abspath(data), "state", "pending")


def _write_atomic(path, obj):
    tmp = "%s.%d.tmp" % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (json.dumps(obj) + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(tmp, path)


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            req = json.load(f)
    except (OSError, ValueError):
        return None
    return req if isinstance(req, dict) else None


def request_approval(data, agent, session_id, tool_name, tool_input, rule_id, reason, timeout=60):
    """Hold one `ask` until a person answers it in the dashboard, at most `timeout` seconds.

    Returns ("allow", "") or ("deny", why). No answer, or a request file that went away, is a deny.
    """
    folder = _pending_dir(data)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    now = time.time()
    for old in glob.glob(os.path.join(glob.escape(folder), "req-*.json")):  # left by a killed hook
        req = _read(old)
        if req is None or req.get("expires_at", 0) < now:
            try:
                os.unlink(old)
            except OSError:
                pass
    req_id = "req-%d-%s" % (int(now * 1000), secrets.token_hex(4))
    path = os.path.join(folder, req_id + ".json")
    sid = str(session_id or "unknown")
    _write_atomic(path, {
        "id": req_id, "ts": _now(), "expires_at": now + timeout, "agent": str(agent or "unknown"),
        "session_id": sid, "tool_name": str(tool_name),
        "input": redact(tool_input if isinstance(tool_input, dict) else {}),
        "rule": str(rule_id), "reason": str(reason), "status": "pending"})
    try:
        while time.time() < now + timeout:
            status = (_read(path) or {}).get("status")
            if status in ("allow", "allow-session"):
                return "allow", ""
            if status != "pending":  # denied, or the file is gone or unreadable
                return "deny", "[%s] Denied in the dashboard: %s" % (rule_id, reason)
            time.sleep(0.15)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    audit.write_audit(data, {
        "session_id": sid, "tool_name": str(tool_name), "event": "approval-timeout",
        "decision": "deny", "rule": str(rule_id), "input": {},
        "reason": "Nobody answered in the dashboard within %d seconds." % timeout,
        "agent": str(agent or "unknown")}, {})
    return "deny", "[%s] Nobody answered in the dashboard in time: %s" % (rule_id, reason)


def list_pending(data):
    """The calls waiting for an answer now. Reads only: an expired file is skipped, not removed."""
    now, out = time.time(), []
    for path in sorted(glob.glob(os.path.join(glob.escape(_pending_dir(data)), "req-*.json"))):
        req = _read(path)
        if req and req.get("status") == "pending" and req.get("expires_at", 0) >= now:
            out.append(req)
    return out


def resolve_pending(data, req_id, action, passable=False):
    """Answer one waiting call. Returns the request, or None when it is gone or already answered.

    passable says whether its rule may get a session pass (the caller knows the policy); when it
    may not, allow-session answers this one call only.
    """
    if action not in ACTIONS:
        raise ValueError("invalid approval action")
    safe_id = audit.safe_name(req_id)
    path = os.path.join(_pending_dir(data), safe_id + ".json")
    req = _read(path)
    if not req or req.get("status") != "pending" or req.get("expires_at", 0) < time.time():
        return None
    req["status"] = action
    _write_atomic(path, req)
    sid, tool, rule = req.get("session_id", "unknown"), req.get("tool_name", ""), req.get("rule")
    audit.write_audit(data, {
        "session_id": sid, "tool_name": tool, "event": "approval-resolved",
        "decision": "deny" if action == "deny" else "allow", "rule": rule,
        "input": req.get("input", {}),
        "reason": "A person answered '%s' in the dashboard for call %s." % (action, safe_id),
        "agent": "dashboard"}, {})
    if action == "allow-session" and passable:
        allow_for_session(data, sid, rule, tool)
    return req
