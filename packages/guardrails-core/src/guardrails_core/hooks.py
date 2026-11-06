"""The two hook entry points. The plugin scripts call run_pre and run_post and nothing else.

Fail-safe rule: PreToolUse fails closed to "ask" (never to "allow"). PostToolUse only logs,
so it raises and the script reports a non-blocking error.
"""
import json
import os

from . import audit, injection, rules
from .policy import load_policy


def _parse(raw):
    p = json.loads(raw)
    if not isinstance(p, dict):
        raise ValueError("hook input must be a JSON object")
    name = p.get("tool_name")
    if not isinstance(name, str) or not name:
        raise ValueError("tool_name must be a non-empty string")
    if not isinstance(p.get("tool_input", {}), dict):
        raise ValueError("tool_input must be an object")
    return p


def _need_data(data):
    if not data:
        raise RuntimeError("CLAUDE_PLUGIN_DATA is not set, so nothing can be logged")


def pre_json(decision, reason):
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason}})


def _error_reason(exc):
    return ("Guardrails could not check this call (%s: %s). Asking instead of guessing."
            % (type(exc).__name__, exc))


def error_ask(exc):
    return pre_json("ask", "[guardrails-error] " + _error_reason(exc))


def _record(data, p, d, pol):
    """Save the decision memo and the audit line. Returns the first error, or None."""
    err = None
    tool, tin = p["tool_name"], p.get("tool_input", {})
    sid, tid = p.get("session_id", "unknown"), p.get("tool_use_id")
    try:
        _need_data(data)
        audit.remember_decision(data, sid, tid, d.decision, d.rule, d.step)
    except Exception as e:
        err = e
    if d.decision != "allow":
        try:
            audit.write_audit(data, {
                "session_id": sid, "tool_name": tool, "tool_use_id": tid,
                "event": "decision", "decision": d.decision, "rule": d.rule,
                "step": d.step, "input": tin, "reason": d.reason}, pol)
        except Exception as e:
            err = err or e
    return err


def _logged_error_ask(data, p, exc, step=None):
    """The error ask, logged like any decision so Post can copy it (a failed write is ignored)."""
    d = rules.Decision("ask", "guardrails-error", _error_reason(exc), step)
    _record(data, p or {"tool_name": "unknown"}, d, {})
    return error_ask(exc)


def _count(data, p):
    """The step number of this call, or None when it cannot be counted."""
    try:
        _need_data(data)
        return audit.next_step(data, p.get("session_id", "unknown"), p.get("tool_use_id"))
    except Exception:
        return None


def run_pre(raw, root, data):
    """Return the text to print on stdout. Empty text means allow (normal prompts still apply).

    The rules run before anything that can fail (policy trouble, an unwritable data folder), so
    a deny stays a deny. Only an allow that cannot be counted or logged becomes an ask.
    """
    p = None
    try:
        p = _parse(raw)
        tool, tin = p["tool_name"], p.get("tool_input", {})
        cwd = p.get("cwd") if isinstance(p.get("cwd"), str) and p.get("cwd") else os.getcwd()
        try:
            guard = rules.guard_check(tool, tin, rules.guard_paths(
                root, data, os.environ.get("GUARDRAILS_POLICY")), cwd)
        except Exception as e:  # guard trouble must not hide a deny of the rules: ask instead
            guard = rules.Decision("ask", "guardrails-error",
                                   "The guard-path check failed (%s). Confirm it." % e, None)
        try:
            pol, errors = load_policy(root, data)
        except Exception as e:
            if guard and guard.decision == "deny":  # broken shipped policy: the guard deny stands
                d = guard._replace(step=_count(data, p))
                _record(data, p, d, {})
                return pre_json(d.decision, "[%s] %s" % (d.rule, d.reason))
            return _logged_error_ask(data, p, e, _count(data, p))
        d = rules.stronger(guard, rules.match(pol, tool, tin))
        if d is None and errors:
            d = rules.Decision("ask", "guardrails-policy-error",
                               "An added policy file was left out, so its rules are off (the "
                               "shipped rules still apply). Fix or remove it: " + "; ".join(errors),
                               None)
        step = _count(data, p)
        if d is None:
            if step is None:
                return _logged_error_ask(data, p, RuntimeError("the call could not be counted"))
            d = rules.cap(pol, step) or rules.Decision("allow", "default-allow",
                                                       "No rule matched.", step)
        d = d._replace(step=step)
        err = _record(data, p, d, pol)
        if err and d.decision == "allow":  # a deny stays a deny; an unlogged allow becomes an ask
            return _logged_error_ask(data, p, err, step)
        return "" if d.decision == "allow" else pre_json(d.decision, "[%s] %s" % (d.rule, d.reason))
    except Exception as e:
        return _logged_error_ask(data, p, e)


def run_post(raw, root, data):
    """Write one audit line for a call that ran. Raises on error (the script reports it)."""
    p = _parse(raw)
    _need_data(data)
    pol, _ = load_policy(root, data)
    sid, tid, tool = p.get("session_id", "unknown"), p.get("tool_use_id"), p["tool_name"]
    prior = audit.recall_decision(data, sid, tid)
    failed = p.get("hook_event_name") == "PostToolUseFailure"
    resp = p["tool_response"] if "tool_response" in p else p.get("error", "")
    warnings, cut = injection.scan(pol, resp) if injection.is_scanned(pol, tool) else ([], False)
    bad = failed or (isinstance(resp, dict) and (resp.get("is_error") or resp.get("interrupted")))
    rec = {
        "session_id": sid, "tool_name": tool, "tool_use_id": tid,
        "event": "result", "decision": prior.get("decision", "unknown"),
        "rule": prior.get("rule"), "step": prior.get("step"),
        "input": p.get("tool_input", {}),
        "result_bytes": injection.result_bytes(resp),
        "status": "error" if bad else "ok", "warnings": warnings}
    if cut:
        rec["scan_truncated"] = True
    audit.write_audit(data, rec, pol)
