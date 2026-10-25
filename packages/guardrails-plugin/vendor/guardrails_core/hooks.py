"""The two hook entry points. The plugin scripts call run_pre and run_post and nothing else.

Fail-safe rule: PreToolUse fails closed to "ask" (never to "allow"). PostToolUse only logs,
so it raises and the script reports a non-blocking error.
"""
import json

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


def error_ask(exc):
    return pre_json("ask", "[guardrails-error] Guardrails could not check this call (%s: %s). "
                    "Asking instead of guessing." % (type(exc).__name__, exc))


def run_pre(raw, root, data):
    """Return the text to print on stdout. Empty text means allow (normal prompts still apply)."""
    try:
        p = _parse(raw)
        _need_data(data)
        pol = load_policy(root, data)
        sid, tid = p.get("session_id", "unknown"), p.get("tool_use_id")
        tool, tin = p["tool_name"], p.get("tool_input", {})
        step = audit.next_step(data, sid, tid)
        d = rules.evaluate(pol, tool, tin, step)
        reason = "[%s] %s" % (d.rule, d.reason)
        try:
            audit.remember_decision(data, sid, tid, d.decision, d.rule, step)
            if d.decision != "allow":
                audit.write_audit(data, {
                    "session_id": sid, "tool_name": tool, "tool_use_id": tid,
                    "event": "decision", "decision": d.decision, "rule": d.rule,
                    "step": step, "input": tin, "reason": d.reason}, pol)
        except Exception as e:  # a deny stays a deny; an unlogged allow becomes an ask
            if d.decision == "allow":
                return error_ask(e)
        return "" if d.decision == "allow" else pre_json(d.decision, reason)
    except Exception as e:
        return error_ask(e)


def run_post(raw, root, data):
    """Write one audit line for a call that ran. Raises on error (the script reports it)."""
    p = _parse(raw)
    _need_data(data)
    pol = load_policy(root, data)
    sid, tid, tool = p.get("session_id", "unknown"), p.get("tool_use_id"), p["tool_name"]
    prior = audit.recall_decision(data, sid, tid)
    resp = p.get("tool_response")
    warnings = injection.scan(pol, resp) if injection.is_untrusted_tool(pol, tool) else []
    bad = isinstance(resp, dict) and (resp.get("is_error") or resp.get("interrupted"))
    audit.write_audit(data, {
        "session_id": sid, "tool_name": tool, "tool_use_id": tid,
        "event": "result", "decision": prior.get("decision", "unknown"),
        "rule": prior.get("rule"), "step": prior.get("step"),
        "input": p.get("tool_input", {}),
        "result_bytes": len(injection.result_text(resp).encode("utf-8")),
        "status": "error" if bad else "ok", "warnings": warnings}, pol)
