"""Other agents, the same engine.

An adapter turns one agent's hook input into the hook input of Claude Code (tool_name, tool_input,
session_id, ...) and hands it to hooks.run_pre / hooks.run_post, so every agent gets the same
rules, redaction, injection scan, session mark and audit log. Then it turns the answer back into
the shape that agent reads.

    python3 -m guardrails_core.adapters <claude-code|cursor|codex|generic> [--data DIR]

The hook input comes on stdin. Fail-safe: any failure before a call is an ask (a deny where the
agent has no ask), never an allow. mcp_proxy.py and shell_guard.py call check() too.
"""
import argparse
import json
import os
import re
import sys

from . import hooks

AGENTS = ("claude-code", "cursor", "codex", "generic")
_PATCH_FILE = re.compile(r"^\*\*\* (?:(?:Add|Update|Delete) File|Move to): (.+?)\s*$", re.M)
NO_ASK = " (%s cannot ask the person, so the call was refused. Run it yourself if you want it.)"


def plugin_root():
    """The folder that holds policy.json: GUARDRAILS_ROOT, else found from this file's place (the
    plugin's vendor copy, or a clone)."""
    here = os.path.dirname(os.path.abspath(__file__))
    for root in (os.environ.get("GUARDRAILS_ROOT"), os.path.join(here, "..", ".."),
                 os.path.join(here, "..", "..", "..", "guardrails-plugin")):
        if root and os.path.isfile(os.path.join(root, "policy.json")):
            return os.path.normpath(root)
    raise RuntimeError("policy.json not found: set GUARDRAILS_ROOT to the plugin folder")


def data_dir():
    """Where the log and the session state go: the folder Claude Code gives the plugin when set,
    so every agent writes one log; else ~/.agent-guardrails."""
    return (os.environ.get("GUARDRAILS_DATA") or os.environ.get("CLAUDE_PLUGIN_DATA")
            or os.path.join(os.path.expanduser("~"), ".agent-guardrails"))


def mcp_name(server, tool):
    """mcp__<server>__<tool>, the name the rules read. The server part never holds "__"."""
    if tool.startswith("mcp__"):
        return tool
    server = re.sub(r"_{2,}", "_", re.sub(r"[^A-Za-z0-9_-]", "_", str(server))) or "unknown"
    return "mcp__%s__%s" % (server, tool)


def _text(v):
    """A value that may have come as JSON text (Cursor sends MCP input and results as text)."""
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            pass
    return v


def _obj(v):
    """The tool input as an object. Text that is not JSON is kept as one field, so the rules still
    read it; anything else that is not an object is refused (the caller asks)."""
    v = _text(v)
    if v is None:
        return {}
    if isinstance(v, str):
        return {"input": v}
    if not isinstance(v, dict):
        raise ValueError("tool input must be a JSON object")
    return v


def _claude(p):
    return dict(p), str(p.get("hook_event_name", "")).startswith("PostToolUse")


def _codex(p):
    """Codex sends Claude Code's shape. A patch becomes an Edit of the files it names, and a
    command given as a word list becomes text, so the command rules read it."""
    p, post = _claude(p)
    tin = p.get("tool_input")
    if isinstance(tin, dict) and isinstance(tin.get("command"), list):
        tin = p["tool_input"] = dict(tin, command=" ".join(str(x) for x in tin["command"]))
    if p.get("tool_name") == "apply_patch" and isinstance(tin, dict):
        # whichever field holds the patch; one whose files cannot be read is not guessed at
        files = _PATCH_FILE.findall("\n".join(str(v) for v in tin.values()))
        if not files:
            raise ValueError("apply_patch names no file this guard can read")
        p["tool_name"], p["tool_input"] = "Edit", {"file_path": files[0], "file_paths": files}
    return p, post


def _cursor(p):
    ev = str(p.get("hook_event_name", ""))
    out = {"session_id": p.get("conversation_id"), "tool_use_id": p.get("generation_id"),
           "cwd": p.get("cwd") or (p.get("workspace_roots") or [None])[0]}
    if ev.endswith("ShellExecution"):
        out.update(tool_name="Bash", tool_input={"command": str(p.get("command", ""))})
        result = {"stdout": p.get("output", "")}
    elif ev.endswith("MCPExecution"):
        server = (p.get("mcp_server_name")
                  or os.path.basename(str(p.get("command") or "").split(" ")[0]) or "unknown")
        out.update(tool_name=mcp_name(server, str(p.get("tool_name"))),
                   tool_input=_obj(p.get("tool_input")))
        result = _text(p.get("result_json"))
    elif ev == "beforeReadFile":  # the file's content comes too; it is dropped here, never logged
        out.update(tool_name="Read", tool_input={"file_path": str(p.get("file_path", ""))})
    else:
        raise ValueError("unknown Cursor hook event %r" % ev)
    post = ev.startswith("after")
    if post:
        out["tool_response"] = result
    return out, post


def _generic(p):
    """{"tool": name, "input": {...}} or {"command": "..."}; Claude Code's own field names work
    too. A "result" (or "tool_response", or "error") that is not null makes it the
    after-the-call report; a null one does not, so it cannot skip the check."""
    out = {k: p[k] for k in ("tool_response", "error", "hook_event_name", "cwd")
           if p.get(k) is not None}
    if p.get("result") is not None:
        out["tool_response"] = p["result"]
    tin = _obj(p.get("tool_input", p.get("input")))
    if "command" in p:  # a top-level command is always read, whatever "input" holds
        tin = dict(tin, command=p["command"])
    out.update(tool_name=p.get("tool_name") or p.get("tool") or ("Bash" if "command" in p else ""),
               tool_input=tin, session_id=p.get("session_id") or p.get("session"),
               tool_use_id=p.get("tool_use_id") or p.get("id"))
    return out, "tool_response" in out or "error" in out


_SHAPES = {"claude-code": _claude, "codex": _codex, "cursor": _cursor, "generic": _generic}


def normalize(agent, payload):
    """(hook input in Claude Code's shape, True for the after-the-call report). Generic input may
    name its own agent ("agent": "aider"); that name is the label in the log."""
    if not isinstance(payload, dict):
        raise ValueError("hook input must be a JSON object")
    p, post = _SHAPES[agent](payload)
    p = {k: v for k, v in p.items() if v is not None}
    p["agent"] = str(payload.get("agent") or agent) if agent == "generic" else agent
    return p, post


def check(agent, payload, root, data):
    """One call through the engine. Before the call: (False, decision, reason). After it:
    (True, what hooks.run_post printed as an object, "")."""
    p, post = normalize(agent, payload)
    raw = json.dumps(p)
    if post:
        out = hooks.run_post(raw, root, data)
        return True, json.loads(out) if out else {}, ""
    out = hooks.run_pre(raw, root, data)
    if not out:
        return False, "allow", ""
    h = json.loads(out)["hookSpecificOutput"]
    return False, h["permissionDecision"], h["permissionDecisionReason"]


def answer(agent, event, decision, reason):
    """(stdout text, exit code) for a before-the-call decision, in the agent's own shape."""
    if agent == "cursor":
        if decision == "ask" and event == "beforeReadFile":  # that hook takes allow or deny only
            decision, reason = "deny", reason + NO_ASK % "Cursor's file-read hook"
        out = {"permission": decision}
        if decision != "allow":
            out.update(user_message="agent-guardrails: " + reason, agent_message=reason)
        return json.dumps(out), 0
    if agent in ("claude-code", "codex"):
        if decision == "allow":
            return "", 0
        if agent == "codex" and decision == "ask":
            # Codex's hook doc: an "ask" answer fails the hook and the call runs. So refuse.
            decision, reason = "deny", reason + NO_ASK % "A Codex hook"
        return hooks.pre_json(decision, reason), 0
    return json.dumps({"decision": decision, "reason": reason}), 0 if decision == "allow" else 2


def after(agent, out):
    """stdout text for the after-the-call report. Cursor reads nothing back from those hooks."""
    if agent == "cursor" or not out:
        return ""
    if agent == "codex":  # Codex fails a hook that prints a field it does not know
        out.get("hookSpecificOutput", {}).pop("updatedToolOutput", None)
    return json.dumps(out)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="guardrails_core.adapters",
                                 description="One agent's hook input through the guard.")
    ap.add_argument("agent", choices=AGENTS)
    ap.add_argument("--data", help="the data folder (default: see data_dir)")
    args = ap.parse_args(argv)
    event = ""
    try:
        payload = json.loads(sys.stdin.read())
        event = str(payload.get("hook_event_name", "")) if isinstance(payload, dict) else ""
        post, a, b = check(args.agent, payload, plugin_root(), args.data or data_dir())
    except Exception as e:
        if event.startswith(("after", "PostToolUse")):  # a log failure does not block the agent
            sys.stderr.write("guardrails audit failed: %s: %s\n" % (type(e).__name__, e))
            return 1
        post, a, b = False, "ask", "[guardrails-error] %s: %s" % (type(e).__name__, e)
    out, code = (after(args.agent, a), 0) if post else answer(args.agent, event, a, b)
    sys.stdout.write(out)
    return code


if __name__ == "__main__":
    sys.exit(main())
