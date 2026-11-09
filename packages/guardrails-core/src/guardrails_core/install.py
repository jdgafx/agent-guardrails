"""Wire the guard into an agent, so nobody copies JSON by hand (the dashboard's --install).

claude  runs Claude Code's own plugin commands.
cursor  adds hook entries to ~/.cursor/hooks.json.
codex   adds hook entries to ~/.codex/hooks.json.

A hooks file keeps every entry it had. A second run changes nothing, except that an entry of an
older copy of the guard gets the new path. The file as it was is kept beside it as
hooks.json.guardrails-bak the first time. A hooks file that is not valid JSON is left alone.
"""
import json
import os
import shlex
import shutil
import subprocess

from .discovery import HOOK_MARK

TARGETS = ("claude", "cursor", "codex")
PLUGIN_KEY = "agent-guardrails@agent-guardrails"
GITHUB = "jdgafx/agent-guardrails"
# Cursor: (event, block the call when the hook itself fails). The after-hooks only log and scan.
CURSOR_EVENTS = (("beforeShellExecution", True), ("beforeMCPExecution", True),
                 ("beforeReadFile", True), ("afterShellExecution", False),
                 ("afterMCPExecution", False))
CODEX_EVENTS = ("PreToolUse", "PostToolUse")
NOTES = {
    "cursor": ["  A file read that would ask is refused: that Cursor hook takes allow or deny "
               "only.",
               "  Cursor's own file edits are not checked: only shell commands, MCP calls and file "
               "reads are wired."],
    "codex": ["  Codex runs a new or changed hook only after you review it: start Codex and run "
              "/hooks.",
              "  A call that would ask is refused: a Codex hook cannot ask, and its doc says an "
              "ask answer lets the call run."],
}


def _mine(entry):
    return isinstance(entry, dict) and HOOK_MARK in str(entry.get("command"))


def _cursor(hooks, cmd):
    for event, fail_closed in CURSOR_EVENTS:
        entries = hooks.setdefault(event, [])
        old = [e for e in entries if _mine(e)]
        for e in old:
            e["command"] = cmd
        if not old:
            entries.append(dict({"command": cmd, "timeout": 10},
                                **({"failClosed": True} if fail_closed else {})))


def _codex(hooks, cmd):
    for event in CODEX_EVENTS:
        groups = hooks.setdefault(event, [])
        old = [h for g in groups if isinstance(g, dict) for h in g.get("hooks") or [] if _mine(h)]
        for h in old:
            h["command"] = cmd
        if not old:  # no matcher: every tool
            groups.append({"hooks": [{"type": "command", "command": cmd, "timeout": 10}]})


def _merge(path, add, cmd):
    """Add our entries to the hooks file. Returns True when the file was written."""
    cfg = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    if not isinstance(cfg, dict) or not isinstance(cfg.setdefault("hooks", {}), dict):
        raise ValueError("not a JSON object with a \"hooks\" object")
    before = json.dumps(cfg, sort_keys=True)
    add(cfg["hooks"], cmd)
    if add is _cursor:
        cfg.setdefault("version", 1)
    if json.dumps(cfg, sort_keys=True) == before:
        return False
    if os.path.exists(path) and not os.path.exists(path + ".guardrails-bak"):
        shutil.copy2(path, path + ".guardrails-bak")
    tmp = path + ".guardrails-tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)  # the agent never reads a half-written file
    return True


def _claude(plugin_root):
    exe = shutil.which("claude")
    if not exe:
        return 2, ["claude is not on PATH. Install Claude Code, then run this again."]
    repo = os.path.normpath(os.path.join(str(plugin_root), "..", ".."))
    clone = os.path.isfile(os.path.join(repo, ".claude-plugin", "marketplace.json"))
    lines, code = [], 0
    for args in (["plugin", "marketplace", "add", repo if clone else GITHUB],
                 ["plugin", "install", PLUGIN_KEY]):
        r = subprocess.run([exe] + args, capture_output=True, text=True, timeout=300)
        lines.append("$ claude " + " ".join(args))
        lines += ["  " + ln for ln in (r.stdout + r.stderr).strip().splitlines()]
        code = r.returncode  # the marketplace may be there already: the install decides
    lines.append("Restart Claude Code to load the hooks." if code == 0 else
                 "The install command failed (exit %d); nothing else was changed." % code)
    return (0 if code == 0 else 2), lines


def install(agent, plugin_root, data, home=None):
    """Returns (exit code, lines to print). data is where that agent's hooks will log."""
    if agent == "claude":
        return _claude(plugin_root)
    folder = os.path.join(home or os.path.expanduser("~"), "." + agent)
    if not os.path.isdir(folder):
        return 2, ["%s is not set up on this computer (no %s). Nothing was changed."
                   % (agent.capitalize(), folder)]
    path = os.path.join(folder, "hooks.json")
    cmd = "python3 %s hook %s --data %s" % (
        shlex.quote(os.path.join(str(plugin_root), "guard.py")), agent, shlex.quote(str(data)))
    try:
        changed = _merge(path, _cursor if agent == "cursor" else _codex, cmd)
    except (OSError, ValueError) as e:
        return 2, ["%s was left as it is (%s). Fix it, then run this again." % (path, e)]
    return 0, ["%s: %s" % (path, "guard hooks added" if changed else "already wired, no change"),
               "  hook command: " + cmd,
               "  log and session marks: %s (the dashboard reads the same folder)" % data,
               *(["  the file as it was: %s.guardrails-bak" % path]
                 if os.path.exists(path + ".guardrails-bak") else []),
               *NOTES[agent],
               "  To undo: remove the entries whose command holds \"%s\" from that file."
               % HOOK_MARK]
