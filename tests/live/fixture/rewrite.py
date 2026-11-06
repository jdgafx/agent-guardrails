"""Test hook for tests/live/t014_probe.py (PreToolUse, outside the sandbox).

Haiku refuses to run the raw test commands, so the model sends `echo stepN` and this hook swaps in
test command N through `updatedInput`. The sandbox and Post see the real command; the plugin's
own Pre sees `echo stepN` (Claude Code runs the hooks in parallel on the model's input).

Environment: T014_STEPS is the steps file (`<id> <command>` per line), T014_LOG a file that gets
one line per rewrite.
"""
import json
import os
import re
import sys

d = json.load(sys.stdin)
steps = {}
for line in open(os.environ["T014_STEPS"], encoding="utf-8"):
    n, _, rest = line.rstrip("\n").partition(" ")
    steps[n] = rest
tin = d.get("tool_input", {})
new = None
if d.get("tool_name") == "Bash":
    m = re.fullmatch(r"echo step(\w+)", tin.get("command", "").strip())
    if m and m.group(1) in steps:
        new = dict(tin, command=steps[m.group(1)])
        if m.group(1) == "28":  # case 15: the sandbox stays on although the call asks it off
            new["dangerouslyDisableSandbox"] = True
elif d.get("tool_name") == "Grep":
    m = re.fullmatch(r"step(G\d+)", tin.get("pattern", ""))
    if m and m.group(1) in steps:
        new = json.loads(steps[m.group(1)])
if new is not None:
    with open(os.environ["T014_LOG"], "a", encoding="utf-8") as f:
        f.write(json.dumps(new) + "\n")
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                             "updatedInput": new}}))
