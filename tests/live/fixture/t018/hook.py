"""Stub PreToolUse hook of the T-018 mode check (case 44): answers argv[1] (ask, deny or allow) for
every Bash call and logs the permission mode it was told, next to this file."""
import json
import os
import sys

p = json.load(sys.stdin)
log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hook.log")
with open(log, "a") as f:
    f.write(json.dumps({"mode": p.get("permission_mode"), "tool": p.get("tool_name"),
                        "answer": sys.argv[1]}) + "\n")
if p.get("tool_name") == "Bash":
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": sys.argv[1],
        "permissionDecisionReason": "[probe] T-018 probe " + sys.argv[1]}}))
