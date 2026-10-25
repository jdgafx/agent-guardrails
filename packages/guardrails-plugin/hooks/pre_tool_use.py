"""PreToolUse hook: deny / ask / allow. Any failure, even a failed import, becomes "ask"."""
import json
import os
import sys

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "vendor"))


def main():
    try:
        from guardrails_core.hooks import run_pre
        out = run_pre(sys.stdin.read(), ROOT, os.environ.get("CLAUDE_PLUGIN_DATA"))
    except Exception as e:  # the import itself can fail (missing vendor dir)
        out = json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "ask",
            "permissionDecisionReason": "[guardrails-error] hook failed to start (%s: %s)"
                                        % (type(e).__name__, e)}})
    if out:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
