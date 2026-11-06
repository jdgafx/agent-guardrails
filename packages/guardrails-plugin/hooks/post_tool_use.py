"""PostToolUse hook: write the audit line and scan untrusted output.

It prints nothing and never changes the result, except with isolation on: then it prints the
shell output with shaped secrets replaced (run_post decides; see docs/ARCHITECTURE.md).
"""
import os
import sys

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "vendor"))


def main():
    try:
        from guardrails_core.hooks import run_post
        out = run_post(sys.stdin.read(), ROOT, os.environ.get("CLAUDE_PLUGIN_DATA"))
    except Exception as e:
        # exit 1 is a non-blocking error: the user sees the notice, the tool result is untouched
        sys.stderr.write("guardrails audit failed: %s: %s\n" % (type(e).__name__, e))
        return 1
    if out:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
