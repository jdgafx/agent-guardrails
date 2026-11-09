"""The guard for agents other than Claude Code, on stock python3 with nothing installed:

    python3 guard.py hook <cursor|codex|generic|claude-code> [--data DIR]   hook input on stdin
    python3 guard.py shell -c "<cmd>"                    a $SHELL that checks each command
    python3 guard.py mcp [--name NAME] -- <cmd> <args>   a proxy in front of one MCP server
    python3 guard.py scan [--text]                       the NHI and agent inventory

Any failure to start exits 2, which Claude Code, Cursor and Codex all read as "block the call".
"""
import os
import sys

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))
MODULES = {"hook": "adapters", "shell": "shell_guard", "mcp": "mcp_proxy", "scan": "discovery"}


def main():
    try:
        module = MODULES[sys.argv[1]]
        sys.path.insert(0, os.path.join(ROOT, "vendor"))
        os.environ.setdefault("GUARDRAILS_ROOT", ROOT)
        import importlib
        run = importlib.import_module("guardrails_core." + module).main
    except Exception as e:  # no such mode, or a half-copied plugin
        sys.stderr.write("agent-guardrails could not start (%s: %s).\n%s"
                         % (type(e).__name__, e, __doc__))
        return 2
    return run(sys.argv[2:])


if __name__ == "__main__":
    sys.exit(main())
