"""Start the dashboard from the installed plugin: python3 dashboard.py [--port N] [--data FOLDER].

The interface is frozen across versions: an old copy of this file can hand over to a new one.
"""
import os
import sys

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.abspath(__file__))


def main():
    sys.path.insert(0, os.path.join(ROOT, "vendor"))
    from guardrails_dashboard import server
    return server.run_installed(ROOT, sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
