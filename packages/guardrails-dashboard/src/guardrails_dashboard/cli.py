"""The one-word command: `guardrails` starts the dashboard on a free port and opens the browser.

scripts/install.sh puts a launcher for this on PATH. Every dashboard option still works after the
word: guardrails --port 8766, guardrails --scan, guardrails --install cursor.
"""
import os
import sys
from pathlib import Path

from .server import OWN_DATA, find_data, main

REPO = Path(__file__).resolve().parents[4]


def run(argv):
    home = os.path.expanduser("~")
    first = ["--port", "0", "--open"]  # an option typed after the word wins over these
    if find_data(None, os.environ, home)[0] is None:
        # No hook has logged yet: open on the folder the hooks fall back to, so the page says
        # "no tool call yet" instead of the command failing on a fresh install.
        first += ["--data", os.path.join(home, OWN_DATA)]
    return main(first + argv, REPO / "packages" / "guardrails-plugin", REPO / "index.html")


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
