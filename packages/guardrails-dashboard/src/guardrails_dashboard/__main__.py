"""The clone entry (make dashboard): it finds the repo from its own path."""
import sys
from pathlib import Path

from .server import main

REPO = Path(__file__).resolve().parents[4]


def run():
    plugin_root, page = REPO / "packages" / "guardrails-plugin", REPO / "index.html"
    for need in (plugin_root / "policy.json", page):
        if not need.is_file():
            print("cannot find %s: run this from a clone of the agent-guardrails repo." % need)
            return 2
    return main(sys.argv[1:], plugin_root, page)


sys.exit(run())
