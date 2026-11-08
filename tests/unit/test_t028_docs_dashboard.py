"""T-028: the docs say the repo ships a static dashboard (index.html) and no doc denies it."""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC_FILES = [ROOT / "GLOSSARY.md", ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
ARCH = re.sub(r"\s+", " ", (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8"))
DENIAL = re.compile(
    r"\bno (ui|dashboard)\b|\bnot? (a )?(ui|dashboard)\b|\bnon-goals?\b[^.\n]*\ba ui\b", re.I
)


def test_no_doc_says_there_is_no_ui_or_dashboard():
    texts = {p.name: p.read_text(encoding="utf-8") for p in DOC_FILES}
    hits = [f"{n}: {m.group(0)}" for n, t in texts.items() for m in DENIAL.finditer(t)]
    assert not hits, hits


def test_architecture_says_the_repo_ships_a_static_dashboard():
    assert (ROOT / "index.html").is_file()
    assert "`index.html`" in ARCH and "static dashboard" in ARCH
    assert "/api" in ARCH and "sample data" in ARCH


def test_the_no_server_claim_is_true_in_the_code():
    # The page asks for /api. Server code lives only in packages/guardrails-dashboard and its
    # vendored copy in the plugin (T-037); the hooks and the engine import no network module.
    page = (ROOT / "index.html").read_text(encoding="utf-8")
    assert all(p in page for p in ("/api/status", "/api/policy", "/api/events"))
    server = re.compile(
        r"http\.server|HTTPServer|socketserver|serve_forever|createServer|flask|uvicorn", re.I
    )
    src = (ROOT / "packages").rglob("*.py")
    hits = [p for p in src if server.search(p.read_text(encoding="utf-8"))]
    plugin = ROOT / "packages" / "guardrails-plugin"
    home = (ROOT / "packages" / "guardrails-dashboard", plugin / "vendor" / "guardrails_dashboard")
    assert all(any(h in p.parents for h in home) for p in hits), hits
    assert hits  # the dashboard server exists
    banned = {"socket", "socketserver", "http.client", "http.server", "urllib.request",
              "guardrails_dashboard"}
    core = (plugin / "vendor" / "guardrails_core").glob("*.py")
    quiet = [*(plugin / "hooks").glob("*.py"), *core]
    assert quiet
    for path in quiet:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                     else [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
            bad = [n for n in names if n in banned or n.startswith("guardrails_dashboard.")]
            assert not bad, (path, bad)
    assert "the hooks open no port" in ARCH


def test_readme_get_started_has_the_install_and_start_commands():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    start = text.index("## Get started")
    assert start < text.index("## The seven controls")
    block = text[start:text.index("## The seven controls")]
    for need in ("claude plugin marketplace add jdgafx/agent-guardrails",
                 "claude plugin install agent-guardrails@agent-guardrails",
                 'exec python3 "$f"', "dashboard.py",
                 "claude plugin marketplace update agent-guardrails",
                 "claude plugin update agent-guardrails@agent-guardrails",
                 "No account and no sign-up for the plugin or the dashboard: the dashboard reads "
                 "the log the plugin writes on your own computer, and neither the plugin nor the "
                 "dashboard sends anything off it."):
        assert need in block, need
    assert ("It uses only the Python standard library. No API key, no account, no pip install. The "
            "hooks open no network connection and no port; the dashboard, when you start it, "
            "listens on 127.0.0.1 only and answers only with its key.") in text
    both = [ln for ln in text.splitlines() if "macOS" in ln and "Windows" in ln]
    assert len(both) == 1 and "not tested" in both[0], both
