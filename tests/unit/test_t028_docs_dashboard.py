"""T-028: the docs say the repo ships a static dashboard (index.html) and no doc denies it."""

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
    # The page asks for /api. Only packages/guardrails-dashboard serves it; the plugin has no server.
    page = (ROOT / "index.html").read_text(encoding="utf-8")
    assert all(p in page for p in ("/api/status", "/api/policy", "/api/events"))
    server = re.compile(
        r"http\.server|HTTPServer|socketserver|serve_forever|createServer|flask|uvicorn", re.I
    )
    hits = [p for p in (ROOT / "packages").rglob("*.py") if server.search(p.read_text(encoding="utf-8"))]
    plugin = ROOT / "packages" / "guardrails-plugin"
    assert not [p for p in hits if plugin in p.parents]
    assert all(ROOT / "packages" / "guardrails-dashboard" in p.parents for p in hits), hits
    assert hits  # the dashboard server exists
    assert "no server" in ARCH.lower() and "opens no port" in ARCH
