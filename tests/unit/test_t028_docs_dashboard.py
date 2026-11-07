"""T-028: the docs say the repo ships a static dashboard (index.html) and no doc denies it."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC_FILES = [ROOT / "GLOSSARY.md", ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
ARCH = re.sub(r"\s+", " ", (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8"))
DENIAL = re.compile(r"\bno (ui|dashboard)\b|\bnot? (a )?(ui|dashboard)\b|\bnon-goals?\b[^.\n]*\ba ui\b", re.I)


def test_no_doc_says_there_is_no_ui_or_dashboard():
    hits = [f"{p.name}: {m.group(0)}" for p in DOC_FILES for m in DENIAL.finditer(p.read_text(encoding="utf-8"))]
    assert not hits, hits


def test_architecture_says_the_repo_ships_a_static_dashboard():
    assert (ROOT / "index.html").is_file()
    assert "`index.html`" in ARCH and "static dashboard" in ARCH
    assert "/api" in ARCH and "sample data" in ARCH


def test_the_no_server_claim_is_true_in_the_code():
    # The page asks for /api; the doc says no server in the plugin. Both must hold in the code.
    page = (ROOT / "index.html").read_text(encoding="utf-8")
    assert all(p in page for p in ("/api/status", "/api/policy", "/api/events"))
    server = re.compile(r"http\.server|HTTPServer|socketserver|serve_forever|createServer|flask|uvicorn", re.I)
    src = [p for d in (ROOT / "packages").rglob("*.py") for p in [d] if "node_modules" not in str(p)]
    assert not [p for p in src if server.search(p.read_text(encoding="utf-8"))]
    assert "no server" in ARCH.lower()
