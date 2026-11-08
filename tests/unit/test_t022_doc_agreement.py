"""T-022: ARCHITECTURE (where the README's rules text moved), THREAT_MODEL and the refusal message
tell one story."""

import json
from pathlib import Path

from guardrails_core import isolation

ROOT = Path(__file__).resolve().parents[2]
README = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
ARCH = " ".join((ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8").split())
THREAT = " ".join((ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8").split())
SHIPPED = json.loads((ROOT / "packages/guardrails-plugin/policy.json").read_text())


def _refusal(tmp_path, settings):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.local.json").write_text(json.dumps(settings))
    ok, why = isolation.block_in_force(str(tmp_path), SHIPPED)
    assert not ok
    return isolation.not_active_reason(str(tmp_path), str(ROOT / "packages/guardrails-plugin"), why)


def test_threat_model_bypass_matches_readme():
    assert "in interactive bypass mode is not tested" not in THREAT
    assert "A live interactive check has not been run" not in THREAT
    assert "tested 2026-11-06" in THREAT


def test_readme_timeout_clause_matches_fail_safe():
    assert "a call that times out goes through" not in README + ARCH
    tail = ARCH.split("a slow regex in your file can delay a shipped shell ask")[1][:400]
    assert "2.1.295" in tail


def test_refusal_tells_where_to_move_a_host_rule(tmp_path):
    why = _refusal(tmp_path, {"permissions": {"allow": ["WebFetch(domain:example.com)"]}})
    assert "WebFetch(domain:" in why and "~/.claude/settings.json" in why and "move" in why


def test_release_note_for_isolation_users():
    note = ARCH.split("Release note for upgrades")
    assert any("allowWrite" in n and "allowedDomains" in n and "WebFetch(domain:" in n
               and "~/.claude/settings.json" in n for n in note[1:])
