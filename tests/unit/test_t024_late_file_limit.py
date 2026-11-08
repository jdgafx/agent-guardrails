"""T-024: the late-file limit is in the docs once each; the probe runs cases as a person would."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def flat(p):
    return " ".join((ROOT / p).read_text(encoding="utf-8").split())


ARCH = flat("docs/ARCHITECTURE.md")  # T-038: the README text moved here
THREAT = flat("docs/THREAT_MODEL.md")
PROBE = (ROOT / "tests/live/t014_probe.py").read_text(encoding="utf-8")

LIMIT = "when each command starts"
LATE = "created while a shell command is already running"


def test_limit_is_in_architecture_and_threat_model_once_each():
    for doc in (ARCH, THREAT):
        assert doc.count(LATE) == 1
        i = doc.index(LATE)
        tail = doc[max(0, i - 300) : i + 900]
        assert LIMIT in tail
        assert "file pattern" in tail and "folder pattern" in tail
        assert "next command" in tail
    assert "before each command" not in ARCH + THREAT


def test_probe_case3_sends_33_and_34_separately():
    assert re.search(r'p\.run\(\["33"\]\)', PROBE) and re.search(r'p\.run\(\["34"\]\)', PROBE)
    assert '"33", "34"' not in PROBE.split("check(3,")[0]


def test_probe_t018_44_checks_each_pair_in_the_hook_log():
    body = PROBE.split("def modes(")[1].split("def no_bwrap")[0]
    assert "len(runs) - 1" not in body
    assert '"answer"' in body and '"mode"' in body


def test_probe_t018_47_runs_in_its_own_session():
    assert 'p.run(["45", "46", "47"])' not in PROBE
    assert re.search(r'p\.run\(\["47"\]\)', PROBE)
