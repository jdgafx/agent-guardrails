"""T-025: every pytest version in uv.lock is at or above the first fixed one (9.0.3)."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXED = (9, 0, 3)


def test_locked_pytest_is_fixed():
    lock = (ROOT / "uv.lock").read_text()
    versions = re.findall(r'\[\[package\]\]\nname = "pytest"\nversion = "([^"]+)"', lock)
    assert versions, "pytest not in uv.lock"
    for v in versions:
        assert tuple(int(p) for p in v.split(".")[:3]) >= FIXED, v
