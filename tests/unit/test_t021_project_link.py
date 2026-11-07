"""T-021: a project that sits in, or is reached through, a folder named prod or production keeps
working, while real production config and secrets stay denied.

Real files in a real tmp tree, the real run_pre on the shipped policy.json, no mocks:

    tmp/srv/production/app/        the project (src, tests, config/production/db.yml, a link out)
    tmp/home/app                -> tmp/srv/production/app   (how the person reaches it)
    tmp/srv/production/secret   a production file outside the project
    tmp/prod/app                a project under prod/ with no link in it

Step 0 of the ticket (a real `claude -p` in tmp/home/app): the hook payload cwd and
CLAUDE_PROJECT_DIR were the RESOLVED folder (.../srv/production/app); the file_path the model
wrote was the LINKED form (.../home/app/probe.txt). So both forms reach the hook; each test
runs both.
"""
import filecmp
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from guardrails_core import hooks, isolation

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "packages" / "guardrails-plugin"
SHIPPED = json.loads((PLUGIN / "policy.json").read_text())


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    # the tmp folder itself must not carry a production word, or every test would be denied
    assert not re.search(r"prod", str(tmp_path), re.I), tmp_path
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    monkeypatch.delenv("GUARDRAILS_POLICY", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


@pytest.fixture
def tree(tmp_path):
    app = tmp_path / "srv" / "production" / "app"
    for d in ("src", "tests", "config/production", ".claude"):
        (app / d).mkdir(parents=True)
    (app / "src" / "x.py").write_text("x = 1\n")
    (app / "tests" / "t.py").write_text("def test(): pass\n")
    (app / "config" / "production" / "db.yml").write_text("pw: x\n")
    (tmp_path / "srv" / "production" / "secret").write_text("s\n")
    (tmp_path / "srv" / "production" / "other").mkdir()
    (tmp_path / "srv" / "production" / "other" / "x").write_text("o\n")
    (app / "leak").symlink_to("../../production/secret")
    (tmp_path / "home").mkdir()
    (tmp_path / "home" / "app").symlink_to(app)
    plain = tmp_path / "prod" / "app"
    (plain / "src").mkdir(parents=True)
    (plain / ".claude").mkdir()
    (plain / "src" / "x.py").write_text("x = 1\n")
    (tmp_path / "prod" / "app2").mkdir()
    (tmp_path / "prod" / "app2" / "y.py").write_text("y = 1\n")
    (tmp_path / "prod" / "other").mkdir()
    (tmp_path / "prod" / "other" / "x").write_text("o\n")
    return tmp_path


def _iso(tmp_path, monkeypatch, on, *projects):
    if not on:
        return
    f = tmp_path / "iso.json"
    f.write_text('{"version": 1, "isolation": true}\n')
    monkeypatch.setenv("GUARDRAILS_POLICY", str(f))
    for p in projects:  # the tripwire wants the sandbox block in the project's settings
        (p / ".claude").mkdir(exist_ok=True)
        (p / ".claude" / "settings.local.json").write_text(
            json.dumps(isolation.sandbox_block(SHIPPED)))


def pre(tool, tin, cwd, tmp_path):
    raw = json.dumps({"session_id": "s", "tool_use_id": "t", "tool_name": tool,
                      "tool_input": tin, "cwd": str(cwd)})
    out = hooks.run_pre(raw, str(PLUGIN), str(tmp_path / "data"))
    if not out:
        return "allow", None
    h = json.loads(out)["hookSpecificOutput"]
    m = re.match(r"\[([^\]]+)\]", h["permissionDecisionReason"])
    return h["permissionDecision"], m.group(1)


MODES = ["iso-off", "iso-on"]


def _file_calls(path):
    return [("Read", {"file_path": path}),
            ("Edit", {"file_path": path, "old_string": "a", "new_string": "b"}),
            ("Write", {"file_path": path, "content": "x"})]


@pytest.mark.parametrize("on", [False, True], ids=MODES)
@pytest.mark.parametrize("cwd_linked", [False, True], ids=["cwd-resolved", "cwd-linked"])
@pytest.mark.parametrize("path_linked", [False, True], ids=["path-resolved", "path-linked"])
def test_own_files_are_allowed_in_every_form(tree, monkeypatch, on, cwd_linked, path_linked):
    real, link = tree / "srv" / "production" / "app", tree / "home" / "app"
    _iso(tree, monkeypatch, on, real)
    cwd, base = (link if cwd_linked else real), (link if path_linked else real)
    for rel in ("src/x.py", "tests/t.py", "src/new.py", "src"):
        for tool, tin in _file_calls(str(base / rel)):
            assert pre(tool, tin, cwd, tree)[0] == "allow", (tool, base / rel)
    # Glob and Grep carry the folder in a path field too
    assert pre("Grep", {"pattern": "x", "path": str(base / "src")}, cwd, tree)[0] == "allow"
    assert pre("Glob", {"pattern": "*.py", "path": str(base)}, cwd, tree)[0] == "allow"


@pytest.mark.parametrize("on", [False, True], ids=MODES)
@pytest.mark.parametrize("cwd_linked", [False, True], ids=["cwd-resolved", "cwd-linked"])
@pytest.mark.parametrize("path_linked", [False, True], ids=["path-resolved", "path-linked"])
def test_own_shell_commands_get_no_ask(tree, monkeypatch, on, cwd_linked, path_linked):
    real, link = tree / "srv" / "production" / "app", tree / "home" / "app"
    _iso(tree, monkeypatch, on, real)
    cwd, base = (link if cwd_linked else real), (link if path_linked else real)
    for cmd in ("cat %s/src/x.py", "pytest %s/tests", "ls %s", "python3 %s/src/x.py"):
        assert pre("Bash", {"command": cmd % base}, cwd, tree)[0] == "allow", cmd % base


@pytest.mark.parametrize("on", [False, True], ids=MODES)
@pytest.mark.parametrize("cwd_linked", [False, True], ids=["cwd-resolved", "cwd-linked"])
@pytest.mark.parametrize("path_linked", [False, True], ids=["path-resolved", "path-linked"])
def test_config_inside_the_project_stays_denied(tree, monkeypatch, on, cwd_linked,
                                                  path_linked):
    real, link = tree / "srv" / "production" / "app", tree / "home" / "app"
    _iso(tree, monkeypatch, on, real)
    cwd, base = (link if cwd_linked else real), (link if path_linked else real)
    for rel in ("config/production/db.yml", "config/production/new.yml",
                "src/../config/production/db.yml"):
        for tool, tin in _file_calls(str(base / rel)):
            assert pre(tool, tin, cwd, tree) == ("deny", "deny-prod-config"), (tool, rel)
        assert pre("Bash", {"command": "cat %s" % (base / rel)}, cwd, tree) == (
            "ask", "deny-prod-config"), rel


@pytest.mark.parametrize("on", [False, True], ids=MODES)
@pytest.mark.parametrize("cwd_linked", [False, True], ids=["cwd-resolved", "cwd-linked"])
def test_files_outside_the_project_stay_denied(tree, monkeypatch, on, cwd_linked):
    real, link = tree / "srv" / "production" / "app", tree / "home" / "app"
    _iso(tree, monkeypatch, on, real)
    cwd = link if cwd_linked else real
    outside = [str(tree / "srv" / "production" / "other" / "x"),
               str(tree / "srv" / "production" / "secret"),
               # a ".." that leaves the project, from the resolved and the linked root
               str(real) + "/../../production/other/x",
               str(real) + "/src/../../../production/secret"]
    for path in outside:
        for tool, tin in _file_calls(path):
            assert pre(tool, tin, cwd, tree) == ("deny", "deny-prod-config"), (tool, path)
        assert pre("Bash", {"command": "cat " + path}, cwd, tree) == (
            "ask", "deny-prod-config"), path


def test_a_dotdot_after_the_link_stays_denied(tree):
    link = tree / "home" / "app"
    # tmp/home/app/../../srv/production/other/x: Claude Code folds the ".." as text, so the
    # text spelling is outside the project and is matched whole
    path = "%s/../../production/other/x" % link
    assert (Path(path).resolve() == tree / "srv" / "production" / "other" / "x")
    assert pre("Read", {"file_path": path}, link, tree) == ("deny", "deny-prod-config")


@pytest.mark.parametrize("on", [False, True], ids=MODES)
def test_a_link_out_of_the_project_is_denied(tree, monkeypatch, on):
    real, link = tree / "srv" / "production" / "app", tree / "home" / "app"
    _iso(tree, monkeypatch, on, real)
    for base in (real, link):
        for tool, tin in _file_calls(str(base / "leak")):
            d = pre(tool, tin, real, tree)
            if on:
                assert d == ("deny", "deny-prod-config"), (tool, base)
            else:
                # Settled (Chris #586): links are followed only with isolation on. With it off the
                # hook cannot know "leak" is a link, so the project's own spelling is allowed
                # in both forms, as the linked form already was on main.
                assert d[0] == "allow", (tool, base, d)


@pytest.mark.parametrize("on", [False, True], ids=MODES)
def test_a_plain_project_without_a_link(tree, monkeypatch, on):
    plain = tree / "prod" / "app"
    _iso(tree, monkeypatch, on, plain)
    for tool, tin in _file_calls(str(plain / "src" / "x.py")):
        assert pre(tool, tin, plain, tree)[0] == "allow", tool
    assert pre("Bash", {"command": "cat %s/src/x.py" % plain}, plain, tree)[0] == "allow"
    # a sibling whose name starts with the project's name is outside it (no text prefix test)
    sibling = str(tree / "prod" / "app2" / "y.py")
    assert pre("Read", {"file_path": sibling}, plain, tree) == ("deny", "deny-prod-config")
    other = str(plain) + "/../other/x"
    assert pre("Read", {"file_path": other}, plain, tree) == ("deny", "deny-prod-config")
    assert pre("Bash", {"command": "cat " + other}, plain, tree) == ("ask", "deny-prod-config")


@pytest.mark.parametrize("on", [False, True], ids=MODES)
def test_claude_project_dir_is_the_root_when_cwd_is_a_subfolder(tree, monkeypatch, on):
    real, link = tree / "srv" / "production" / "app", tree / "home" / "app"
    _iso(tree, monkeypatch, on, real)
    for project in (real, link):
        monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project))
        for base in (real, link):
            assert pre("Read", {"file_path": str(base / "src" / "x.py")},
                       real / "src", tree)[0] == "allow", (project, base)
            assert pre("Read", {"file_path": str(base / "config/production/db.yml")},
                       real / "src", tree) == ("deny", "deny-prod-config")


@pytest.mark.parametrize("on", [False, True], ids=MODES)
def test_secret_files_stay_denied_when_the_project_root_is_home(tree, monkeypatch, on):
    home = tree / "home"
    (home / ".ssh").mkdir()
    for n in ("id_rsa", "known_hosts", "config"):
        (home / ".ssh" / n).write_text("k")
    (home / ".aws").mkdir()
    (home / ".aws" / "credentials").write_text("k")
    _iso(tree, monkeypatch, on, home)
    for path in (home / ".ssh" / "id_rsa", home / ".ssh" / "known_hosts",
                 home / ".ssh" / "config", home / ".aws" / "credentials", "~/.ssh/id_rsa",
                 "~/.ssh/known_hosts"):
        for tool, tin in _file_calls(str(path)):
            assert pre(tool, tin, home, tree)[0] == "deny", (tool, path)
        assert pre("Bash", {"command": "cat %s" % path}, home, tree)[0] == "ask", path
    assert pre("Read", {"file_path": str(home / "notes.txt")}, home, tree)[0] == "allow"


def test_only_a_rule_with_project_relative_matches_below_the_root(tree):
    """A user rule without the field keeps whole-path matching; with it, matches below the root."""
    from guardrails_core import rules
    real = tree / "srv" / "production" / "app"
    tin = {"file_path": str(real / "vault" / "a")}

    def pol(**extra):
        return {"rules": [dict({"id": "mine", "kind": "path", "decision": "deny", "reason": "r",
                                "match": ["*/production/app/vault/*"]}, **extra)]}
    assert rules.match(pol(), "Read", tin, str(real)).rule == "mine"
    assert rules.match(pol(project_relative=False), "Read", tin, str(real)).rule == "mine"
    assert rules.match(pol(project_relative=True), "Read", tin, str(real)) is None
    below = {"rules": [dict(pol(project_relative=True)["rules"][0], match=["*/vault/*"])]}
    assert rules.match(below, "Read", tin, str(real)).rule == "mine"


def test_only_the_folder_rule_is_project_relative():
    flagged = [r["id"] for r in SHIPPED["rules"] if r.get("project_relative")]
    assert flagged == ["deny-prod-config"]


@pytest.mark.parametrize("bad", ["yes", 1, None, [], {}])
def test_project_relative_must_be_a_boolean(tree, bad):
    from guardrails_core import policy
    schema = json.loads((PLUGIN / "policy.schema.json").read_text())
    rule = {"id": "r", "decision": "deny", "kind": "path", "match": ["*"], "reason": "r"}
    policy.validate({"version": 1, "rules": [dict(rule, project_relative=True)]}, schema)
    with pytest.raises(policy.PolicyError):
        policy.validate({"version": 1, "rules": [dict(rule, project_relative=bad)]}, schema)
    # an added file with the bad value is left out and reported, the shipped rules still apply
    f = tree / "added.json"
    f.write_text(json.dumps({"version": 1, "rules": [dict(rule, project_relative=bad)]}))
    import os
    os.environ["GUARDRAILS_POLICY"] = str(f)
    try:
        pol, errors = policy.load_policy(str(PLUGIN), None)
    finally:
        del os.environ["GUARDRAILS_POLICY"]
    assert errors and all(r["id"] != "r" for r in pol["rules"])


@pytest.mark.parametrize("on", [False, True], ids=MODES)
@pytest.mark.parametrize("sub", [".ssh", ".aws", ".kube", ".docker", ".config/gcloud"])
def test_a_project_rooted_at_a_secret_folder_keeps_its_denies(tree, monkeypatch, on, sub):
    home = tree / "home"
    root = home / sub
    root.mkdir(parents=True)
    names = ("id_ecdsa", "config", "credentials", "config.json",
             "application_default_credentials.json")
    for n in names:
        (root / n).write_text("k")
    _iso(tree, monkeypatch, on, root)
    denied = {".ssh": ("id_ecdsa", "config"), ".aws": ("credentials", "config"),
              ".kube": ("config",), ".docker": ("config.json",),
              ".config/gcloud": ("application_default_credentials.json", "credentials")}[sub]
    for n in denied:
        for tool, tin in _file_calls(str(root / n)):
            assert pre(tool, tin, root, tree)[0] == "deny", (tool, root / n)
        assert pre("Bash", {"command": "cat %s" % (root / n)}, root, tree)[0] == "ask", n


@pytest.mark.parametrize("on", [False, True], ids=MODES)
def test_an_env_file_stays_denied_in_a_project_under_production(tree, monkeypatch, on):
    real = tree / "srv" / "production" / "app"
    (real / ".env").write_text("K=1\n")
    _iso(tree, monkeypatch, on, real)
    for base in (real, tree / "home" / "app"):
        assert pre("Read", {"file_path": str(base / ".env")}, real, tree) == (
            "deny", "deny-env-files")


@pytest.mark.parametrize("on", [False, True], ids=MODES)
def test_a_link_with_the_folder_name_inside_the_project(tree, monkeypatch, on):
    """Side effect 2: an in-project link named production.

    To a place outside the project it resolves out, so it is matched in full and denied. To a
    place inside the project it is the project's own file, matched below the root, and allowed.
    """
    real = tree / "srv" / "production" / "app"
    (real / "production").symlink_to(tree / "srv" / "production" / "other")
    (real / "src" / "production").symlink_to(real / "src")
    _iso(tree, monkeypatch, on, real)
    for base in (real, tree / "home" / "app"):
        for tool, tin in _file_calls(str(base / "production" / "x")):
            assert pre(tool, tin, real, tree) == ("deny", "deny-prod-config"), (tool, base)
        # the spelling names production below the root, so it is denied in both modes, like a
        # folder of that name: the text spelling places itself, the resolved form is its own entry
        assert pre("Read", {"file_path": str(base / "src" / "production" / "x.py")},
                   real, tree)[0] == "deny"
    # an in-project link to the project's own production config resolves to it with isolation
    # on; with it off no link is followed (the one stated limit), so the plain spelling passes
    (real / "cfg").symlink_to(real / "config" / "production")
    for base in (real, tree / "home" / "app"):
        assert pre("Read", {"file_path": str(base / "cfg" / "db.yml")}, real, tree) == (
            ("deny", "deny-prod-config") if on else ("allow", None))


# (cwd below the project, own-file spellings, denied spellings) for a project at ~/prod/app
SPELLINGS = {
    "": (["~/prod/app/src/x.py", "src/x.py", "./src/x.py", "../app/src/x.py",
          "../../prod/app/src/x.py", "~/prod/app/src/../src/x.py"],
         ["~/prod/app/config/production/db.yml", "config/production/db.yml",
          "../app/config/production/db.yml", "~/prod/other/x",
          "~/prod/app/../other/x", "../../prod/other/x"]),
    "src": (["~/prod/app/src/x.py", "x.py", "../src/x.py", "../../app/src/x.py",
             "../../../prod/app/src/x.py"],
            ["~/prod/app/config/production/db.yml", "../config/production/db.yml",
             "~/prod/other/x", "../../../prod/other/x"]),
}


@pytest.mark.parametrize("on", [False, True], ids=MODES)
@pytest.mark.parametrize("sub", list(SPELLINGS))
def test_every_spelling_of_an_own_path_gets_one_answer(tree, monkeypatch, on, sub):
    """Round 1 covered absolute spellings only. A ~ or relative spelling of the same file was
    matched on its whole text and denied. The inside-the-project test now runs once per path, on
    the path as the tool opens it (~ expanded, joined to the working folder, links followed).
    Project at ~/prod/app; HOME is tmp/home.
    """
    app = tree / "home" / "prod" / "app"
    for d in ("src", "config/production", ".claude"):
        (app / d).mkdir(parents=True)
    (app / "src" / "x.py").write_text("x = 1\n")
    (app / "config" / "production" / "db.yml").write_text("pw: x\n")
    (tree / "home" / "prod" / "other").mkdir()
    (tree / "home" / "prod" / "other" / "x").write_text("o\n")
    _iso(tree, monkeypatch, on, app)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(app))  # Claude Code sets it for every hook
    cwd = app / sub if sub else app
    own, denied = SPELLINGS[sub]
    for path in own:
        for tool, tin in _file_calls(path):
            assert pre(tool, tin, cwd, tree)[0] == "allow", (tool, path, sub)
        assert pre("Bash", {"command": "cat " + path}, cwd, tree)[0] == "allow", (path, sub)
    for path in denied:
        for tool, tin in _file_calls(path):
            assert pre(tool, tin, cwd, tree) == ("deny", "deny-prod-config"), (tool, path, sub)
        assert pre("Bash", {"command": "cat " + path}, cwd, tree) == (
            "ask", "deny-prod-config"), (path, sub)
    for cmd in ("ls ~/prod/app/src", "cd ~/prod/app && pytest", "ls ~/prod/app", "ls ~/prod/app/"):
        assert pre("Bash", {"command": cmd}, cwd, tree)[0] == "allow", (cmd, sub)


def test_vendor_copy_equals_core_and_demo_prints_24():
    core = ROOT / "packages" / "guardrails-core" / "src" / "guardrails_core"
    vendor = PLUGIN / "vendor" / "guardrails_core"
    for f in core.glob("*.py"):
        assert filecmp.cmp(f, vendor / f.name, shallow=False), f.name
    out = subprocess.run(
        [sys.executable, "-m", "guardrails_demo"], capture_output=True, text=True, check=True,
        env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin",
             "PYTHONPATH": "%s:%s" % (core.parent, ROOT / "packages/guardrails-demo/src")}).stdout
    assert "24 calls: 10 allow, 10 ask, 4 deny." in out
    assert "All decisions matched the fixtures." in out


def _timed(tin, cwd, tool="mcp__x__bulk"):
    import time

    from guardrails_core import rules
    t = time.monotonic()
    d = rules.match(SHIPPED, tool, tin, str(cwd))
    return d, time.monotonic() - t


def test_big_input_costs_no_disk_call_per_string(tree, monkeypatch):
    """Round 2 followed links on every candidate string: a 2 MB base64 string took 13.8 s and the
    guard test's 2000 x 4096 characters 32 s, past the 10 s hook limit. Only the named path
    fields are resolved now; every other string is placed by text alone. Each finishes well
    under the hook limit, with links on (what isolation runs).
    """
    import base64
    import os
    real = tree / "srv" / "production" / "app"
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(real))
    blob = base64.b64encode(os.urandom(1_500_000)).decode()  # 2 MB, has "/" like real uploads
    assert len(blob) >= 2_000_000
    calls = []
    real_realpath = os.path.realpath
    monkeypatch.setattr(os.path, "realpath", lambda p, *a, **k: (
        calls.append(len(str(p))), real_realpath(p, *a, **k))[1])
    d, took = _timed({"data": blob}, real)
    assert took < 5, took
    assert max(calls) < 1000, "a candidate string was resolved on disk"
    d, took = _timed({"k": ["a/" * 2048 for _ in range(2000)]}, real)  # the t008 guard input
    assert d is None and took < 5, took
    d, took = _timed({"file_path": "a/" * 2048, "k": "x"}, real, "Read")  # a long named field
    assert took < 5, took


@pytest.mark.parametrize("on", [False, True], ids=MODES)
def test_a_link_then_dotdot_out_of_the_project_is_denied(tree, monkeypatch, on):
    """Round 3 judge case: Claude Code folds '..' as text, so the text spelling opens the
    outside file."""
    real = tree / "srv" / "prod" / "app"
    real.mkdir(parents=True, exist_ok=True)
    (real / "a" / "b").mkdir(parents=True)
    (real / "l").symlink_to(real / "a" / "b")
    (tree / "srv" / "prod" / "secrets.yaml").write_text("k: v\n")
    _iso(tree, monkeypatch, on, real)
    for tool, tin in _file_calls(str(real / "l" / ".." / ".." / "secrets.yaml")):
        assert pre(tool, tin, real, tree) == ("deny", "deny-prod-config"), tool
