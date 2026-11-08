"""T-037: the dashboard runs from a marketplace install (designs/agent-guardrails-T-039/design.md).

Cases 1-23 of that design's ## Cases, one test each. They run the real plugin folder after
`make build`, log lines written by its real hook scripts, the install record in the shape Claude
Code wrote it (design evidence 1) and the start command copied from README's "Get started".
Cases 24-26 sit in test_core.py, test_t009_scan.py and test_t028_docs_dashboard.py; cases 27-28
are the live script tests/live/t037_clean_home.sh.
"""
import http.client
import json
import os
import re
import shutil
import signal
import subprocess
import threading
from pathlib import Path

import pytest
from guardrails_core.policy import load_policy

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "packages" / "guardrails-plugin"
KEY = "agent-guardrails@agent-guardrails"
PAIRED = "agent-guardrails-agent-guardrails"
LINK = re.compile(r"http://127\.0\.0\.1:(\d+)/\?key=(\S+)")
UPDATE = "claude plugin update agent-guardrails@agent-guardrails"


def start_command():
    """The start command, as README's Get started block gives it."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    block = next(ln for ln in text.splitlines() if ln.startswith("(for f in "))
    assert block.count('exec python3 "$f"') == 1
    return block


def with_args(cmd, *args):
    return cmd.replace('exec python3 "$f"', 'exec python3 "$f" ' + " ".join(args))


@pytest.fixture(scope="session", autouse=True)
def built():
    if not (PLUGIN / "dashboard.py").is_file() or not (PLUGIN / "vendor" / "index.html").is_file():
        subprocess.run(["make", "build"], cwd=str(ROOT), check=True, capture_output=True)


# ---- a fake Claude Code config folder with real copies of the plugin

class Box:
    def __init__(self, tmp, config=None):
        self.home = tmp / "home"
        self.config = Path(config) if config else self.home / ".claude"
        self.cwd = tmp / "empty"
        self.home.mkdir(parents=True, exist_ok=True)
        self.cwd.mkdir(exist_ok=True)
        self.cache = self.config / "plugins" / "cache" / "agent-guardrails" / "agent-guardrails"
        self.data = self.config / "plugins" / "data" / PAIRED

    def copy(self, version, dashboard=True, fewer_rules=0):
        dst = self.cache / version
        shutil.copytree(PLUGIN, dst, ignore=shutil.ignore_patterns("__pycache__"))
        meta = dst / ".claude-plugin" / "plugin.json"
        meta.write_text(json.dumps(dict(json.loads(meta.read_text()), version=version)))
        if fewer_rules:
            pol = json.loads((dst / "policy.json").read_text())
            pol["rules"] = pol["rules"][:-fewer_rules]
            (dst / "policy.json").write_text(json.dumps(pol))
        if not dashboard:
            (dst / "dashboard.py").unlink()
        return dst

    def record(self, *recs):
        """Each record is a path (scope user) or (path, scope, extra fields)."""
        items = [rec(*(r if isinstance(r, tuple) else (r,))) for r in recs]
        self.write_record(json.dumps({"version": 2, "plugins": {KEY: items}}))

    def write_record(self, text):
        path = self.config / "plugins" / "installed_plugins.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def env(self, **extra):
        return {"PATH": "/usr/bin:/bin", "HOME": str(self.home), **extra}

    def hook_lines(self, data=None, tag="x", plugin=None):
        """Log lines written by the real hook scripts of an installed copy; returns their ids."""
        data, plugin = data or self.data, plugin or sorted(self.cache.iterdir())[0]
        cfg = json.loads((plugin / "hooks" / "hooks.json").read_text())
        deny = {"session_id": "s" + tag, "tool_use_id": "d" + tag, "tool_name": "Read",
                "tool_input": {"file_path": ".env"}}
        ran = {"session_id": "s" + tag, "tool_use_id": "a" + tag, "tool_name": "Bash",
               "tool_input": {"command": "ls"}}
        for event, payload in (("PreToolUse", deny), ("PreToolUse", ran),
                               ("PostToolUse", dict(ran, tool_response="x"))):
            cmd = cfg["hooks"][event][0]["hooks"][0]["command"]
            env = {"PATH": "/usr/bin:/bin", "HOME": str(self.home),
                   "CLAUDE_PLUGIN_ROOT": str(plugin), "CLAUDE_PLUGIN_DATA": str(data)}
            cmd = cmd.replace("${CLAUDE_PLUGIN_ROOT}", str(plugin))
            out = subprocess.run(["/bin/bash", "-c", cmd],
                                 input=json.dumps(payload), env=env, capture_output=True, text=True,
                                 timeout=30)
            assert out.returncode == 0, out.stderr
        return ["d" + tag, "a" + tag]


def rec(path, scope="user", more=None):
    return dict({"scope": scope, "installPath": str(path), "version": "x",
                 "installedAt": "2026-11-07T00:00:00.000Z",
                 "lastUpdated": "2026-11-07T00:00:00.000Z", "gitCommitSha": "f" * 40},
                **(more or {}))


# ---- a process that prints its link and is stopped with Ctrl-C

class Proc:
    def __init__(self, args, env, cwd, group=False):
        self.p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                  env=env, cwd=str(cwd), start_new_session=group)
        self.group = group
        self.out, self.port, self.key = [], None, None
        guard = threading.Timer(60, self.kill)
        guard.start()
        try:
            for text in iter(self.p.stdout.readline, ""):
                self.out.append(text.rstrip("\n"))
                m = LINK.search(text)
                if m and self.port is None:
                    self.port, self.key = int(m.group(1)), m.group(2)
                if "Ctrl-C stops it" in text:
                    break
        finally:
            guard.cancel()
        if self.port is None:  # it exited without serving: collect the rest
            self.p.wait(timeout=30)
            self.out += self.p.stdout.read().splitlines()

    def signal(self, sig):
        if self.group:
            os.killpg(self.p.pid, sig)
        else:
            self.p.send_signal(sig)

    def kill(self):
        self.signal(signal.SIGKILL)

    def text(self):
        return "\n".join(self.out)

    def exit_code(self):
        return self.p.wait(timeout=30)

    def get(self, path, key=True):
        if key is True:
            key = self.key
        if key is not None:
            path += ("&" if "?" in path else "?") + "key=" + key
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, body

    def json(self, path):
        code, body = self.get(path)
        assert code == 200, (code, self.text())
        return json.loads(body)

    def stop(self):
        if self.p.poll() is None:
            self.signal(signal.SIGINT)
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.kill()
            self.p.wait()


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.delenv("GUARDRAILS_POLICY", raising=False)
    started = []

    def go(box, args, env=None, cwd=None, **kw):
        p = Proc(args, env if env is not None else box.env(), cwd or box.cwd, **kw)
        started.append(p)
        return p
    yield go
    for p in started:
        p.stop()


def launcher(run, box, copy, *args, env=None):
    return run(box, ["python3", str(copy / "dashboard.py"), "--port", "0", *args], env=env)


def start_cmd(run, box, *args, env=None, pre=""):
    cmd = pre + with_args(start_command(), "--port", "0", *args)
    return run(box, ["/bin/bash", "-c", cmd], env=env, group=True)  # the subshell is a child


def rule_count(p):
    return len(p.json("/api/policy")["rules"])


def full_rules(copy):
    return len(json.loads((copy / "policy.json").read_text())["rules"])


def event_ids(p):
    return [e["tool_use_id"] for e in p.json("/api/events?after=")]


def one(tmp_path, version="0.2.0"):
    box = Box(tmp_path)
    copy = box.copy(version)
    box.record((copy,))
    return box, copy


# ---- cases 1-3: one installed copy

def test_case_01_the_launcher_serves_the_policy_in_force(tmp_path, run):
    box, copy = one(tmp_path)
    box.hook_lines()
    p = launcher(run, box, copy)
    assert re.fullmatch(r"agent-guardrails dashboard: http://127\.0\.0\.1:\d+/\?key=\S+",
                        p.out[0])
    expected, _ = load_policy(str(copy), str(box.data))
    assert p.json("/api/policy") == expected


def test_case_02_the_events_are_the_hook_written_lines_of_that_install(tmp_path, run):
    box, copy = one(tmp_path)
    ids = box.hook_lines()
    assert list((box.data / "audit").glob("*.jsonl"))
    p = launcher(run, box, copy)
    code, _ = p.get("/api/events?after=")
    assert code == 200
    assert set(ids) <= set(event_ids(p))


def test_case_03_the_start_up_lines_name_the_copy_and_its_data_folder(tmp_path, run):
    box, copy = one(tmp_path)
    box.hook_lines()
    text = launcher(run, box, copy).text()
    assert "  plugin: %s (version 0.2.0 from .claude-plugin/plugin.json)" % copy in text
    assert "  shipped policy: %s" % (copy / "policy.json") in text
    assert "  data folder: %s (this install's folder; --data picks another)" % box.data in text


# ---- cases 4-9: which copy runs

def two(tmp_path, named, **kw):
    box = Box(tmp_path)
    old = box.copy("0.1.0", fewer_rules=1, **kw)
    new = box.copy("0.2.0")
    box.record((old if named == "old" else new,))
    return box, old, new


def test_case_04_the_start_command_hands_over_to_the_copy_in_the_record(tmp_path, run):
    box, old, new = two(tmp_path, "new")
    p = start_cmd(run, box)  # bash sorts 0.1.0 first
    assert rule_count(p) == full_rules(new) == full_rules(old) + 1
    assert "  plugin: %s (version 0.2.0" % new in p.text()
    assert len([ln for ln in p.out if LINK.search(ln)]) == 1


def test_case_05_a_new_launcher_hands_over_to_the_old_copy_in_the_record(tmp_path, run):
    box, old, new = two(tmp_path, "old")
    p = launcher(run, box, new)
    assert rule_count(p) == full_rules(old)
    assert "  plugin: %s (version 0.1.0" % old in p.text()


def test_case_06_a_version_in_force_without_a_dashboard_is_named(tmp_path, run):
    box = Box(tmp_path)
    old = box.copy("0.1.0", dashboard=False)
    new = box.copy("0.2.0")
    box.record((old,))
    p = launcher(run, box, new)
    assert p.port is None and p.exit_code() == 2
    assert str(old) in p.text() and "version 0.1.0" in p.text() and UPDATE in p.text()
    assert "http://127.0.0.1" not in p.text()


def test_case_07_an_orphaned_old_copy_hands_over_to_the_new_one(tmp_path, run):
    box, old, new = two(tmp_path, "new")
    (old / ".orphaned_at").write_text("1762560000000")
    p = launcher(run, box, old)
    assert rule_count(p) == full_rules(new)


def test_case_08_the_user_record_beats_the_project_record(tmp_path, run):
    box, old, new = two(tmp_path, "new")
    box.record((new, "user"), (old, "project", {"projectPath": "/work/proj"}))
    p = launcher(run, box, old)
    assert rule_count(p) == full_rules(new)
    assert "also installed: %s (scope project, project /work/proj)" % old in p.text()


def test_case_09_a_project_record_alone_is_the_copy_in_force(tmp_path, run):
    box, old, new = two(tmp_path, "old")
    box.record((old, "project", {"projectPath": "/work/proj"}))
    p = launcher(run, box, new)
    assert rule_count(p) == full_rules(old)


# ---- cases 10-13: a record that cannot be used

def unchecked(p, box, copy):
    lines = [ln for ln in p.out if "warning" in ln.lower()]
    assert len(lines) == 1 and "installed_plugins.json" in lines[0]
    assert "could not be checked against Claude Code's record" in lines[0]
    assert rule_count(p) == full_rules(copy)
    assert "Traceback" not in p.text()


def test_case_10_a_record_without_the_key_warns_and_serves_the_started_copy(tmp_path, run):
    box = Box(tmp_path)
    copy = box.copy("0.2.0")
    box.write_record(json.dumps({"version": 2, "plugins": {"other@x": [rec(copy)]}}))
    unchecked(launcher(run, box, copy), box, copy)


@pytest.mark.parametrize("text", [
    "this is not json",
    "[1, 2]",
    json.dumps({"version": 2, "plugins": {KEY: [{"scope": "user"}]}}),
], ids=["not-json", "list", "no-installPath"])
def test_case_11_a_broken_record_is_the_same_as_a_missing_key(tmp_path, run, text):
    box = Box(tmp_path)
    copy = box.copy("0.2.0")
    box.write_record(text)
    unchecked(launcher(run, box, copy), box, copy)


def test_case_12_a_second_hand_over_is_refused(tmp_path, run):
    box, old, new = two(tmp_path, "old")
    p = launcher(run, box, new, env=box.env(GUARDRAILS_DASHBOARD_HANDOVER="1"))
    assert p.port is None and p.exit_code() == 2
    assert ("Claude Code's plugin record changed while the dashboard was starting; "
            "run the command again.") in p.text()


def test_case_13_a_record_outside_the_cache_is_never_run(tmp_path, run):
    box = Box(tmp_path)
    copy = box.copy("0.2.0")
    evil = tmp_path / "evil"
    evil.mkdir()
    marker = tmp_path / "marker"
    (evil / "dashboard.py").write_text("open(%r, 'w').write('ran')\n" % str(marker))
    box.record((evil,))
    p = launcher(run, box, copy)
    assert "warning" in p.text().lower() and rule_count(p) == full_rules(copy)
    assert not marker.exists()


# ---- cases 14-16: nothing to start, no log yet

NOTHING = ("No agent-guardrails dashboard in %s/.claude/plugins/cache/agent-guardrails/"
           "agent-guardrails/. Install the plugin, or update it to 0.2.0 or later "
           "(see Get started).")


@pytest.mark.parametrize("pre", ["", "shopt -s nullglob; "], ids=["default", "nullglob"])
def test_case_14_no_copy_prints_where_it_looked(tmp_path, pre):
    box = Box(tmp_path)
    out = subprocess.run(["/bin/bash", "-c", pre + start_command()], env=box.env(),
                         cwd=str(box.cwd), capture_output=True, text=True, timeout=30)
    assert out.returncode == 1 and out.stdout == ""
    assert NOTHING % box.home in out.stderr


def test_case_15_a_copy_without_a_dashboard_prints_the_same(tmp_path):
    box = Box(tmp_path)
    box.copy("0.1.0", dashboard=False)
    out = subprocess.run(["/bin/bash", "-c", start_command()], env=box.env(), cwd=str(box.cwd),
                         capture_output=True, text=True, timeout=30)
    assert out.returncode == 1 and out.stdout == ""
    assert NOTHING % box.home in out.stderr


def test_case_16_no_data_folder_yet_still_starts(tmp_path, run):
    box, copy = one(tmp_path)
    assert not box.data.exists()
    st = launcher(run, box, copy).json("/api/status")
    assert st["log_found"] is False
    assert st["plugin_detail"] == "No audit log yet in %s" % box.data


# ---- cases 17-18: CLAUDE_CONFIG_DIR, and another install's folder

def test_case_17_a_config_folder_from_the_environment_is_searched(tmp_path, run):
    cfg = tmp_path / "elsewhere"
    box = Box(tmp_path, config=cfg)
    copy = box.copy("0.2.0")
    box.record((copy,))
    p = start_cmd(run, box, env=box.env(CLAUDE_CONFIG_DIR=str(cfg)))
    assert "  plugin: %s (version" % copy in p.text()
    assert "  data folder: %s " % (cfg / "plugins" / "data" / PAIRED) in p.text()


def test_case_18_another_installs_newer_log_is_never_shown(tmp_path, run):
    cfg = tmp_path / "elsewhere"
    box = Box(tmp_path, config=cfg)
    copy = box.copy("0.2.0")
    box.record((copy,))
    mine = box.hook_lines(tag="mine")
    inline = box.home / ".claude" / "plugins" / "data" / "agent-guardrails-inline"
    other = box.hook_lines(data=inline, tag="other", plugin=copy)
    p = start_cmd(run, box, env=box.env(CLAUDE_CONFIG_DIR=str(cfg)))
    assert "  data folder: %s (this install" % box.data in p.text()
    ids = event_ids(p)
    assert set(mine) <= set(ids) and not set(other) & set(ids)


# ---- cases 19-21: the key, the options, the added policy

@pytest.mark.parametrize("path", ["/", "/api/status", "/api/policy", "/api/events?after="])
def test_case_19_a_missing_or_wrong_key_is_refused(tmp_path, run, path):
    box, copy = one(tmp_path)
    box.hook_lines()
    p = launcher(run, box, copy)
    for key in (None, "wrong", p.key[:-1]):
        assert p.get(path, key=key)[0] == 403
    assert p.get(path)[0] == 200


def test_case_20_options_after_the_file_name_reach_the_server(tmp_path, run):
    box, copy = one(tmp_path)
    other = tmp_path / "chosen"
    ids = box.hook_lines(data=other, tag="chosen", plugin=copy)
    p = start_cmd(run, box, "--data", str(other))
    assert f"http://127.0.0.1:{p.port}/" in p.text()
    assert set(ids) <= set(event_ids(p))
    assert "  data folder: %s" % other in p.text() and "this install's folder" not in p.text()


def test_case_21_the_added_policy_of_the_data_folder_is_merged(tmp_path, run):
    box, copy = one(tmp_path)
    box.data.mkdir(parents=True)
    added = {"version": 1, "rules": [{"id": "ask-added-by-test", "decision": "ask", "kind": "tool",
                                     "match": ["NoSuchTool"], "reason": "test"}]}
    (box.data / "policy.json").write_text(json.dumps(added))
    p = launcher(run, box, copy)
    assert "ask-added-by-test" in [r["id"] for r in p.json("/api/policy")["rules"]]


# ---- cases 22-23: a clone keeps working

def test_case_22_make_dashboard_from_a_clone(tmp_path, run):
    box = Box(tmp_path)
    ids = box.hook_lines(data=tmp_path / "d", tag="clone", plugin=PLUGIN)
    p = run(box, ["make", "dashboard", 'ARGS=--port 0 --data %s' % (tmp_path / "d")],
            env={"PATH": os.environ["PATH"], "HOME": str(box.home)}, cwd=ROOT, group=True)
    at = next(n for n, ln in enumerate(p.out) if ln.startswith("agent-guardrails dashboard: http"))
    # make echoes its recipe, then the server prints the link as its first line
    assert at <= 2 and "python3 -m guardrails_dashboard" in p.out[at - 1]
    assert "  shipped policy: %s" % (PLUGIN / "policy.json") in p.text()
    code, _ = p.get("/api/events?after=")
    assert code == 200 and set(ids) <= set(event_ids(p))


def test_case_23_the_module_from_a_clone(tmp_path, run):
    box = Box(tmp_path)
    ids = box.hook_lines(data=tmp_path / "d", tag="module", plugin=PLUGIN)
    env = {"PATH": os.environ["PATH"], "HOME": str(box.home), "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONPATH": "packages/guardrails-core/src:packages/guardrails-dashboard/src"}
    p = run(box, ["python3", "-m", "guardrails_dashboard", "--port", "0", "--data",
                  str(tmp_path / "d")], env=env, cwd=ROOT)
    assert p.out[0].startswith("agent-guardrails dashboard: http://127.0.0.1:")
    assert "  shipped policy: %s" % (PLUGIN / "policy.json") in p.text()
    assert p.get("/api/events?after=")[0] == 200 and set(ids) <= set(event_ids(p))
