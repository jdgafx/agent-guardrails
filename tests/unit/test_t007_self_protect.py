"""T-007: the policy files can only add, and a deny stays a deny. One test per case of the design.

Every case copies packages/guardrails-plugin (so no test writes into the repo) and runs the copy's
hooks/pre_tool_use.py as a subprocess with real temp folders, real links and a real chmod.
"""
import copy
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "packages" / "guardrails-plugin"
SHIPPED = json.loads((PLUGIN / "policy.json").read_text())
SCHEMA = json.loads((PLUGIN / "policy.schema.json").read_text())
FIXTURES = json.loads((ROOT / "packages" / "guardrails-demo" / "src" / "guardrails_demo"
                       / "fixtures.json").read_text())

DENY_MINE = {"id": "deny-mine", "decision": "deny", "kind": "path", "match": ["*.secret"],
             "reason": "r"}


def shipped(**changes):
    """A copy of the shipped policy with some top-level keys changed (None removes a key)."""
    p = copy.deepcopy(SHIPPED)
    for k, v in changes.items():
        if v is None:
            p.pop(k, None)
        else:
            p[k] = v
    return p


def rule_changed(policy, rid, **fields):
    for r in policy["rules"]:
        if r["id"] == rid:
            r.update(fields)
    return policy


def only(*rules):
    return {"version": 1, "rules": list(rules)}


class Env:
    """One throwaway plugin copy plus data, home, project and tmp folders."""

    def __init__(self, base):
        base = Path(os.path.realpath(base))
        self.root = base / "plugin"
        shutil.copytree(PLUGIN, self.root)
        self.data = base / "data"
        self.home = base / "home"
        self.proj = base / "proj"
        self.tmp = base / "tmp"
        for d in (self.data, self.home, self.proj, self.tmp):
            d.mkdir()
        self.extra = {}
        self.data_set = True

    def write_json(self, path, obj):
        Path(path).write_text(obj if isinstance(obj, str) else json.dumps(obj))
        return str(path)

    def hook(self, event, tool, tin, tid="t1", cwd=None, **more):
        script = "pre_tool_use.py" if event == "PreToolUse" else "post_tool_use.py"
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.home),
               "CLAUDE_PLUGIN_ROOT": str(self.root)}
        if self.data_set:
            env["CLAUDE_PLUGIN_DATA"] = str(self.data)
        env.update({k: str(v) for k, v in self.extra.items()})
        payload = {"session_id": "s", "tool_use_id": tid, "hook_event_name": event,
                   "tool_name": tool, "tool_input": tin, "cwd": str(cwd or self.proj)}
        payload.update(more)
        return subprocess.run([sys.executable, str(self.root / "hooks" / script)],
                              input=json.dumps(payload), capture_output=True, text=True,
                              env=env, timeout=30)

    def pre(self, tool, tin, **kw):
        """Return (decision, rule id, reason). Allow prints nothing."""
        r = self.hook("PreToolUse", tool, tin, **kw)
        assert r.returncode == 0, r.stderr
        if not r.stdout.strip():
            return "allow", None, ""
        h = json.loads(r.stdout)["hookSpecificOutput"]
        reason = h["permissionDecisionReason"]
        return h["permissionDecision"], reason[1:reason.index("]")], reason

    def audit(self):
        out = []
        folder = self.data / "audit"
        for f in sorted(folder.glob("*.jsonl")) if folder.is_dir() else []:
            out += [json.loads(x) for x in f.read_text().splitlines()]
        return out


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def check(env, tool, tin, want, **kw):
    got = env.pre(tool, tin, **kw)
    assert got[:2] == want, got
    return got


DENY_GUARD = ("deny", "deny-guard-files")
ASK_GUARD = ("ask", "ask-guard-paths")
ALLOW = ("allow", None)
ASK_POLICY = ("ask", "guardrails-policy-error")
DENY_ENV = ("deny", "deny-env-files")
ASK_ENV = ("ask", "deny-env-files")  # T-018: a shell text match asks


# ---- Write tools on guard paths (goal d)

def test_case01_write_to_data_policy_is_denied(env):
    check(env, "Write", {"file_path": str(env.data / "policy.json"), "content": "{}"}, DENY_GUARD)


def test_case02_edit_of_shipped_policy_is_denied(env):
    check(env, "Edit", {"file_path": str(env.root / "policy.json"), "old_string": '"deny"',
                        "new_string": '"ask"'}, DENY_GUARD)


def test_case03_write_to_hook_script_is_denied(env):
    check(env, "Write", {"file_path": str(env.root / "hooks" / "pre_tool_use.py"),
                         "content": "print()"}, DENY_GUARD)


def test_case04_dotdot_into_vendor_is_denied(env):
    p = str(env.root / "hooks" / ".." / "vendor" / "guardrails_core" / "rules.py")
    check(env, "Write", {"file_path": p, "content": ""}, DENY_GUARD)


def test_case05_multiedit_of_step_counter_is_denied(env):
    check(env, "MultiEdit", {"file_path": str(env.data / "state" / "s.calls"), "edits": []},
          DENY_GUARD)


def test_case06_notebook_edit_in_audit_is_denied(env):
    check(env, "NotebookEdit", {"notebook_path": str(env.data / "audit" / "x.ipynb"),
                                "new_source": ""}, DENY_GUARD)


def test_case07_symlink_into_data_is_denied(env):
    (env.proj / "link").symlink_to(env.data)
    check(env, "Write", {"file_path": str(env.proj / "link" / "policy.json"), "content": "{}"},
          DENY_GUARD)


def test_case08_relative_dotdot_path_is_denied(tmp_path):
    e = Env(tmp_path)
    e.data = e.tmp / "d"
    e.proj = e.tmp / "p"
    e.data.mkdir()
    e.proj.mkdir()
    check(e, "Write", {"file_path": "../d/policy.json", "content": "{}"}, DENY_GUARD)


def test_case09_mcp_write_with_tilde_path_is_denied(tmp_path):
    e = Env(tmp_path)
    e.data = e.home / "plugdata"
    e.data.mkdir()
    check(e, "mcp__fs__write_file", {"path": "~/plugdata/policy.json"}, DENY_GUARD)


def test_case10_mcp_read_on_audit_log_is_denied(env):
    check(env, "mcp__fs__read_file", {"path": str(env.data / "audit" / "x.jsonl")}, DENY_GUARD)


def test_case11_write_to_env_policy_file_is_denied(env):
    mine = env.write_json(env.tmp / "mine.json", only(DENY_MINE))
    env.extra["GUARDRAILS_POLICY"] = mine
    check(env, "Write", {"file_path": mine, "content": "{}"}, DENY_GUARD)


def test_case12_deny_holds_when_shipped_policy_is_broken_and_is_logged(env):
    env.write_json(env.root / "policy.json", "{}")
    check(env, "Write", {"file_path": str(env.data / "policy.json"), "content": "{}"}, DENY_GUARD)
    lines = env.audit()
    assert [(x["event"], x["decision"], x["rule"]) for x in lines] == [
        ("decision", "deny", "deny-guard-files")]


def test_case13_folder_with_same_prefix_is_not_inside(tmp_path):
    e = Env(tmp_path)
    e.data = e.tmp / "d"
    e.data.mkdir()
    check(e, "Write", {"file_path": str(e.tmp / "d2" / "x"), "content": ""}, ALLOW)


def test_case14_read_of_audit_log_is_allowed(env):
    (env.data / "audit").mkdir()
    (env.data / "audit" / "a.jsonl").write_text("")
    check(env, "Read", {"file_path": str(env.data / "audit" / "a.jsonl")}, ALLOW)


# ---- Added policy files can only add (goal a)

def test_case15_added_ask_rule_does_not_weaken_a_deny(env):
    env.write_json(env.data / "policy.json", only(
        {"id": "x", "decision": "ask", "kind": "tool", "match": ["^NeverMatches$"], "reason": "x"}))
    check(env, "Read", {"file_path": ".env"}, DENY_ENV)


def test_case16_env_policy_cannot_turn_deny_into_ask(env):
    p = rule_changed(shipped(), "deny-env-files", decision="ask")
    env.extra["GUARDRAILS_POLICY"] = env.write_json(env.tmp / "p.json", p)
    check(env, "Read", {"file_path": ".env"}, DENY_ENV)


def test_case17_added_policy_cannot_remove_a_shipped_rule(env):
    p = shipped()
    p["rules"] = [r for r in p["rules"] if r["id"] != "deny-prod-config"]
    env.write_json(env.data / "policy.json", p)
    check(env, "Read", {"file_path": "/srv/app/production/db.yaml"},
          ("deny", "deny-prod-config"))


def test_case18_added_policy_cannot_raise_the_step_cap(env):
    p = shipped()
    p["step_cap"]["max_calls"] = 1000
    env.write_json(env.data / "policy.json", p)
    (env.data / "state").mkdir()
    (env.data / "state" / "s.calls").write_text('{"id": "x"}\n' * 205)
    check(env, "Bash", {"command": "ls"}, ("ask", "step-cap"))


def test_case19_added_rule_is_applied(env):
    env.write_json(env.data / "policy.json", only(DENY_MINE))
    check(env, "Read", {"file_path": "a.secret"}, ("deny", "deny-mine"))
    check(env, "Read", {"file_path": "a.txt"}, ALLOW, tid="t2")


def test_case20_env_and_data_policy_both_add(env):
    a = dict(DENY_MINE, id="deny-a", match=["*.a"])
    b = dict(DENY_MINE, id="deny-b", match=["*.b"])
    env.extra["GUARDRAILS_POLICY"] = env.write_json(env.tmp / "a.json", only(a))
    env.write_json(env.data / "policy.json", only(b))
    check(env, "Read", {"file_path": "x.a"}, ("deny", "deny-a"))
    check(env, "Read", {"file_path": "x.b"}, ("deny", "deny-b"), tid="t2")


# Rules from main's `make demo` table, in fixture order (decision, rule id).
DEMO_TABLE = [
    ("allow", "default-allow"), ("deny", "deny-env-files"), ("deny", "deny-env-files"),
    ("allow", "default-allow"), ("ask", "deny-key-files"), ("deny", "deny-credential-dirs"),
    ("deny", "deny-prod-config"), ("allow", "default-allow"), ("allow", "default-allow"),
    ("ask", "ask-git-push"), ("ask", "deny-force-push"), ("ask", "ask-rm-recursive"),
    ("ask", "ask-terraform-apply"), ("ask", "ask-vercel-prod"), ("ask", "ask-publish"),
    ("ask", "ask-mcp-write"), ("allow", "default-allow"), ("allow", "default-allow"),
    ("allow", "default-allow"), ("ask", "ask-after-injection"), ("allow", "default-allow"),
    ("allow", "default-allow"), ("allow", "default-allow"), ("allow", "default-allow"),
    ("ask", "step-cap"), ("ask", "step-cap"),
]


def test_case21_demo_table_is_unchanged(tmp_path):
    from guardrails_demo import runner
    data = tmp_path / "data"
    data.mkdir()
    pol = shipped()
    pol["step_cap"]["max_calls"] = runner.DEMO_CAP
    (data / "policy.json").write_text(json.dumps(pol))
    got = []
    for i, fx in enumerate(FIXTURES, 1):
        fx = runner.fill(fx)
        payload = {"session_id": fx.get("session", "demo-%d" % i), "tool_use_id": "t%d" % i,
                   "tool_name": fx["tool_name"], "tool_input": fx["tool_input"],
                   "hook_event_name": "PreToolUse"}
        got.append(runner.decide(runner.run_hook("pre_tool_use.py", payload, str(data)).stdout))
        if "tool_response" in fx:  # as runner.py does: the flagged page marks its session
            post = dict(payload, hook_event_name="PostToolUse", tool_response=fx["tool_response"])
            runner.run_hook("post_tool_use.py", post, str(data))
    assert got == DEMO_TABLE


def test_case22_added_audit_keys_are_ignored(env):
    env.write_json(env.data / "policy.json", shipped(audit={"max_input_chars": 100}))
    cmd = "cat .env #" + "a" * 500
    check(env, "Bash", {"command": cmd}, ASK_ENV)
    assert env.audit()[0]["input"] == {"command": cmd}


# ---- A deny stays a deny (goal b)

def test_case23_unset_data_folder_keeps_env_deny(env):
    env.data_set = False
    check(env, "Read", {"file_path": ".env"}, DENY_ENV)


def test_case24_unset_data_folder_keeps_the_force_push_rule(env):
    env.data_set = False
    check(env, "Bash", {"command": "git push --force origin main"}, ("ask", "deny-force-push"))


def test_case25_unset_data_folder_still_asks_an_allow(env):
    env.data_set = False
    check(env, "Bash", {"command": "ls"}, ("ask", "guardrails-error"))


def test_case26_data_folder_that_is_a_file_keeps_deny(env):
    env.data.rmdir()
    env.data.write_text("a file")
    check(env, "Read", {"file_path": ".env"}, DENY_ENV)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_case27_read_only_state_keeps_deny_and_asks_an_allow(env):
    (env.data / "state").mkdir()
    (env.data / "state").chmod(0o500)
    try:
        check(env, "Read", {"file_path": ".env"}, DENY_ENV)
        check(env, "Bash", {"command": "ls"}, ("ask", "guardrails-error"), tid="t2")
    finally:
        (env.data / "state").chmod(0o700)


def test_case28_broken_data_policy_keeps_env_deny(env):
    env.write_json(env.data / "policy.json", "{not json")
    check(env, "Read", {"file_path": ".env"}, DENY_ENV)


def test_case29_broken_data_policy_keeps_git_push_ask(env):
    env.write_json(env.data / "policy.json", "{not json")
    check(env, "Bash", {"command": "git push origin main"}, ("ask", "ask-git-push"))


def test_case30_broken_data_policy_makes_unmatched_calls_ask_and_logs_it(env):
    env.write_json(env.data / "policy.json", "{not json")
    got = check(env, "Bash", {"command": "ls"}, ASK_POLICY)
    assert str(env.data / "policy.json") in got[2]
    assert [(x["event"], x["rule"]) for x in env.audit()] == [
        ("decision", "guardrails-policy-error")]


def test_case31_dangling_symlink_policy_asks(env):
    (env.data / "policy.json").symlink_to(env.tmp / "missing.json")
    check(env, "Bash", {"command": "ls"}, ASK_POLICY)


def test_case32_fifo_policy_asks_and_does_not_hang(env):
    os.mkfifo(env.data / "policy.json")
    start = time.monotonic()
    check(env, "Bash", {"command": "ls"}, ASK_POLICY)
    assert time.monotonic() - start < 2


# ---- Strict checks (goal c)

def test_case33_string_except_is_rejected_and_the_deny_stays(env):
    env.write_json(env.data / "policy.json", rule_changed(shipped(), "deny-env-files",
                                                         **{"except": "*.example"}))
    check(env, "Read", {"file_path": ".env"}, DENY_ENV)
    got = check(env, "Bash", {"command": "ls"}, ASK_POLICY, tid="t2")
    assert "except" in got[2]


def test_case34_unknown_top_level_key_is_rejected(env):
    env.write_json(env.data / "policy.json", shipped(step_caps={"max_calls": 5}))
    got = check(env, "Bash", {"command": "ls"}, ASK_POLICY)
    assert "step_caps" in got[2]


def test_case35_version_true_is_rejected(env):
    env.write_json(env.data / "policy.json", shipped(version=True))
    check(env, "Bash", {"command": "ls"}, ASK_POLICY)


def test_case36_version_float_is_rejected(env):
    env.write_json(env.data / "policy.json", shipped(version=1.0))
    check(env, "Bash", {"command": "ls"}, ASK_POLICY)


def test_case37_decision_allow_is_rejected(env):
    env.write_json(env.data / "policy.json", rule_changed(shipped(), "deny-key-files",
                                                         decision="allow"))
    check(env, "Bash", {"command": "ls"}, ASK_POLICY)


def test_case38_added_policy_without_step_cap_keeps_the_shipped_cap(env):
    env.write_json(env.data / "policy.json", only(DENY_MINE))
    (env.data / "state").mkdir()
    (env.data / "state" / "s.calls").write_text('{"id": "x"}\n' * 205)
    check(env, "Bash", {"command": "ls"}, ("ask", "step-cap"))


def test_case39_missing_env_policy_path_is_an_error(env):
    env.extra["GUARDRAILS_POLICY"] = "/nonexistent/p.json"
    check(env, "Read", {"file_path": ".env"}, DENY_ENV)
    got = check(env, "Bash", {"command": "ls"}, ASK_POLICY, tid="t2")
    assert "/nonexistent/p.json" in got[2]


def test_case40_env_policy_that_is_a_folder_is_an_error(env):
    env.extra["GUARDRAILS_POLICY"] = env.tmp
    check(env, "Bash", {"command": "ls"}, ASK_POLICY)


def test_case41_shipped_policy_without_step_cap_asks_everything(env):
    env.write_json(env.root / "policy.json", shipped(step_cap=None))
    check(env, "Bash", {"command": "ls"}, ("ask", "guardrails-error"))


def test_case42_schema_walker_accepts_the_shipped_files():
    from guardrails_core.policy import check_schema, validate
    check_schema(SCHEMA)  # raises on any keyword the walker does not know
    validate(SHIPPED, SCHEMA)


# ---- A Bash command that names a guard path (goal e)

def test_case43_redirect_into_data_policy_asks(env):
    check(env, "Bash", {"command": "echo '{}' > %s" % (env.data / "policy.json")}, ASK_GUARD)


def test_case44_sed_on_shipped_policy_asks(env):
    check(env, "Bash", {"command": "sed -i s/deny/ask/ %s" % (env.root / "policy.json")},
          ASK_GUARD)


def test_case45_tilde_path_into_data_asks(tmp_path):
    e = Env(tmp_path)
    e.data = e.home / "plugdata"
    e.data.mkdir()
    check(e, "Bash", {"command": "tail ~/plugdata/audit/x.jsonl"}, ASK_GUARD)


def test_case46_guard_ask_wins_a_tie_with_a_shell_ask(env):
    check(env, "Bash", {"command": "cat .env > %s" % (env.data / "x")}, ASK_GUARD)


def test_case47_guard_ask_wins_a_tie(env):
    check(env, "Bash", {"command": "rm -r %s" % (env.data / "state")}, ASK_GUARD)


def test_case48_folder_with_same_prefix_is_not_a_guard_path(tmp_path):
    e = Env(tmp_path)
    e.data = e.tmp / "d"
    e.data.mkdir()
    check(e, "Bash", {"command": "ls %s" % (e.tmp / "d2")}, ALLOW)


# ---- The stated limit: these allow, so the docs' claim is tested

def test_case49_variable_path_is_not_seen(env):
    check(env, "Bash", {"command": 'rm "$CLAUDE_PLUGIN_DATA"/state/s.calls'}, ALLOW)


def test_case50_relative_path_after_cd_is_not_seen(tmp_path):
    e = Env(tmp_path)
    e.data = e.home / "plugdata"
    e.data.mkdir()
    cmd = "cd %s && python3 -c \"open('plugdata/policy.json','w')\"" % e.home
    check(e, "Bash", {"command": cmd}, ALLOW)


# ---- Must keep working

def test_case51_ordinary_edits_are_allowed(env):
    check(env, "Read", {"file_path": "README.md"}, ALLOW)
    check(env, "Edit", {"file_path": "src/app.py", "old_string": "a", "new_string": "b"}, ALLOW,
          tid="t2")
    check(env, "Write", {"file_path": str(env.proj / "notes.md"), "content": "x"}, ALLOW, tid="t3")


def test_case52_shipped_rules_still_decide(env):
    check(env, "Read", {"file_path": ".env.example"}, ALLOW)
    check(env, "Bash", {"command": "git push origin main"}, ("ask", "ask-git-push"), tid="t2")
    check(env, "Bash", {"command": "git push --force origin main"},
          ("ask", "deny-force-push"), tid="t3")
    check(env, "Bash", {"command": "cd ~ && ls"}, ALLOW, tid="t4")


def test_case53_audit_flow_pre_then_post(env):
    check(env, "Bash", {"command": "cat .env"}, ASK_ENV, tid="t1")
    lines = env.audit()
    assert [(x["event"], x["decision"], x["rule"]) for x in lines] == [
        ("decision", "ask", "deny-env-files")]
    check(env, "Bash", {"command": "ls"}, ALLOW, tid="t2")
    r = env.hook("PostToolUse", "Bash", {"command": "ls"}, tid="t2",
                 tool_response={"stdout": "x"})
    assert r.returncode == 0, r.stderr
    last = env.audit()[-1]
    assert (last["event"], last["decision"]) == ("result", "allow")
    assert len(env.audit()) == 2


# ---- Claude Code settings files (Chris answered yes to question 3)

def test_case54_write_to_project_settings_asks(env):
    check(env, "Write", {"file_path": str(env.proj / ".claude" / "settings.json"),
                         "content": "{}"}, ("ask", "ask-claude-settings"))


def test_case55_edit_of_home_settings_local_asks(env):
    check(env, "Edit", {"file_path": str(env.home / ".claude" / "settings.local.json"),
                        "old_string": "a", "new_string": "b"}, ("ask", "ask-claude-settings"))


# ---- Round 2: a NUL byte must not turn a deny into an ask; CLAUDE_CONFIG_DIR; stated Bash limits

def test_case56_nul_word_keeps_the_force_push_rule(env):
    check(env, "Bash", {"command": "git push --force origin main /tmp/a\x00"},
          ("ask", "deny-force-push"))


def test_case57_nul_word_keeps_the_env_rule_and_a_clean_command_allows(env):
    check(env, "Bash", {"command": "cat .env /x\x00"}, ASK_ENV)
    check(env, "Bash", {"command": "ls /tmp/a\x00"}, ALLOW, tid="t2")


def test_case58_write_to_claude_config_dir_settings_asks(env):
    cfg = env.tmp / "cfg"
    env.extra["CLAUDE_CONFIG_DIR"] = cfg
    check(env, "Write", {"file_path": str(cfg / "settings.json"), "content": "{}"},
          ("ask", "ask-claude-settings"))
    check(env, "Write", {"file_path": str(cfg / "other.json"), "content": "{}"}, ALLOW, tid="t2")


def test_case59_bash_forms_the_tripwire_does_not_see_are_allowed(tmp_path):
    e = Env(tmp_path)
    e.data = e.tmp / "my dir" / "data"  # a space in a parent folder: the word split cuts the path
    e.data.mkdir(parents=True)
    for i, cmd in enumerate((
            'rm "%s/policy.json"' % e.data,
            "rm %s/d*/policy.json" % e.tmp,  # a glob
            "mv %s /tmp/x" % e.tmp)):        # a parent folder
        check(e, "Bash", {"command": cmd}, ALLOW, tid="g%d" % i)
