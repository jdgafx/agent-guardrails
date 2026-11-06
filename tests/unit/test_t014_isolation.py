"""T-014: opt-in isolation. One test per unit case of the design (## Cases of
designs/agent-guardrails-T-014/design.md): 31, 34 to 44 and 46 to 48.

Cases 1 to 30, 32, 33 and 37 run live in tests/live/t014_probe.py (a real `claude -p` session
with the real sandbox; not part of `make test`). Case 45 is docs only (PowerShell and Monitor
are sandboxed per the Claude Code docs; not probed). Cases 38, 47 and 48 are also run through
the real hook scripts in tests/e2e/test_hooks_e2e.py.

The tests call the real run_pre / run_post on the shipped policy.json, with real files in a temp
project folder: no mocks.
"""
import copy
import json
import re
import shutil
from pathlib import Path

import pytest
from guardrails_core import hooks, isolation, policy, redact

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "packages" / "guardrails-plugin"
SHIPPED = json.loads((PLUGIN / "policy.json").read_text())
BLOCK_FILE = PLUGIN / "isolation" / "settings.local.json"
SECRET = "sk-ant-" + "abcdefghijklmnopqrstuvwx"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    monkeypatch.delenv("GUARDRAILS_POLICY", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()


@pytest.fixture
def data(tmp_path):
    return tmp_path / "data"


@pytest.fixture
def proj(tmp_path):
    p = tmp_path / "proj"
    p.mkdir()
    return p


@pytest.fixture
def iso_on(tmp_path, monkeypatch):
    """GUARDRAILS_POLICY names the README's file, word for word."""
    f = tmp_path / "iso.json"
    f.write_text('{"version": 1, "isolation": true}\n')
    monkeypatch.setenv("GUARDRAILS_POLICY", str(f))
    return f


def put_settings(proj, name="settings.local.json", obj=None, text=None):
    d = proj / ".claude"
    d.mkdir(exist_ok=True)
    (d / name).write_text(text if text is not None else json.dumps(obj))


def put_block(proj, mutate=None):
    block = isolation.sandbox_block(SHIPPED)
    if mutate:
        mutate(block["sandbox"])
    put_settings(proj, obj=block)


def pre(tool, tin, proj, data, **extra):
    raw = json.dumps(dict({"session_id": "s", "tool_use_id": "t", "tool_name": tool,
                           "tool_input": tin, "cwd": str(proj)}, **extra))
    out = hooks.run_pre(raw, str(PLUGIN), str(data))
    if not out:
        return "allow", None, None
    h = json.loads(out)["hookSpecificOutput"]
    m = re.match(r"\[([^\]]+)\] (.*)", h["permissionDecisionReason"], re.S)
    return h["permissionDecision"], m.group(1), m.group(2)


def post(tool, response, data, **extra):
    p = dict({"session_id": "s", "tool_use_id": "t", "hook_event_name": "PostToolUse",
              "tool_name": tool, "tool_input": {"command": "x"}, "tool_response": response},
             **extra)
    return hooks.run_post(json.dumps(p), str(PLUGIN), str(data))


# ---- the generator (cases 34, 35)

def _core(g):
    g = g[2:] if g.startswith("*/") else g
    return g[:-2] if g.endswith("/*") else g


def test_case_34_block_comes_from_the_secret_list_and_matches_the_committed_file():
    block = isolation.sandbox_block(SHIPPED)
    assert block == json.loads(BLOCK_FILE.read_text())
    sb = block["sandbox"]
    assert (sb["enabled"], sb["failIfUnavailable"], sb["allowUnsandboxedCommands"],
            sb["autoAllowBashIfSandboxed"]) == (True, True, False, False)
    deny, allow = sb["filesystem"]["denyRead"], sb["filesystem"]["allowRead"]
    by_id = {r["id"]: r for r in SHIPPED["rules"]}
    want_deny, want_allow = [], []
    for rid in ("deny-env-files", "deny-credential-dirs"):
        for g in by_id[rid]["match"]:
            for a in ("./**/", "~/", "~/.config/"):
                assert a + _core(g) in deny
                want_deny.append(a + _core(g))
        for g in by_id[rid].get("except", []):
            for a in ("./**/", "~/", "~/.config/"):
                assert a + _core(g) in allow
                want_allow.append(a + _core(g))
    assert len(deny) == len(set(deny)) == len(set(want_deny))
    assert len(allow) == len(set(allow)) == len(set(want_allow))
    assert not [e for e in deny + allow if e.startswith(("~/**", "/**"))]
    # no entry comes from another rule (key files, production config)
    assert not [e for e in deny if re.search(r"pem|\.key|id_rsa|id_ed25519|prod", e)]
    assert sorted(sb) == ["allowUnsandboxedCommands", "autoAllowBashIfSandboxed", "enabled",
                          "failIfUnavailable", "filesystem"]


def test_case_34_the_makefile_target_writes_the_committed_file(tmp_path):
    import subprocess
    import sys
    out = subprocess.run(
        [sys.executable, "-m", "guardrails_core.isolation", str(PLUGIN / "policy.json")],
        capture_output=True, text=True, check=True,
        env={"PYTHONPATH": str(ROOT / "packages" / "guardrails-core" / "src"),
             "PYTHONDONTWRITEBYTECODE": "1"})
    assert out.stdout == BLOCK_FILE.read_text()
    assert out.stdout == json.dumps(isolation.sandbox_block(SHIPPED), indent=2) + "\n"


def test_case_35_added_policy_files_do_not_change_the_block(tmp_path, data, monkeypatch):
    extra = tmp_path / "extra.json"
    extra.write_text(json.dumps({"version": 1, "rules": [
        {"id": "deny-mine", "decision": "deny", "kind": "path", "match": ["*.secret"],
         "reason": "x"},
        {"id": "deny-env-files", "decision": "deny", "kind": "path", "match": ["*.vault"],
         "reason": "same id as a shipped rule"}]}))
    monkeypatch.setenv("GUARDRAILS_POLICY", str(extra))
    merged, errors = policy.load_policy(str(PLUGIN), str(data))
    assert not errors and any(r["id"] == "deny-mine" for r in merged["rules"])
    assert isolation.sandbox_block(merged) == isolation.sandbox_block(SHIPPED)


# ---- isolation off changes nothing (case 36)

def test_case_36_isolation_off_changes_nothing(proj, data):
    assert SHIPPED["isolation"] is False
    # no block in the project, and nothing is denied for it
    assert pre("Bash", {"command": "git status"}, proj, data)[0] == "allow"
    assert pre("PowerShell", {"command": "Get-Content x"}, proj, data)[0] == "allow"
    # the link check is off too (T-008 case 43)
    (proj / ".env").write_text("A=1\n")
    (proj / "n").symlink_to(".env")
    assert pre("Read", {"file_path": "n"}, proj, data)[0] == "allow"
    # Post leaves a shaped secret in shell output alone
    assert post("Bash", {"stdout": "k=" + SECRET, "stderr": ""}, data) == ""


def test_case_36_isolation_missing_from_the_policy_is_off(tmp_path, data):
    plugin = tmp_path / "plugin"
    shutil.copytree(PLUGIN, plugin)
    pol = json.loads((plugin / "policy.json").read_text())
    del pol["isolation"]
    (plugin / "policy.json").write_text(json.dumps(pol))
    raw = json.dumps({"session_id": "s", "tool_use_id": "t", "tool_name": "Bash",
                      "tool_input": {"command": "git status"}, "cwd": str(tmp_path)})
    assert hooks.run_pre(raw, str(plugin), str(data)) == ""


# ---- the tripwire (cases 38 to 44)

def test_case_38_no_block_in_the_project_denies_shell_calls(proj, data, iso_on):
    d, rule, why = pre("Bash", {"command": "git status"}, proj, data)
    assert (d, rule) == ("deny", "isolation-not-active")
    assert str(proj / ".claude" / "settings.local.json") in why
    assert str(PLUGIN / "isolation" / "settings.local.json") in why


def test_case_39_local_enabled_false_beats_shared_true(proj, data, iso_on):
    sb = isolation.sandbox_block(SHIPPED)
    put_settings(proj, "settings.json", sb)
    put_settings(proj, "settings.local.json", {"sandbox": {"enabled": False}})
    assert pre("Bash", {"command": "git status"}, proj, data)[:2] == (
        "deny", "isolation-not-active")
    # the other way round, local wins too: shared false, local true
    shared_off = copy.deepcopy(sb)
    shared_off["sandbox"]["enabled"] = False
    put_settings(proj, "settings.json", shared_off)
    put_settings(proj, "settings.local.json", {"sandbox": {"enabled": True}})
    assert pre("Bash", {"command": "git status"}, proj, data)[0] == "allow"


def _drop_first_deny(sb):
    sb["filesystem"]["denyRead"].pop(0)


def _extra_allow(sb):
    sb["filesystem"]["allowRead"].append("./**/.env")


def _excluded(sb):
    sb["excludedCommands"] = ["git *"]


def _unix_sockets(sb):
    sb["network"] = {"allowAllUnixSockets": True}


def _weak_nested(sb):
    sb["enableWeakerNestedSandbox"] = True


def _auto_allow(sb):
    sb["autoAllowBashIfSandboxed"] = True


def _unsandboxed(sb):
    sb["allowUnsandboxedCommands"] = True


def _fail_open(sb):
    sb["failIfUnavailable"] = False


@pytest.mark.parametrize("mutate", [
    _drop_first_deny, _extra_allow, _excluded, _unix_sockets, _weak_nested, _auto_allow,
    _unsandboxed, _fail_open])
def test_case_40_a_changed_block_denies(proj, data, iso_on, mutate):
    put_block(proj, mutate)
    assert pre("Bash", {"command": "git status"}, proj, data)[:2] == (
        "deny", "isolation-not-active")


@pytest.mark.parametrize("text", ["{not json", "[]", '{"sandbox": []}', ""])
def test_case_40_a_settings_file_that_is_not_valid_denies(proj, data, iso_on, text):
    put_settings(proj, text=text)
    assert pre("Bash", {"command": "git status"}, proj, data)[:2] == (
        "deny", "isolation-not-active")


def test_case_40_a_settings_file_that_cannot_be_read_denies(proj, data, iso_on):
    (proj / ".claude").mkdir()
    (proj / ".claude" / "settings.local.json").mkdir()  # a folder where a file should be
    assert pre("Bash", {"command": "git status"}, proj, data)[:2] == (
        "deny", "isolation-not-active")


def test_case_41_allowed_domains_are_allowed(proj, data, iso_on):
    put_block(proj, lambda sb: sb.update(network={"allowedDomains": ["github.com"]}))
    assert pre("Bash", {"command": "git status"}, proj, data)[0] == "allow"


def test_case_41_the_block_in_the_shared_file_counts_too(proj, data, iso_on):
    put_settings(proj, "settings.json", isolation.sandbox_block(SHIPPED))
    assert pre("Bash", {"command": "git status"}, proj, data)[0] == "allow"


def test_case_42a_a_push_still_asks(proj, data, iso_on):
    put_block(proj)
    assert pre("Bash", {"command": "git push origin main"}, proj, data)[:2] == (
        "ask", "ask-git-push")


def test_case_42b_a_rule_deny_stays_a_rule_deny(proj, data, iso_on):
    put_block(proj)
    assert pre("Bash", {"command": "cat .env"}, proj, data)[:2] == ("deny", "deny-env-files")
    # and without the block the rule deny is still the rule's, not the tripwire's
    (proj / ".claude" / "settings.local.json").unlink()
    assert pre("Bash", {"command": "cat .env"}, proj, data)[:2] == ("deny", "deny-env-files")


def test_case_42c_the_tripwire_checks_only_the_shell_tools(proj, data, iso_on):
    assert pre("Read", {"file_path": "README.md"}, proj, data)[0] == "allow"
    assert pre("Grep", {"pattern": "x"}, proj, data)[0] == "allow"


@pytest.mark.parametrize("tool,tin", [
    ("PowerShell", {"command": "Get-Content x"}), ("Monitor", {"command": "tail -f x"})])
def test_case_42d_powershell_and_monitor_are_checked_too(proj, data, iso_on, tool, tin):
    assert pre(tool, tin, proj, data)[:2] == ("deny", "isolation-not-active")
    put_block(proj)
    assert pre(tool, tin, proj, data)[0] == "allow"


def test_case_42_a_rule_ask_does_not_hide_a_missing_block(proj, data, iso_on):
    assert pre("Bash", {"command": "git push origin main"}, proj, data)[:2] == (
        "deny", "isolation-not-active")


def test_case_43_a_file_tool_on_a_link_to_a_listed_file_is_denied(proj, data, iso_on):
    (proj / ".env").write_text("API=1\n")
    (proj / "n").symlink_to(".env")
    for tool, tin in (("Read", {"file_path": "n"}),
                      ("Read", {"file_path": str(proj / "n")}),
                      ("Edit", {"file_path": "n", "old_string": "a", "new_string": "b"}),
                      ("Write", {"file_path": "n", "content": "x"})):
        assert pre(tool, tin, proj, data)[:2] == ("deny", "deny-env-files"), tool


def test_case_43_a_link_to_a_listed_folder_is_denied(proj, data, iso_on, tmp_path):
    ssh = tmp_path / "home" / ".ssh"
    ssh.mkdir()
    (ssh / "id_x").write_text("k")
    (proj / "s").symlink_to(ssh)
    assert pre("Read", {"file_path": "s/id_x"}, proj, data)[:2] == (
        "deny", "deny-credential-dirs")


def test_case_43_a_plain_file_and_a_plain_link_are_allowed(proj, data, iso_on, tmp_path):
    (proj / "README.md").write_text("x")
    (proj / "ok").symlink_to("README.md")
    assert pre("Read", {"file_path": "README.md"}, proj, data)[0] == "allow"
    assert pre("Read", {"file_path": "ok"}, proj, data)[0] == "allow"
    # a project that sits under a folder named production is not denied for its plain files
    prod = tmp_path / "production" / "app"
    prod.mkdir(parents=True)
    (prod / "a.txt").write_text("x")
    assert pre("Read", {"file_path": "a.txt"}, prod, data)[0] == "allow"


def test_case_43_off_the_same_read_is_allowed(proj, data):
    (proj / ".env").write_text("API=1\n")
    (proj / "n").symlink_to(".env")
    assert pre("Read", {"file_path": "n"}, proj, data)[0] == "allow"


def test_case_44_without_claude_project_dir_only_the_cwd_is_read(proj, data, iso_on):
    put_block(proj)
    sub = proj / "sub"
    sub.mkdir()
    assert pre("Bash", {"command": "git status"}, sub, data)[:2] == (
        "deny", "isolation-not-active")
    assert pre("Bash", {"command": "git status"}, proj, data)[0] == "allow"


def test_case_44_claude_project_dir_wins_over_cwd(proj, data, iso_on, monkeypatch):
    put_block(proj)
    sub = proj / "sub"
    sub.mkdir()
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(proj))
    assert pre("Bash", {"command": "git status"}, sub, data)[0] == "allow"


# ---- the forms no shell isolation can block (case 31)

@pytest.mark.parametrize("uri", ["file:///home/u/%2Eenv", "file:///home/u/.ssh?x=1"])
def test_case_31_mcp_uris_are_allowed_a_stated_limit(proj, data, iso_on, uri):
    put_block(proj)
    assert pre("mcp__x__open", {"uri": uri}, proj, data)[0] == "allow"


# ---- the switch in policy files (case 46)

def _load(tmp_path, data, monkeypatch, env_text=None, data_text=None):
    if env_text is not None:
        f = tmp_path / "env-policy.json"
        f.write_text(env_text)
        monkeypatch.setenv("GUARDRAILS_POLICY", str(f))
    if data_text is not None:
        data.mkdir(exist_ok=True)
        (data / "policy.json").write_text(data_text)
    return policy.load_policy(str(PLUGIN), str(data))


ON, OFF = '{"version": 1, "isolation": true}', '{"version": 1, "isolation": false}'


def test_case_46_the_readme_file_word_for_word_turns_isolation_on(
        tmp_path, data, monkeypatch):
    pol, errors = _load(tmp_path, data, monkeypatch, env_text=ON)
    assert errors == [] and pol["isolation"] is True
    # the rules are still the shipped rules
    assert pol["rules"] == SHIPPED["rules"]


@pytest.mark.parametrize("env_text,data_text", [(OFF, ON), (ON, OFF), (None, ON), (ON, None)])
def test_case_46_once_any_file_says_true_it_stays_on(
        tmp_path, data, monkeypatch, env_text, data_text):
    pol, errors = _load(tmp_path, data, monkeypatch, env_text, data_text)
    assert errors == [] and pol["isolation"] is True


@pytest.mark.parametrize("env_text", [OFF, None])
def test_case_46_false_files_leave_it_off(tmp_path, data, monkeypatch, env_text):
    pol, errors = _load(tmp_path, data, monkeypatch, env_text)
    assert errors == [] and pol["isolation"] is False


@pytest.mark.parametrize("text", [
    '{"version": 1, "isolation": "yes"}', '{"version": 1, "isolation": 1}',
    '{"version": 1, "rules": []}', '{"version": 1}', '{"isolation": true}'])
def test_case_46_a_wrong_file_is_left_out_with_a_message(tmp_path, data, monkeypatch, text):
    pol, errors = _load(tmp_path, data, monkeypatch, env_text=text)
    assert len(errors) == 1 and pol["isolation"] is False


def test_case_46_a_shipped_policy_with_no_rules_is_an_error(tmp_path, data):
    plugin = tmp_path / "plugin"
    shutil.copytree(PLUGIN, plugin)
    pol = json.loads((plugin / "policy.json").read_text())
    del pol["rules"]
    (plugin / "policy.json").write_text(json.dumps(pol))
    with pytest.raises(policy.PolicyError):
        policy.load_policy(str(plugin), str(data))
    pol["rules"] = []
    (plugin / "policy.json").write_text(json.dumps(pol))
    with pytest.raises(policy.PolicyError):
        policy.load_policy(str(plugin), str(data))


# ---- Post redacts shaped secrets in shell output (cases 47, 48)

@pytest.mark.parametrize("tool", ["Bash", "PowerShell", "Monitor"])
def test_case_47_shaped_secrets_in_shell_output_are_replaced(data, iso_on, tool):
    resp = {"stdout": "key " + SECRET, "stderr": "also " + SECRET, "interrupted": False,
            "isImage": False}
    out = post(tool, resp, data)
    h = json.loads(out)
    assert list(h) == ["hookSpecificOutput"]
    assert h["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
    assert h["hookSpecificOutput"]["updatedToolOutput"] == {
        "stdout": "key [REDACTED:anthropic-key]", "stderr": "also [REDACTED:anthropic-key]",
        "interrupted": False, "isImage": False}
    # the audit line was still written
    assert list((data / "audit").glob("*.jsonl"))


def test_case_47_other_tools_other_shapes_and_clean_output_print_nothing(data, iso_on):
    assert post("Read", {"stdout": "key " + SECRET}, data) == ""
    assert post("Bash", "key " + SECRET, data) == ""
    assert post("Bash", ["key " + SECRET], data) == ""
    assert post("Bash", {"stdout": "all fine", "stderr": ""}, data) == ""
    assert post("Bash", {"content": "key " + SECRET}, data) == ""  # no stdout/stderr, no new key
    assert post("Bash", {"stdout": 5, "stderr": None}, data) == ""


def test_case_47_a_failed_call_has_no_response_to_change(data, iso_on):
    raw = json.dumps({"session_id": "s", "tool_use_id": "t", "tool_name": "Bash",
                      "hook_event_name": "PostToolUseFailure", "tool_input": {"command": "x"},
                      "error": "Exit code 1 " + SECRET})
    assert hooks.run_post(raw, str(PLUGIN), str(data)) == ""


def test_case_47_redact_fields_never_adds_a_key_and_returns_a_copy():
    src = {"stdout": SECRET}
    out = redact.redact_fields(src, ("stdout", "stderr"))
    assert out == {"stdout": "[REDACTED:anthropic-key]"} and src == {"stdout": SECRET}
    assert redact.redact_fields("text " + SECRET, ("stdout",)) == "text " + SECRET


def test_case_48_an_unwritable_log_still_gives_the_redacted_output(tmp_path, iso_on):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    for bad in (blocker / "data", None):
        out = hooks.run_post(json.dumps({
            "session_id": "s", "tool_use_id": "t", "hook_event_name": "PostToolUse",
            "tool_name": "Bash", "tool_input": {"command": "x"},
            "tool_response": {"stdout": "k=" + SECRET, "stderr": ""}}), str(PLUGIN),
            str(bad) if bad else None)
        h = json.loads(out)
        assert h["hookSpecificOutput"]["updatedToolOutput"]["stdout"] == (
            "k=[REDACTED:anthropic-key]")
        assert h["systemMessage"].startswith("guardrails audit failed: ")


def test_case_48_an_unwritable_log_with_nothing_to_redact_still_raises(tmp_path, iso_on):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(OSError):
        post("Bash", {"stdout": "fine", "stderr": ""}, blocker / "data")
