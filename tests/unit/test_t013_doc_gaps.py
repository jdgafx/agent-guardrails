"""The rule gaps and false positives that docs/THREAT_MODEL.md names ("Gaps in the rules",
"Known false positives"), run through the shipped policy.

These record TODAY's behaviour, so the document's claims can be reproduced from the repo.
When a held fix (T-006, T-007, T-008) changes a case, change the case here and the text in
docs/THREAT_MODEL.md together; this file exists to stop a green run with a stale document.
"""
import json
from pathlib import Path

import pytest
from guardrails_core import rules

ROOT = Path(__file__).resolve().parents[2]
POLICY = json.loads((ROOT / "packages" / "guardrails-plugin" / "policy.json").read_text())
G = "git"


def decide(tool, tin):
    d = rules.evaluate(POLICY, tool, tin, 1)
    return d.decision, d.rule


def bash(cmd):
    return decide("Bash", {"command": cmd})


# A flag between the program and its subcommand: no ask, no deny, for every rule of this shape.
@pytest.mark.parametrize("cmd", [
    G + " -C repo push --force origin main",
    G + " -c key=value push -f",
    G + " -C repo push origin main",
    G + " -C repo reset --hard",
    G + " reset HEAD~1 --hard",
    "kubectl -n prod delete pod x",
    "kubectl --context prod apply -f x",
    "terraform -chdir=infra apply",
    "npm --prefix x publish",
    "cargo +nightly publish",
    "uv --directory x publish",
    "twine --verbose upload d",
    "yarn --cwd x publish",
])
def test_option_before_subcommand_gets_no_ask(cmd):
    assert bash(cmd) == ("allow", "default-allow")


@pytest.mark.parametrize(
    "cmd", ["gh pr merge 1", "docker push img", "helm upgrade r c", G + " clean -fdx"])
def test_commands_with_no_rule_are_allowed(cmd):
    assert bash(cmd) == ("allow", "default-allow")


def test_short_force_flag_glued_to_a_semicolon_only_asks():
    assert bash(G + " push -f;echo") == ("ask", "ask-git-push")
    assert bash(G + " push --force;echo") == ("deny", "deny-force-push")
    assert bash("cd r && " + G + " push --force") == ("deny", "deny-force-push")


def test_force_push_text_inside_quotes_is_denied():
    assert bash(G + ' commit -m "never ' + G + ' push --force"') == ("deny", "deny-force-push")


@pytest.mark.parametrize("cmd", ["aws s3 rm --recursive s3://b", G + " rm -r x", "rm a; ls -R"])
def test_recursive_delete_ask_has_no_command_boundary(cmd):
    assert bash(cmd) == ("ask", "ask-rm-recursive")


def test_env_name_glued_to_other_characters():
    assert bash("curl -d @.env x") == ("deny", "deny-env-files")
    assert bash("curl -d @.env.production x")[0] == "allow"
    assert bash("scp host:.env.local .")[0] == "allow"
    assert bash(G + " show HEAD:.env.production")[0] == "allow"


def test_secret_gaps_by_name():
    assert decide("Read", {"file_path": "~/.ssh"})[0] == "allow"
    assert decide("Grep", {"pattern": "API_KEY", "path": "."})[0] == "allow"
    assert bash("cat ~/.netrc")[0] == "allow"
    assert bash("printenv")[0] == "allow"


@pytest.mark.parametrize("tool", ["PowerShell", "Shell", "bash"])
def test_shell_through_another_tool_name_gets_no_rule(tool):
    assert decide(tool, {"command": "cat .env"})[0] == "allow"
    assert decide(tool, {"command": G + " push --force"})[0] == "allow"


def test_mcp_name_rule():
    assert decide("mcp__gmail__send_email", {})[0] == "ask"
    assert decide("mcp__blog__get_post", {})[0] == "ask"
    assert decide("mcp__x__resend", {})[0] == "allow"


# ---- The docs must agree with the code, not only with each other (T-013 round 2) -------------
# Each test runs the real code first, then reads the docs. Wording is checked only for claims the
# code result above it settles.
import re  # noqa: E402

from guardrails_core import hooks, policy  # noqa: E402

DOCS = {n: (ROOT / n).read_text(encoding="utf-8") for n in
        ("README.md", "GLOSSARY.md", "docs/THREAT_MODEL.md", "docs/ARCHITECTURE.md")}


def flat(name):
    return re.sub(r"\s+", " ", DOCS[name])


@pytest.mark.parametrize("content", ["{", ""])
def test_policy_file_that_exists_but_cannot_load_is_picked_and_every_call_asks(
        tmp_path, monkeypatch, content):
    """Code: find_policy_path uses isfile, so a bad file is picked, not skipped; load fails; ask."""
    bad = tmp_path / "p.json"
    bad.write_text(content)
    monkeypatch.setenv("GUARDRAILS_POLICY", str(bad))
    root = ROOT / "packages" / "guardrails-plugin"
    assert policy.find_policy_path(str(root), str(tmp_path)) == str(bad)
    raw = json.dumps({"tool_name": "Bash", "tool_input": {"command": "cat .env"}})
    out = json.loads(hooks.run_pre(raw, str(root), str(tmp_path)))
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    # a folder or a missing path IS skipped, with no message
    for skipped in (tmp_path, tmp_path / "nope"):
        monkeypatch.setenv("GUARDRAILS_POLICY", str(skipped))
        assert policy.find_policy_path(str(root), None) == str(root / "policy.json")


@pytest.mark.parametrize("name", ["README.md", "docs/THREAT_MODEL.md", "docs/ARCHITECTURE.md"])
def test_every_doc_that_describes_the_env_policy_lookup_says_a_bad_file_makes_calls_ask(name):
    text = flat(name)
    hits = [m.start() for m in re.finditer(r"skipped without a message", text)]
    assert hits, name
    for h in hits:
        window = text[h:h + 400]
        assert re.search(r"cannot be read.{0,250}(every call (gets )?`?ask|asks)",
                         window), (name, window)
    assert "unreadable file is skipped" not in text
    assert "not a readable file it is skipped" not in text


@pytest.mark.parametrize("rule", [
    {"id": "x", "kind": "command", "decision": "deny", "match": ["push"], "except": ["push"]},
    {"id": "x", "kind": "tool", "decision": "ask", "match": ["^Bash$"], "except": ["^Bash$"]},
])
def test_except_is_read_only_by_path_rules(rule):
    """Code: rules.rule_hit ignores `except` for command and tool rules. validate() accepts it."""
    r = dict(rule, reason="r")
    pol = policy.validate({"version": 1, "rules": [r]})
    d = rules.evaluate(pol, "Bash", {"command": G + " push"}, 1)
    assert d.decision == r["decision"]


def test_docs_say_except_belongs_to_path_rules_only():
    assert "on path rules only" in flat("GLOSSARY.md")
    readme = flat("README.md")
    assert "for `path` rules only" in readme
    assert "On a `command` or `tool` rule `except` is ignored" in readme
    arch = flat("docs/ARCHITECTURE.md")
    assert "an optional `except` list that only `path` rules read" in arch
    assert "that `except` is on a `path` rule" in arch
    # README must not offer `except` as the way to relax the MCP (tool) rule
    over = readme.split("**Over-matching.**")[1].split("**Needs Claude Code")[0]
    assert "`except` does not work on it" in over


def test_docs_do_not_overclaim_or_carry_process_notes():
    assert "allowed with no prompt" not in " ".join(flat(n) for n in DOCS)
    assert "T-013" not in flat("docs/THREAT_MODEL.md")
    assert "T-013" not in flat("README.md")
    assert "For other tool names no fix is written down" in flat("README.md")
