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
