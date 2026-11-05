"""The rule gaps and false positives that docs/THREAT_MODEL.md names ("Gaps in the rules",
"Known false positives"), run through the shipped policy.

These record TODAY's behaviour, so the document's claims can be reproduced from the repo.
When a fix (T-008 is built) changes a case, change the case here and the text in
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


# T-006: an option word between the program and its subcommand no longer hides the command.
@pytest.mark.parametrize("cmd,want", [
    (G + " -C repo push --force origin main", ("deny", "deny-force-push")),
    (G + " -c key=value push -f", ("deny", "deny-force-push")),
    (G + " -C repo push origin main", ("ask", "ask-git-push")),
    (G + " -C repo reset --hard", ("ask", "ask-git-reset-hard")),
    (G + " reset HEAD~1 --hard", ("ask", "ask-git-reset-hard")),
    ("kubectl -n prod delete pod x", ("ask", "ask-kubectl-change")),
    ("kubectl --context prod apply -f x", ("ask", "ask-kubectl-change")),
    ("terraform -chdir=infra apply", ("ask", "ask-terraform-apply")),
    ("npm --prefix x publish", ("ask", "ask-publish")),
    ("cargo +nightly publish", ("ask", "ask-publish")),
    ("uv --directory x publish", ("ask", "ask-publish")),
    ("twine --verbose upload d", ("ask", "ask-publish")),
    ("yarn --cwd x publish", ("ask", "ask-publish")),
])
def test_option_before_subcommand_is_seen(cmd, want):
    assert bash(cmd) == want


# T-006: these commands had no rule; they ask now. Cases that still have none are below.
@pytest.mark.parametrize("cmd,want", [
    ("gh pr merge 1", "ask-gh-write"), ("gh release create v1", "ask-gh-write"),
    ("docker push img", "ask-docker-push"), ("helm upgrade r c", "ask-helm-change"),
    (G + " clean -fdx", "ask-git-clean"), ("find . -delete", "ask-find-delete"),
    ("aws s3 rm s3://b/k", "ask-aws-change"),
    ("python3 -c \"import shutil;shutil.rmtree('x')\"", "ask-python-delete")])
def test_commands_that_had_no_rule_ask(cmd, want):
    assert bash(cmd) == ("ask", want)


def test_short_force_flag_glued_to_a_semicolon_is_denied():
    # T-006: the flag may end at ; & | ) as well as at white space.
    assert bash(G + " push -f;echo") == ("deny", "deny-force-push")
    assert bash(G + " push --force;echo") == ("deny", "deny-force-push")
    assert bash("cd r && " + G + " push --force") == ("deny", "deny-force-push")


@pytest.mark.parametrize("cmd", [
    G + ' push "--force" origin main',
    G + " push '-f'",
    G + " push origin main \\\n  --force-with-lease",
    G + " push -f>/dev/null",
    G + " push origin main 2>&1 --force",
])
def test_other_force_spellings_only_ask(cmd):
    assert bash(cmd) == ("ask", "ask-git-push")


def test_quoted_recursive_flag_matches_no_rule():
    assert bash('rm "-rf" build') == ("allow", "default-allow")


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
    assert decide("Read", {"file_path": "~/.ssh"})[0] == "deny"  # T-008
    assert decide("Grep", {"pattern": "API_KEY", "path": "."})[0] == "allow"
    assert bash("cat ~/.netrc")[0] == "deny"  # T-008
    assert bash("printenv")[0] == "allow"


@pytest.mark.parametrize("cmd", [
    "grep -r API_KEY .", "cat config/*", "env", "aws s3 ls", "rm -f x",
    "python3 script.py"])  # T-006: gh, find -delete moved to asks
def test_the_rest_of_the_secret_and_no_rule_gaps_are_allowed(cmd):
    assert bash(cmd) == ("allow", "default-allow")


# T-006: the limits THREAT_MODEL states once (forms the regexes do not read).
@pytest.mark.parametrize("cmd", [
    '"rm" -r x', "vercel\n--prod", "vercel deploy\n--prod", G + ' "push" -f',
    G + " -a -b -c -d -e -f -g -h -i push -f",  # nine option words, the limit is eight
    "kubectl patch deploy x", "gh api -X DELETE /x", G + " branch -D x",
    "docker buildx build --push .", "aws s3 rb s3://b",
    G + ' -C "my repo" push --force', G + " -C my\\ repo push --force"])  # T-006 round 6
def test_t006_limits_are_allowed(cmd):
    assert bash(cmd) == ("allow", "default-allow")


@pytest.mark.parametrize("cmd", [
    G + " push '--force'", G + ' push "-f"', 'bash -c "' + G + ' push -f"',
    "F=--force; " + G + " push $F", "alias gp='" + G + " push -f'; gp",
    G + " push -f>/dev/null", G + " --no-pager log --grep push"])
def test_t006_hidden_force_spellings_ask_and_a_read_with_push_in_it_asks_too(cmd):
    assert bash(cmd)[0] == "ask"


def test_grep_glob_field_is_checked_and_unlisted_mcp_tools_are_allowed():
    assert decide("Grep", {"pattern": "K", "path": ".", "glob": ".env*"}) == (
        "deny", "deny-env-files")
    for tool in ("mcp__x__push_files", "mcp__x__merge_pull_request", "mcp__x__create_issue"):
        assert decide(tool, {}) == ("allow", "default-allow")


@pytest.mark.parametrize("tool", ["PowerShell", "Shell", "bash"])
def test_shell_through_another_tool_name_is_matched_whole(tool):
    # T-008: the whole command string is matched against the path rules; no command rule.
    assert decide(tool, {"command": "cat .env"})[0] == "deny"
    assert decide(tool, {"command": "cat .env.local"})[0] == "allow"
    assert decide(tool, {"command": G + " push --force"})[0] == "allow"


def test_paths_are_cleaned_up_before_matching():
    assert decide("Read", {"file_path": "~/.aws/credentials"})[0] == "deny"
    assert decide("Read", {"file_path": "~/.aws/./credentials"})[0] == "deny"
    assert decide("Read", {"file_path": "~/.kube//config"})[0] == "deny"
    assert bash("cat ~/.aws/./credentials")[0] == "deny"


def test_mcp_rule_reads_the_tool_part_of_the_name_not_the_server_part():
    # T-006: the rule looks at the part after the server name; a server name no longer counts.
    for tool in ("mcp__my_pay__list", "mcp__my_sender__list", "mcp__sendgrid__list",
                 "mcp__payments__refund", "mcp__postmark__email"):
        assert decide(tool, {}) == ("allow", "default-allow")


def test_mcp_name_rule():
    # T-006: write words count at the start of a word of the tool name, in _ - and camelCase.
    assert decide("mcp__gmail__send_email", {})[0] == "ask"
    for tool in ("mcp__x__bulkDelete", "mcp__x__email-send", "mcp__x__createPost",
                 "mcp__x__make-payment", "mcp__x__wire-transfer"):
        assert decide(tool, {}) == ("ask", "ask-mcp-write")
    # reading words in front excuse the noun uses (posts, payments); send and delete never do
    for tool in ("mcp__blog__get_post", "mcp__x__get_posts", "mcp__x__list_payments"):
        assert decide(tool, {})[0] == "allow"
    assert decide("mcp__x__list_deleted", {})[0] == "ask"
    # T-006 round 6: a reading word followed by a different word (find_and_pay) does not excuse
    for tool in ("mcp__x__find_and_pay", "mcp__x__getAndPost", "mcp__x__get_user_payments",
                 "mcp__x__postal_lookup", "mcp__x__payment_status"):
        assert decide(tool, {}) == ("ask", "ask-mcp-write")
    # a write word glued inside a longer word, or all lower case with no break, is not seen
    for tool in ("mcp__x__resend", "mcp__x__createpost", "mcp__x__refund"):
        assert decide(tool, {})[0] == "allow"


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
def test_broken_added_policy_keeps_denies_and_asks_on_unmatched_calls(
        tmp_path, monkeypatch, content):
    """Code: a broken added file is left out; the shipped rules still apply; unmatched calls ask."""
    bad = tmp_path / "p.json"
    bad.write_text(content)
    monkeypatch.setenv("GUARDRAILS_POLICY", str(bad))
    root = ROOT / "packages" / "guardrails-plugin"
    pol, errors = policy.load_policy(str(root), str(tmp_path))
    assert len(errors) == 1 and str(bad) in errors[0]
    assert pol["rules"] == POLICY["rules"]

    def run(cmd):
        raw = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
        out = json.loads(hooks.run_pre(raw, str(root), str(tmp_path)))["hookSpecificOutput"]
        return out["permissionDecision"], out["permissionDecisionReason"]

    assert run("cat .env")[0] == "deny"
    assert run("ls")[0] == "ask" and run("ls")[1].startswith("[guardrails-policy-error]")
    # a missing path or a folder is an error too, not skipped
    for bad_path in (tmp_path, tmp_path / "nope"):
        monkeypatch.setenv("GUARDRAILS_POLICY", str(bad_path))
        assert len(policy.load_policy(str(root), None)[1]) == 1


@pytest.mark.parametrize("name", ["README.md", "docs/THREAT_MODEL.md", "docs/ARCHITECTURE.md"])
def test_every_doc_that_describes_the_env_policy_lookup_says_a_bad_file_makes_calls_ask(name):
    text = flat(name)
    assert re.search(r"a missing or broken added policy file is left out, the shipped rules "
                     r"still apply, and calls no rule matches ask", text, re.I), name
    assert "skipped without a message" not in text
    assert "unreadable file is skipped" not in text
    assert "not a readable file it is skipped" not in text


@pytest.mark.parametrize("rule", [
    {"id": "x", "kind": "command", "decision": "deny", "match": ["push"], "except": ["push"]},
    {"id": "x", "kind": "tool", "decision": "ask", "match": ["^Bash$"], "except": ["^Bash$"]},
])
def test_except_is_read_only_by_path_rules(rule):
    """Code: rules.rule_hit ignores `except` for command and tool rules. validate() accepts it."""
    r = dict(rule, reason="r")
    plugin = ROOT / "packages" / "guardrails-plugin"
    schema = json.loads((plugin / "policy.schema.json").read_text())
    pol = policy.validate({"version": 1, "rules": [r]}, schema)
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
