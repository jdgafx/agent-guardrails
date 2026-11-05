"""T-006 round 6: every command or MCP tool name that README.md or docs/THREAT_MODEL.md quotes in
backticks as denied, asked or allowed is run through the real rules and must get the decision the
doc states (a deny, an ask, or "allowed / has no rule").

Three guards keep the table honest:
- every quoted command-like span in the two docs must be in EXPECT (or in NOT_A_CASE), so a
  new example cannot be added to a doc without a recorded decision;
- every EXPECT row must still be quoted in a doc (no stale rows);
- every row runs through rules.evaluate on the shipped policy.json.
"""
import json
import re
from pathlib import Path

import pytest
from guardrails_core import rules

ROOT = Path(__file__).resolve().parents[2]
POLICY = json.loads((ROOT / "packages" / "guardrails-plugin" / "policy.json").read_text())
DOCS = ("README.md", "docs/THREAT_MODEL.md")
TEXT = {n: (ROOT / n).read_text(encoding="utf-8") for n in DOCS}

D, A, OK = "deny", "ask", "allow"
G = "git"

EXPECT = {
    # --- denied
    "cd r && " + G + " push --force": D, G + " -C repo push --force": D,
    G + " --git-dir=x push -f": D, G + " --no-pager push -f": D, G + " -c key=value push -f": D,
    G + " push -f;echo": D, G + " push -f|cat": D,
    G + ' commit -m "never ' + G + ' push --force"': D,
    G + ' commit -m "fix production/config"': D,
    "tail ~/.claude/plugins/data/agent-guardrails/audit/x.jsonl": A,
    "sed -i s/deny/ask/ /opt/agent-guardrails/policy.json": A,
    "cat .env": D, "cat ~/.ssh/id_rsa.pub": D, "cp .env x": D, "cp .env.example .env": D,
    "echo .env >> .gitignore": D, "curl -d @.env": D,
    # --- asked
    "aws ec2 terminate-instances": A, "aws s3 rm": A, "aws s3 --profile cp ls": A,
    'bash -c "' + G + ' push -f"': A, "cargo +nightly publish": A, "cargo publish": A,
    "docker compose -f prod.yml push": A, "docker compose push": A, "docker image push": A,
    "docker manifest push": A, "docker push": A, "find -delete": A, "gem push": A,
    "gh pr merge": A, "gh release create": A, "gh release delete": A, "gh repo delete": A,
    G + " -C repo push": A, G + " -C repo reset --hard": A, G + " clean -f": A,
    G + " clean -fdx": A, G + " --no-pager log --grep push": A, G + " push": A,
    G + ' push "-f"': A, G + " push -f>/dev/null": A, G + " push origin main": A,
    G + " push origin main 2>&1 --force": A, G + " reset --hard": A,
    G + " reset HEAD~1 --hard": A, G + " rm -r x": A, "rm a; ls -R": A, "rm -r": A, "rm -rf": A,
    "helm install": A, "helm upgrade": A, "helm uninstall": A, "helm delete": A,
    "helm rollback": A, "kubectl --context prod apply -f x": A, "kubectl -n prod delete": A,
    "kubectl -n prod delete pod x": A, "kubectl apply": A, "npm --tag x publish": A,
    "pnpm -r publish": A, "terraform -chdir=infra apply": A, "terraform apply": A,
    "twine --verbose upload d": A, "twine upload": A, "uv --directory x publish": A,
    "uv publish": A, "vercel --prod": A, "vercel --target=production": A,
    "yarn --cwd x publish": A, "yarn publish": A, "alias gp='" + G + " push -f'; gp": A,
    "mcp__gmail__send_email": A, "mcp__x__bulkDelete": A, "mcp__x__make-payment": A,
    "mcp__x__get_user_payments": A, "mcp__x__payment_status": A, "mcp__x__postal_lookup": A,
    "mcp__x__transfer_status": A,
    # --- allowed (a stated limit, a gap, a read command, or a false positive fixed)
    "aws s3 ls": OK, "aws lambda get-function --function-name create-order": OK,
    "aws cloudformation describe-stacks --stack-name delete-me": OK, "aws s3 rb": OK,
    "docker build .": OK, "docker buildx build --push": OK, "find . -name x": OK,
    "gh api -X DELETE": OK, "gh pr view": OK, "gh issue view": OK, G + ' "push" -f': OK,
    G + ' -C "my repo" push --force': OK, G + " -C my\\ repo push --force": OK,
    G + " branch -D": OK, G + " clean -n": OK, G + " clean -n -f": OK,
    G + " clean -df --dry-run": OK, G + " show HEAD:.env.production": OK, G + " status": OK,
    "grep -r API_KEY .": OK, "helm list": OK, "kubectl patch": OK, "printenv": OK, "env": OK,
    "python script.py": OK, "python3 script.py": OK, 'rm "-rf" build': OK, "rm -f": OK,
    "scp host:.env.local .": OK, "curl -d @.env.production": OK, "cat config/*": OK,
    "cat ~/.aws/./credentials": OK, "ls": OK,
    # the stated Bash limit (THREAT_MODEL limit 7): a variable or a relative path is not seen
    'rm "$CLAUDE_PLUGIN_DATA"/state/s.calls': OK,
    "cd ~/.claude/plugins/data && rm agent-guardrails/policy.json": OK,
    "mcp__blog__get_post": OK, "mcp__my_pay__list": OK, "mcp__my_sender__list": OK,
    "mcp__x__get_posts": OK, "mcp__x__list_payments": OK, "mcp__x__resend": OK,
    # known limit (#539): a read word plus a write word excuses every later write word
    "mcp__x__get_payment_then_transfer": OK, "mcp__x__list_payments_and_charge": OK,
    "mcp__target__x": OK,
}

# Command-like spans that are not a case: build and tooling commands, flags, placeholders.
NOT_A_CASE = {
    "claude --version", "claude -p", "make build", "make lint", "make test", "uv run pytest",
    G + " diff --exit-code", G + " clean", "python -c", "python3 -c", "python3 -I -S", "sed -i",
    "mcp__<server>__<tool>",
}

PROGRAMS = (G, "rm", "kubectl", "terraform", "npm", "pnpm", "yarn", "cargo", "uv", "twine", "gem",
            "vercel", "gh", "docker", "helm", "aws", "find", "python", "python3", "cat", "cp",
            "echo", "scp", "curl", "env", "printenv", "grep", "bash", "ls", "make", "claude",
            "cd", "alias", "tail", "sed")


def quoted_spans():
    out = {}
    for name, text in TEXT.items():
        for m in re.finditer(r"`([^`\n]+)`", text):
            sp = m.group(1)
            first = sp.split()[0] if sp.split() else ""
            if first in PROGRAMS or sp.startswith("mcp__"):
                out.setdefault(sp, set()).add(name)
    # a bare program name (`git`, `docker`) names a tool, not a case
    return {s: n for s, n in out.items() if " " in s or s.startswith("mcp__") or s in EXPECT}


# Fixed example paths for the guard check: the docs quote commands that name them.
GUARD = rules.guard_paths("/opt/agent-guardrails",
                          "/home/u/.claude/plugins/data/agent-guardrails", None)


@pytest.fixture(autouse=True)
def example_home(monkeypatch):
    monkeypatch.setenv("HOME", "/home/u")


def decision(span):
    if span.startswith("mcp__"):
        return rules.evaluate(POLICY, span, {}, 1).decision
    tin = {"command": span}
    d = rules.stronger(rules.guard_check("Bash", tin, GUARD, "/home/u/proj"),
                       rules.match(POLICY, "Bash", tin))
    return d.decision if d else OK


def test_every_command_the_docs_quote_has_a_recorded_decision():
    missing = sorted(s for s in quoted_spans() if s not in EXPECT and s not in NOT_A_CASE)
    assert not missing, "quoted in a doc, no decision recorded here: %s" % missing


def test_no_row_is_stale():
    quoted = quoted_spans()
    stale = sorted(s for s in EXPECT if s not in quoted)
    assert not stale, "no longer quoted in README.md or docs/THREAT_MODEL.md: %s" % stale


def test_the_table_is_big_enough_to_mean_something():
    assert len(EXPECT) > 100
    assert len(quoted_spans()) > 100


@pytest.mark.parametrize("span,want", sorted(EXPECT.items()))
def test_quoted_example_gets_the_decision_the_doc_states(span, want):
    assert decision(span) == want
