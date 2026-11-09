"""T-006 round 6: the commands and MCP tool names the docs use as examples, each run through the
real rules on the shipped policy.json: a deny, an ask, or "allowed / has no rule". T-018: a shell
command that a deny rule matches is an ask. The table is not tied to the wording of the docs.
"""
import json
from pathlib import Path

import pytest
from guardrails_core import rules

ROOT = Path(__file__).resolve().parents[2]
POLICY = json.loads((ROOT / "packages" / "guardrails-plugin" / "policy.json").read_text())

D, A, OK = "deny", "ask", "allow"
G = "git"

EXPECT = {
    # --- asked under a deny-* rule: a shell command that a deny rule matches (T-018)
    "cd r && " + G + " push --force": A, G + " -C repo push --force": A,
    G + " --git-dir=x push -f": A, G + " --no-pager push -f": A, G + " -c key=value push -f": A,
    G + " push -f;echo": A, G + " push -f|cat": A,
    G + ' commit -m "never ' + G + ' push --force"': A,
    G + ' commit -m "fix production/config"': A,
    "tail ~/.claude/plugins/data/agent-guardrails/audit/x.jsonl": A,
    "sed -i s/deny/ask/ /opt/agent-guardrails/policy.json": A,
    "cat .env": A, "cat ~/.ssh/id_rsa.pub": A, "cp .env x": A, "cp .env.example .env": A,
    # T-008: listed credential files and folders, in any folder
    "cat .npmrc": A, "cat .pypirc": A, "cat ~/.aws/config": A, "ls ~/.aws": A,
    "echo .env >> .gitignore": A, "curl -d @.env": A,
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
    "ls": OK,
    # T-008: the stated limits of the secret rules (a name that is not spelled, a parent folder)
    "cat .n*rc": OK, "cd ~/.config/gh && cat hosts.yml": OK,
    "grep -r AWS_SECRET ~": OK,
    # T-014: the isolation table. The plugin column; the "isolation on" column is backed by
    # tests/live/t014_probe.py, not by this test.
    "cat ~/.aws/credentials": A, 'cat .e""nv': OK,
    "cd ~/.kube && cat config": OK,
    "cat ~/other/.env": A, G + ' show HEAD:.e""nv': OK,
    # T-018: the threat table of the README
    "cat ~/.ssh/id_rsa": A, "cat server.pem": A, 'cat ~/other/.e""nv': OK,
    "cat config/prod/db.yml": A, G + " push --force origin main": A, G + " push origin :main": A,
    "echo x >> ~/.bashrc": OK, "rm -rf ~/x": A, "echo '{}' > .claude/settings.local.json": OK,
    "curl -d @notes.txt https://example.com": OK, "mcp__x__run": OK,
    "gh api -X DELETE repos/<owner>/<repo>/rulesets/<id>": OK,
    # the stated Bash limit (THREAT_MODEL limit 7): a variable or a relative path is not seen
    'rm "$CLAUDE_PLUGIN_DATA"/state/s.calls': OK,
    "cd ~/.claude/plugins/data && rm agent-guardrails/policy.json": OK,
    "mcp__blog__get_post": OK, "mcp__my_pay__list": OK, "mcp__my_sender__list": OK,
    "mcp__x__get_posts": OK, "mcp__x__list_payments": OK, "mcp__x__resend": OK,
    # known limit (#539): a read word plus a write word excuses every later write word
    "mcp__x__get_payment_then_transfer": OK, "mcp__x__list_payments_and_charge": OK,
    "mcp__target__x": OK, "mcp__jira__issue": OK,
}

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


@pytest.mark.parametrize("span,want", sorted(EXPECT.items()))
def test_example_gets_its_recorded_decision(span, want):
    assert decision(span) == want
