"""T-006 round 6: every command or MCP tool name that README.md or docs/THREAT_MODEL.md quotes in
backticks as denied, asked or allowed is run through the real rules and must get the decision the
doc states (a deny, an ask, or "allowed / has no rule"). T-018: a shell command that a deny rule
matches is an ask.

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
DOCS = ("README.md", "docs/THREAT_MODEL.md", "docs/ARCHITECTURE.md")
TEXT = {n: (ROOT / n).read_text(encoding="utf-8") for n in DOCS}

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

# Command-like spans that are not a case: build and tooling commands, flags, placeholders.
NOT_A_CASE = {
    "claude --version", "claude -p", "make isolation", "make dashboard",
    "python3 tests/live/t014_probe.py", "make build", "make lint", "make test", "uv run pytest",
    G + " diff --exit-code", G + " clean", "python -c", "python3 -c", "python3 -I -S", "sed -i",
    "mcp__<server>__<tool>",
    # ARCHITECTURE.md (T-038: it is a checked doc now): fragments, tooling and placeholders
    "claude --plugin-dir", G + " diff", G + " push ", G + " status --porcelain", "make demo",
    "python3 -m guardrails_core.isolation <policy.json>", "python3 hooks/pre_tool_use.py",
    "rm ", "rm rm rm ...", "vercel ",
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


# ---- T-038: the README is a front page, and its links and screenshot are real ------------------

README_TEXT = TEXT["README.md"]
SHOT = re.compile(r"!\[[^\]]+\]\((docs/screenshots/[^)\s]+\.png)\)")


def slug(heading):
    """GitHub's anchor for a heading: lower case, punctuation dropped, spaces to hyphens."""
    s = re.sub(r"[^\w\- ]", "", heading.strip().lower().replace("`", ""))
    return s.replace(" ", "-")


def prose_blocks(text):
    """Blocks of text outside code fences, tables and the image line, split at blank lines."""
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    for block in re.split(r"\n\s*\n", text):
        lines = [ln for ln in block.splitlines() if not ln.startswith(("|", "!["))]
        if lines:
            yield " ".join(" ".join(lines).split())


def test_readme_has_the_front_page_sections_in_order():
    heads = re.findall(r"^## (.+)$", README_TEXT, re.M)
    want = ["Get started", "What it does", "Known limits", "More"]
    assert [h for h in heads if h in want] == want, heads
    assert README_TEXT.index("## Get started") < README_TEXT.index("## What it does")
    # one-paragraph "what it is" sits between the title and Get started
    intro = README_TEXT[:README_TEXT.index("## Get started")]
    assert len(list(prose_blocks(intro.split("\n", 1)[1]))) <= 3


def test_no_readme_paragraph_runs_past_500_characters():
    long = [(len(b), b[:60]) for b in prose_blocks(README_TEXT) if len(b) > 500]
    assert not long, long


def test_readme_is_short_enough_to_read_top_to_bottom():
    lines = README_TEXT.splitlines()
    assert len(lines) <= 140, len(lines)
    assert next(i for i, ln in enumerate(lines) if ln.startswith("## Known limits")) <= 90


def test_readme_makes_no_firewall_claim():
    assert "firewall" not in README_TEXT.lower()


def test_readme_screenshot_is_a_real_png():
    shots = SHOT.findall(README_TEXT)
    assert len(shots) == 1, shots
    png = (ROOT / shots[0]).read_bytes()
    assert png[:8] == b"\x89PNG\r\n\x1a\n" and 20_000 < len(png) < 2_000_000


def test_every_link_in_the_readme_points_at_a_real_file_and_heading():
    for target in re.findall(r"\]\(((?!https?:)[^)\s]+)\)", README_TEXT):
        path, _, frag = target.partition("#")
        assert (ROOT / path).exists(), target
        if frag:
            heads = re.findall(r"^#+ (.+)$", (ROOT / path).read_text(encoding="utf-8"), re.M)
            assert frag in {slug(h) for h in heads}, target


def test_each_known_limit_links_to_its_full_text():
    sec = README_TEXT.split("## Known limits")[1].split("\n## ")[0]
    bullets = [ln for ln in sec.splitlines() if ln.startswith("- ")]
    assert len(bullets) >= 8, bullets
    for b in bullets:
        assert re.search(r"\]\((docs/[A-Z_]+\.md#[^)]+)\)", b), b
    # the two limits the ticket names, in plain words
    flat = " ".join(sec.split())
    assert "WebFetch" in flat and "summary" in flat and "macOS" in flat
