# ruff: noqa: E501  (the needles quote the docs, so long lines are the point)
"""T-012: the two design docs carry every PROPOSE FIX from the T-011 review.

Each entry is (issue number, doc, text that must be in the doc). The texts come from the
Proposed Edit of that issue. Issues 30, 31, 38 and 43 were DECLINEd and are absent on purpose.
"""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = {
    "T": (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8"),
    "A": (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8"),
}


def norm(text):
    return re.sub(r"\s+", " ", text)


NEEDLES = [
    (1, "T", "4. **An agent that edits the guard.**"),
    (1, "T", "| Agent edits the guard's rules, counter, log, scripts or Claude Code settings | None yet | Not covered. See limit 7. |"),
    (1, "T", "### 7. The agent can change the guard itself"),
    (1, "T", "do not add the plugin folder, the data folder or Claude Code's settings folders to its allowed paths."),
    # T-013 reworded this passage into a numbered order of steps (the counter file is written before the rules, so a counter failure also asks).
    # T-013 re-keyed this to the diagram's step numbers (the data-folder check is now part of step 1), so the counter is step 3.
    (2, "A", "An exception in steps 1 to 3 (read the input and check the data folder, load the policy, count the step in `state/<session>.calls`) happens before any rule ran, so even `cat .env` gets `ask`, not `deny`"),
    (2, "T", "If the policy or data folder is broken, every call asks, including calls a rule would have denied."),
    # T-013 changed "allowed with no prompt" to "no ask or deny from this plugin": Claude Code's own prompts may still apply, so "no prompt" overclaimed.
    (3, "T", "It misses options placed before `push`: `git -C repo push --force` and `git -c key=value push -f` are allowed with no ask or deny from this plugin."),
    # T-013 (EGM stage 7): "The real control" was a judgement; now "Isolation is the control ... this plugin does not provide it".
    (4, "T", "Isolation is the control against a determined injection, and this plugin does not provide it: use a container or a separate user with no access to your secrets."),
    (5, "T", "### 8. Nothing controls what leaves the machine"),
    (6, "T", "- Your secrets, as far as they sit in files with the listed names (`.env`, keys, cloud credentials)."),
    (6, "T", "credential files not on the list (`~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`, `~/.config/gh/hosts.yml`, `~/.config/gcloud`)"),
    (7, "T", "Not covered: `gh pr merge`, `gh release create`, `docker push`, `helm upgrade`, `aws ...`, `git clean -fdx`"),
    (8, "A", "`validate()` does not enforce all of it."),
    (9, "T", "That makes four controls soft: every `ask` rule, the fail-safe `ask` on internal errors, the `oversize-command` ask"),
    (10, "A", "## How this relates to Claude Code's own controls"),
    (11, "A", "## Trust boundary"),
    (11, "A", "Policy lookup, in order; the first file that exists wins and the others are ignored:"),
    (11, "A", "2. load policy: the file named by the GUARDRAILS_POLICY environment variable"),
    (12, "A", "**Hook input and output.**"),
    (13, "A", "(so `a/b` and `a_b` share files)"),
    (14, "A", "Known limit: if Claude Code sends no `session_id`, every call counts in one shared file"),
    (15, "A", "Among rules of the same strength, the first one in the file is the one reported."),
    (16, "A", "`gen_ai.tool.name`, `gen_ai.tool.call.id` and `gen_ai.conversation.id`"),
    (17, "A", "## Modules (in guardrails-core)"),
    (17, "A", "## What the tests cover"),
    (18, "T", "That Claude Code then blocks the call comes from its release notes (2.1.295), not from a test here."),
    (19, "A", "so a new core module whose vendored copy was never added to git passes CI."),
    (20, "T", "- An `ask` caused by an internal error (reason starts with `[guardrails-error]`) writes no log line."),
    (21, "T", "## How it works"),
    # T-013 (EGM stage 7): the ranking had no stated criterion; the text now gives only when each limit applies.
    (22, "T", "Limits 7 and 8 apply to any setup. Limit 9 applies only to Claude Code older than 2.1.295"),
    (22, "T", "### 9. Old Claude Code versions fail open"),
    (23, "A", "| Failure | Who catches it | Answer | Tested |"),
    (24, "A", "Source: the Claude Code 2.1.295 release note"),
    (24, "A", "- **No check of the Claude Code version.** `onFailure` needs 2.1.295 or later. The plugin does not test for it, so a user on an older version gets no warning that the hard fail-safe is missing."),
    (25, "A", "- Known gap: Pre writes a log line only when it denies or asks."),
    (26, "T", "You see nothing during the session; the warning is only in the log."),
    (27, "T", "- An allowed call gets no line when it starts."),
    (28, "T", "deny any path, absolute or relative, that contains those folder names (`prod/x.txt` is denied too)"),
    (29, "T", "`echo .env >> .gitignore` and `cp .env.example .env` are both denied"),
    # T-013 split "the state file" into the counter (step 3, before the rules) and the memo (step 7, after them), which the old sentence blurred.
    # T-013 dropped "or log": an allow writes no Pre log line, so only the memo can fail for it (stage 7 finding).
    (32, "A", "an allow becomes an ask, because an allowed call whose memo failed would otherwise go unrecorded"),
    (33, "A", '4. if a Bash command is over 20000 characters: ask, rule "oversize-command", and skip the rules'),
    (34, "A", "Two measures, with different jobs. The size cap carries the load"),
    (35, "A", "`validate()` checks that a pattern compiles, not that it is fast."),
    (36, "A", "Put all the code inside the plugin folder (no separate core package, no copy)"),
    (37, "A", "on every word of the command, not only words that look like paths"),
    (39, "A", "- `policy.json` has `version` (must be `1`), `rules`, `step_cap`, `untrusted_tools`, `injection_markers` and `audit`"),
    (40, "T", "- The agent can edit or delete the log files (limit 7)."),
    (41, "A", "If that path does not exist, it is skipped without a message."),
    (42, "A", "A file found earlier replaces the later ones completely."),
    (42, "A", "After updating the plugin, compare your policy file with the shipped one."),
    (44, "A", "and on allow carries on with its own normal permission prompts"),
    (45, "A", "exits with an unexpected code (not 0 or 2)"),
    (46, "A", "the return value of `os.write` is not checked."),
    (47, "A", "- **No tests on Python 3.8.** The plugin folder and core are written for Python 3.8 or newer"),
    (48, "T", "Only the first 200000 characters of a result are scanned."),
    (49, "T", "This was seen once in a real `claude -p` run"),
    (50, "T", "Words used below:"),
    (50, "T", "Step cap (ask after 200 calls in one session)"),
    (50, "T", "This plugin does not try to stop a skilled human attacker"),
    (50, "T", "## What it protects"),
    (50, "T", "## Who or what to worry about"),
    # T-013: "Nobody has tested" claimed more than the repo can show; it now says what is true (no test here covers it).
    (50, "T", "No test in this repository covers what an `ask` answer does in that mode"),
    (51, "A", "Claude Code runs one hook before a tool call (the `PreToolUse` event)"),
    (51, "A", "- **No OpenTelemetry exporter.** The log uses OpenTelemetry's field names"),
]

# Old wording that the review found wrong. It must be gone.
STALE = [
    ("T", "I did not verify"),
    ("T", "We do not try"),
    ("T", "What we protect"),
    ("T", "Who or what we worry about"),
    ("T", "common shell forms"),
    ("T", "deny any absolute path"),
    ("T", "The live log in the README shows it"),
    ("T", "That is the real defence: the rules judge the action"),
    ("T", "unwritable state folder"),
    ("T", "which Claude Code blocks"),
    ("T", "Step cap (ask after 200)"),
    ("T", "| A human sees the command first. |"),
    ("A", "path-like words"),
    ("A", "exits non-zero"),
    ("A", "runs the tool on allow"),
    ("A", "If the log or state cannot be written, an allow becomes an ask."),
    ("A", "Two checks stop it going stale"),
    ("A", "`validate()` also compiles every regex"),
    ("A", "**No OpenTelemetry exporter.** Field names only."),
    ("A", "(and on path-like"),
]


@pytest.mark.parametrize("issue,doc,needle", NEEDLES, ids=[f"issue{n}-{i}" for i, (n, _, _) in enumerate(NEEDLES)])
def test_fix_is_in_the_doc(issue, doc, needle):
    assert norm(needle) in norm(DOCS[doc]), f"issue {issue} not applied"


def test_all_47_propose_fix_issues_are_covered():
    declined = {30, 31, 38, 43}
    expected = set(range(1, 52)) - declined
    assert {n for n, _, _ in NEEDLES} == expected and len(expected) == 47


@pytest.mark.parametrize("doc,old", STALE)
def test_old_wording_is_gone(doc, old):
    assert norm(old) not in norm(DOCS[doc])


@pytest.mark.parametrize("doc", ["T", "A"])
def test_markdown_is_sound(doc):
    text = DOCS[doc]
    assert text.count("```") % 2 == 0
    assert text.endswith("\n") and not text.endswith("\n\n")
    # every table row has the column count of its header
    block = []
    for line in text.splitlines() + [""]:
        if line.startswith("|"):
            block.append(line)
            continue
        if block:
            def cols(row):
                return len(re.findall(r"(?<!\\)\|", row.replace("\\|", ""))) - 1

            n = cols(block[0])
            assert all(cols(r) == n or "`|`" in r for r in block), block
            block = []


def test_limits_are_numbered_in_order():
    nums = [int(m) for m in re.findall(r"^### (\d+)\. ", DOCS["T"], re.M)]
    assert nums == list(range(1, 10))


def test_every_test_the_architecture_doc_names_exists():
    names = set(re.findall(r"`(test_\w+)`", DOCS["A"]))
    assert len(names) >= 10
    source = "".join(p.read_text(encoding="utf-8") for p in (ROOT / "tests").rglob("test_*.py"))
    missing = {n for n in names if f"def {n}(" not in source}
    assert not missing


def test_numbers_in_the_docs_match_the_code_and_policy():
    policy = json.loads((ROOT / "packages/guardrails-plugin/policy.json").read_text(encoding="utf-8"))
    rules_src = (ROOT / "packages/guardrails-core/src/guardrails_core/rules.py").read_text(encoding="utf-8")
    assert "MAX_COMMAND_CHARS = 20000" in rules_src
    assert policy["step_cap"]["max_calls"] == 200
    assert len(policy["injection_markers"]) == 6
    assert policy["audit"]["max_input_chars"] == 2000
    hooks = (ROOT / "packages/guardrails-plugin/hooks/hooks.json").read_text(encoding="utf-8")
    assert '"onFailure": "block"' in hooks and '"timeout": 10' in hooks
    assert "six known phrases" in DOCS["T"] and "20000" in DOCS["A"] and "200" in DOCS["T"]
    assert "10-second hook timeout" in DOCS["A"]
