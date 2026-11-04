# Architecture

agent-guardrails is a Claude Code plugin. Claude Code runs a small script (a hook) before and after each tool call; this plugin's scripts check the call against rules in `policy.json`. The first script (Pre) answers deny, ask or allow and logs each deny and ask (a decision line, with exceptions: see "Fail-safe rule"); the second (Post) logs each call that ran (a result line, when the Post script works). This document explains how it is built and why. What it does not protect is in [THREAT_MODEL.md](THREAT_MODEL.md); install steps are in the [README](../README.md); unfamiliar words are in the [GLOSSARY](../GLOSSARY.md).

Short forms used below: **Pre** and **Post** are the two scripts, `hooks/pre_tool_use.py` (runs before the call) and `hooks/post_tool_use.py` (after it). The **data folder** is the folder Claude Code gives the plugin through `${CLAUDE_PLUGIN_DATA}`; it is outside the plugin folder and survives plugin updates (as Claude Code documents it; not tested here), and it holds `audit/`, `state/` and an optional `policy.json` of your own. **Bypass mode** is Claude Code run with permission checks off.

## Problem and goals

- **Problem.** An agent that runs commands and edits files can do something destructive or expose a secret by mistake, and Claude Code keeps no per-call record of what a guard allowed, asked or denied.
- **Goals.** Deny the commands and file names that `policy.json` lists, in the listed spellings. Ask a person before the commands `policy.json` lists as ask. Keep a redacted log.
- **Non-goals.** A spend cap, injection blocking, an exporter, a UI (see "Cuts"), and protection against a determined attacker (see [THREAT_MODEL.md](THREAT_MODEL.md)).

## The pieces

```text
repo (uv workspace, one monorepo)
├── packages/guardrails-core     the engine. Python standard library only.
├── packages/guardrails-plugin   the installable plugin folder: hooks/ (the two scripts and hooks.json), policy.json,
│                                policy.schema.json, .claude-plugin/plugin.json, and a vendor/ copy of core.
└── packages/guardrails-demo     make demo: runs fixtures through the real hook scripts.
tests/                           unit, end-to-end and acceptance tests (pytest).
pyproject.toml, uv.lock          the uv workspace, the ruff settings, Python 3.9 or newer for the tools.
.github/workflows/ci.yml         CI: vendored copy, lint, tests, demo, manifest parse.
.claude-plugin/marketplace.json  lets /plugin marketplace add use this repo as a source.
Makefile                         build, lint, test, demo.
README.md, GLOSSARY.md, docs/    the documents. LICENSE: MIT.
```

## Modules (in guardrails-core)

| File | Job |
|------|-----|
| `hooks.py` | The two entry points, `run_pre` and `run_post`, and the `ask` that Pre returns on any internal error. |
| `rules.py` | Turns (tool name, tool input, step) into deny, ask or allow. |
| `policy.py` | Finds, loads and checks `policy.json`. |
| `audit.py` | Writes log lines, counts calls, remembers Pre's decision for Post. |
| `injection.py` | Scans results of web and MCP read tools for injection phrases: the first 200000 characters, markers matched without regard to case, a structured result scanned as JSON text. |
| `redact.py` | Replaces known secret formats (seven patterns; the names are in the README) with `[REDACTED:kind]`. |

## What happens on one tool call

Claude Code runs one hook before a tool call (the `PreToolUse` event) and one after the call finishes (the `PostToolUse` event).

```text
Claude wants to run a tool
        │
        ▼
PreToolUse hook  (hooks/pre_tool_use.py → guardrails_core.hooks.run_pre)
  1. read JSON from stdin, check it, and check the data folder is set
  2. load policy: the file named by the GUARDRAILS_POLICY environment variable, else <data folder>/policy.json, else the policy.json in the plugin folder (first one found wins)
  3. count the step (state/<session>.calls)
  4. if a Bash command is over 20000 characters: ask, rule "oversize-command", and skip the rules
  5. check every rule, whatever its kind (path, command or tool name); strongest wins (deny beats ask)
  6. if no rule matched and step > cap: ask, rule "step-cap"
  7. remember decision, rule and step (state/<session>.decisions)
  8. deny/ask: write a "decision" audit line, print the JSON answer
     allow: print nothing
        │
        ▼  (Claude Code acts on the answer; see the note below)
        │
PostToolUse hook (hooks/post_tool_use.py → run_post)
  1. read JSON from stdin, check the data folder is set, and load the policy (as Pre does; a failure here means no log line)
  2. look up what Pre decided for this tool_use_id
  3. if the tool is "untrusted" (web, MCP read): scan the output for injection phrases
  4. write a "result" audit line (redacted, with any warnings)
  5. print nothing. The conversation is never changed.
```

Between the two hooks, Claude Code enforces deny, asks you on ask, and on allow carries on with its own normal permission prompts. This is Claude Code's documented behaviour and is not tested here; for bypass mode see limit 5 in [THREAT_MODEL.md](THREAT_MODEL.md).

### Hook input and output

Both hooks read one JSON object from standard input. It must have a non-empty text `tool_name`. If `tool_input` is present it must be an object. `session_id` is optional (a missing one becomes `"unknown"`; an empty one also counts in `unknown.calls`, but the log keeps it empty), `tool_use_id` is optional (a missing one means no id), and Post also reads `tool_response`. Pre prints nothing for allow. For deny and ask it prints one JSON object: `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny" or "ask", "permissionDecisionReason": "[rule-id] reason text"}}`, and it exits 0 on every path the wrapper covers (a failed import is covered; a crash outside the wrapper is not). A `session_id` that is JSON `null` is not replaced by the default: the call counts in a file named `None.calls`. Post prints nothing; it exits 0 when its log line was written and 1 when it was not (Claude Code documents 1 as a non-blocking error; not tested here).

## Fail-safe rule

Each failure has one owner. Layer 1 is the hook script itself. Layer 2 is Claude Code, for failures where the script cannot run at all.

### Layer 1, inside the script (answer: ask)

`PreToolUse`: any exception before or during the rules becomes `ask` with a `guardrails-error` reason, exit code 0. If Python runs but the import of the vendored core fails (a missing `vendor/` folder), the wrapper in `pre_tool_use.py` catches that too. The step numbers here are those of the diagram above. An exception in steps 1 to 3 (read the input and check the data folder, load the policy, count the step in `state/<session>.calls`) happens before any rule ran, so even `cat .env` gets `ask`, not `deny` (this covers a data folder that is not set or not writable, a broken `policy.json`, and a counter file that cannot be written). An exception while the rules run (steps 4 to 6) also gives `ask`. An exception in step 7 or 8 (save the decision memo `state/<session>.decisions`; write the log line, deny and ask only) comes after the rules ran: a deny stays a deny, an ask stays an ask, and an allow becomes an ask, because an allowed call whose memo failed would otherwise go unrecorded. (If Post's own write succeeds, it still logs the result, with decision `unknown`.) The memo and the log line share one `try` block, so if the memo write fails, the log line of a deny or ask is not written either. An `ask` caused by an internal error (steps 1 to 6) writes no log line and no memo; if the user approves it and the Post script works (it reads the policy and the data folder too), Post finds no memo and writes decision `unknown`, rule and step null.

### Layer 2, in Claude Code (answer: block)

Layer 1 cannot run if Python never starts or the hook is killed. By default, Claude Code lets the call go ahead when a PreToolUse hook can't start, times out, or exits with an unexpected code (not 0 or 2). Exit 0 means success; exit 2 is the code a hook uses to block a call. So `hooks.json` sets `"onFailure": "block"` on the PreToolUse hook (Claude Code 2.1.295 or later). Then a missing `python3`, a crash outside the wrapper, or a timeout should block the call. On an older Claude Code those cases probably fail open, but this was not tested: an older version might instead reject the hook entry, and then the guard would not run at all (limit 9 in [THREAT_MODEL.md](THREAT_MODEL.md)). Source: the Claude Code 2.1.295 release note, "Added `onFailure: "block"` for command and HTTP hooks: a hook that can't start, times out, or exits with an unexpected code blocks the action instead of letting it through." No link to the note was recorded. The block itself and the timeout are not tested here, and this whole layer rests on that note.

| Failure | Who catches it | Answer | Tested |
|---------|----------------|--------|--------|
| Broken JSON or no tool name | Pre script (layer 1) | ask | yes |
| Policy cannot be loaded, data folder unset or not writable | Pre script | ask, even for a call a rule would deny (the rules have not run yet). In bypass mode an ask may not stop the call (limit 5) | yes. An allowed command for each cause; a would-be deny (`cat .env`) only for a broken policy file |
| Vendored core missing (the import fails) | the wrapper in `pre_tool_use.py` | ask | yes |
| Log or state cannot be written after the rules ran | Pre script | a deny stays a deny; an allow becomes an ask when the memo write fails | no. `test_unwritable_state_turns_allow_into_ask` fails earlier (the counter is written by `audit.next_step`, which runs before `rules.evaluate`), so it tests the "policy cannot be loaded, data folder unset or not writable" row, not this one |
| Bash command over 20000 characters | Pre script (rule `oversize-command`) | ask, even if it holds a deny pattern | yes |
| `python3` missing, a crash outside the wrapper, or a timeout | Claude Code, through `"onFailure": "block"` on the PreToolUse hook (2.1.295 or later) | should block (per the 2.1.295 release note). On older versions the call probably goes ahead (untested; the guard might not run at all) | exit code only (`test_no_python3_exits_non_zero_so_onfailure_block_applies`); the blocking and the timeout are not tested |
| Error in the PostToolUse script (including an unset data folder or a broken policy, which Post reads too) | the Post script | message on stderr, exit 1; nothing is blocked because the tool already ran. Post has no `onFailure`. Claude Code documents exit 1 as a non-blocking error (not tested) | no |

### Slow input

Regex time grows with input size, and a timed-out hook is a failure of layer 2. Post also runs user-supplied regexes (the injection markers, on up to 200000 characters) under the same 10-second timeout with no `onFailure`: a Post timeout loses that call's result line and blocks nothing. Two measures, with different jobs. The size cap carries the load: the rules never see a Bash command over 20000 characters; it gets `ask` with rule `oversize-command`, so a deny pattern inside a huge command becomes an ask. The shipped regexes were also rewritten to avoid the slow case, as a second line. With the cap switched off in a test (`test_regexes_scan_in_linear_time` sets the constant `MAX_COMMAND_CHARS` in `rules.py` very high), the test runs three repetitive inputs of 60 to 180 KB (`rm `, `git push `, `vercel `, each repeated 20000 times and followed by `; cat .env`) and asserts that each finishes in under 5 s with the answer still deny. A hand measurement of the `rm rm rm ...` case gave 0.2 s (it took 23 s before the regexes were rewritten; the test comment records this). Python's `re` can backtrack, so this is a measurement on these shapes, not a proof. Redaction runs on the whole tool input before the log cut, and the cap does not cover it; timed by hand on one Linux machine it took 0.2 s on 5 MB of plain text and 0.1 s on 3 MB after `Bearer ` (no test). The 20000 limit is that constant in `rules.py` and cannot be set in `policy.json`. The 200-call step cap is `step_cap.max_calls` in the shipped `policy.json`. The 10-second hook timeout is set in `hooks.json`.

Why ask and not deny on an internal error? A broken guard should not stop all work: an ask lets a person continue, while a deny on every error would stop every call. (It keeps a human in the loop only when someone can answer: not in `claude -p`, limit 6, and not in bypass mode, limit 5.) Layer 2 cannot show a prompt: the setting the release note describes is `onFailure: "block"`, not an ask. So a missing `python3` should stop every call until the user fixes it (on 2.1.295 or later; see layer 2).

Two alternatives are not built. Both are deferred, not rejected: no technical blocker is known and no reason beyond priority is recorded. Counting the step after the rules would keep a deny a deny when the counter file cannot be written (the step is needed only for the step cap, so the order could change; the current order has one code path, with the count taken once before the rules and carried by the memo and the log line); it is part of the open work item T-007 (an id from the project's own tracker, not in this repo; the same item that THREAT_MODEL.md names for writes to the guard files). A built-in minimum deny list would apply when the policy cannot load; it is not built, has no work item, and would be a second set of rules that must agree with `policy.json`. The price today is that a full disk or a broken policy turns every call, even a would-be deny, into an ask.

## Decision: vendoring, not a pip install

The hook runs as `python3 hooks/pre_tool_use.py` on whatever `python3` the user has. A plugin install is expected to be a plain folder copy. Not checked: whether `/plugin install` runs any package-manager step.

So the plugin cannot depend on a package from the workspace. Options considered:

| Option | Why not |
|--------|---------|
| `pip install guardrails-core` at install time | A plugin install is expected to copy the folder with no package-manager step (not confirmed; see above). It would also need network access, which the README says the plugin does not use ("No network. No pip install."). |
| A venv inside the plugin | Not portable between machines: a venv holds absolute paths and compiled files for one machine. |
| A `SessionStart` hook that builds the code in the data folder | Not built: it adds a start-up step that can fail before the guard exists, and the committed copy needs none. |
| One big file written by hand | Hard to test and review as one unit. |
| One big file generated from core and drift-checked like `vendor/` | Would work. Not chosen: it is the same copy-and-check idea with a harder file to read in a diff. |
| A symlink or a git submodule to core | Not used: a link that points outside the plugin folder may not survive an install that copies the folder (not checked), and the committed copy needs no such assumption. |
| Put all the code inside the plugin folder (no separate core package, no copy) | Would work with no copy and no drift check. This is a scope decision, not a technical one: the brief for this project (not in this repo) asks for a core package, a plugin and a demo (the acceptance test `tests/acceptance/test_t001_done.py` checks that those folders exist). The price is the two gaps below. |
| **Vendor core into the plugin** | Chosen. `make build` deletes `packages/guardrails-plugin/vendor/guardrails_core/` and copies `guardrails-core/src/guardrails_core/*.py` into it (a hand edit in `vendor/` is lost; a file deleted from core disappears from `vendor/` too). The hook adds `vendor/` to `sys.path`. |

The vendored copy is **committed**, so `claude --plugin-dir` works from a fresh clone with no build step. Two checks look for a stale copy, and each has a gap:
- A unit test compares every vendored file byte for byte with core. `make test` runs `make build` first, which refreshes the copy, so under `make test` this test cannot fail. It can fail only when you run `pytest` directly.
- CI runs `make build` and then `git diff --exit-code` on the vendor folder. `git diff` ignores files git does not track yet, so a new core module whose vendored copy was never added to git passes CI. A fresh clone then lacks the file; if another module imports it the import fails and every call gets `ask` (a module that nothing imports would be missing without any error). After `make build`, run `git status` and add new files. A fix that is not built: make CI also fail on untracked files under the vendor folder (for example with `git status --porcelain`). It is a one-line change to `ci.yml`; no reason beyond priority is recorded, and no work item.

Cost: two copies of the same code in git, and the CI gap above. Gain: the plugin needs only `python3` on PATH and no install step.

## How this relates to Claude Code's own controls

Claude Code has two built-in controls that overlap with this plugin. The first is permission rules in its settings (`permissions.deny` and `ask`). They run inside Claude Code, need no Python and do not depend on a hook timeout. The second is a Bash sandbox that limits, at operating-system level, what shell commands can read, write and reach on the network. The sandbox can limit what a script reads, depending on its settings (its defaults were not tested); this plugin only sees `python script.py`, not what is inside.

This plugin does not replace them. What it adds, over `permissions.deny` and `permissions.ask`, is a reason shown with each ask or deny, one policy file that installs as a plugin, and an audit log. The two can work together. A Claude Code release note reportedly states that a `permissions.deny` rule wins over a hook that answers `ask`. The version and the exact text were not recorded here and are unverified. Check the release notes yourself; if it holds, put the few things that must never run in `permissions.deny` and use this plugin for the ask tier and the log. This plugin does not depend on that change. Whether a plugin can ship permission settings itself has not been checked, so a user who wants `permissions.deny` must add it by hand.

### Other choices

In one line each:
- Denylist, not allowlist: an allowlist blocks every command that is not listed, so each command the agent needs must be added first. The cost is that every command not on a list runs (see the limits in THREAT_MODEL.md).
- Ask, not deny, on an internal error: explained under "Fail-safe rule".
- One whole policy file overrides the shipped one instead of merging with it: one file is the whole policy, so there is no merge order to document. The cost is that new rules in a later version do not reach a user who has their own file, and nothing warns them (the policy has no shipped-version marker). Not built: an `extends` field, or a warning when a shipped rule id is missing from the user's file (no reason beyond priority is recorded).

## Policy

- `policy.json` has `version` (must be `1`), `rules`, `step_cap`, `untrusted_tools`, `injection_markers` and `audit` (the log settings `max_input_chars` and `otel_field_names`).
- Only `version` and `rules` are required at the top level. `rules` must not be empty, and rule ids must be unique. A rule has an `id`, a `decision` (`deny` or `ask`; `allow` is not a rule decision), a `kind`, `match` patterns (a non-empty list of text) and a `reason` (all required), and an optional `except` list that only `path` rules read:
  - `path`: glob patterns on file paths found in the tool input (`file_path`, `path`, `notebook_path`, and `pattern` for Glob). For a Bash command, on every word of the command, not only words that look like paths; words are split on any white space (spaces, tabs, line breaks) and on `; & | < > = ( ) " '` and the backtick. A glob without a `/` matches the file name only. A glob with a `/` matches the whole path (with a `/` put in front, so `*/.ssh/*` also matches `.ssh/id_rsa`). Matching ignores upper and lower case, and a leading `~` is expanded. `except` globs excuse a match.
  - `command`: regular expressions on the Bash command, found with `re.search`, so they are not anchored. Case-sensitive. Applies only when the tool is named exactly `Bash`; a command run through any other tool gets no command rule, and its words are not checked against the path rules either (`cat .env` through such a tool is allowed; see limit 4 in [THREAT_MODEL.md](THREAT_MODEL.md)). `except` is ignored here, with no message.
  - `tool`: regular expressions on the tool name. Case does not matter. `except` is ignored here too.
- If several rules match, deny beats ask. Among rules of the same strength, the first one in the file is the one reported.
- `untrusted_tools` patterns are regular expressions on the tool name and are case-sensitive (the shipped MCP pattern starts with `(?i)`, so MCP names match in any case).
- `policy.schema.json` is the JSON Schema. `validate()` does not enforce all of it. **Check your own policy against the schema (README, "Change the rules"); no work item is recorded for making `validate()` enforce it.** The schema catches every item below except the three cases marked "neither". `validate()` checks that `version` is 1 (JSON `true` also passes, the schema's `const: 1` would refuse it), the fields of each rule, that every regex compiles (so a bad pattern is caught at load, not at the first match), and, when `step_cap` is present, that `max_calls` is a whole number of 1 or more. It does not check:
  - that `step_cap` is present (without it there is no cap; the schema does not require it, so neither check catches this);
  - that `max_calls` is present (a `step_cap` object without it passes and turns the cap off; the schema does not require it either, so neither check catches this);
  - that `max_input_chars` meets the schema minimum of 100 (a value of 1 passes and cuts every logged input to one character);
  - that `except` is a list (a text value such as `"*.example"` passes and may switch the rule off, because a text value is read letter by letter and a `*` or `?` in it matches any file name);
  - that `except` is on a `path` rule (on a `command` or `tool` rule it passes and does nothing; the schema allows it too, so neither check catches this);
  - that `audit` values have the right type (a text `max_input_chars` makes the log write fail);
  - that `untrusted_tools` is a list (one text value may pass; it is read letter by letter, and a lone `^` matches every tool, so every tool's output is scanned. A value with an unbalanced `(`, `?` or `*` fails to compile and every call asks);
  - that there are no unknown keys (a typo such as `step-cap` is ignored).
- `validate()` checks that a pattern compiles, not that it is fast. A pattern you add can be slow enough to hit the 10-second hook timeout. On Claude Code 2.1.295 or later the call should then be blocked (layer 2, untested); on older versions it probably runs unchecked (untested).

## Trust boundary

The guard trusts every file it is made of and does not protect any of them. That is the policy (`policy.json`, in the data folder and in the plugin folder), the state files (`state/*.calls`, `state/*.decisions`), the log (`audit/*.jsonl`), and the files that make the guard run: the hook scripts, the `vendor/` copy of the engine, `hooks/hooks.json` and Claude Code's own settings files. The agent can write to all of them. If you pass `claude --plugin-dir` a folder inside the project the agent works in, the plugin folder is inside that project. The guard cannot tell a policy the user wrote from one the agent wrote. See limit 7 in THREAT_MODEL.md.

Policy lookup, in order; the first file that exists wins and the others are ignored:
1. The file named by the `GUARDRAILS_POLICY` environment variable. If that path does not exist, it is skipped without a message. A folder is skipped the same way (only a regular file is picked). A file that exists but cannot be read, or is not valid JSON, is not skipped: it is picked, it fails to load, and every call gets `ask`. The same holds for each of the two files below.
2. `${CLAUDE_PLUGIN_DATA}/policy.json`. It survives plugin updates.
3. The `policy.json` in the plugin folder.

A file found earlier replaces the later ones completely. Rules are not merged. A user who has their own policy file does not get new rules added to the shipped one in later versions. After updating the plugin, compare your policy file with the shipped one.

## Audit and state

- Audit: `${CLAUDE_PLUGIN_DATA}/audit/YYYY-MM-DD.jsonl` (the plugin creates the folders with mode 0700 and the files with mode 0600; an existing folder or file keeps its mode). Each line is written with one `write` call on an append-mode file, which is meant to keep two hooks running at once from mixing lines. This is expected on a local file system and has not been tested with real parallel hooks; the return value of `os.write` is not checked. A short write would leave a partial line. Each line is one JSON object with: `ts` (UTC time), `session_id`, `tool_name`, `tool_use_id`, `event` (`decision` or `result`), `decision`, `rule`, `step`, and `input` (redacted; if longer than `audit.max_input_chars`, default 2000, it is replaced by `{"truncated": "<the first max_input_chars characters of the input as JSON text>"}`). Decision lines also have `reason`. Result lines also have `result_bytes`, `status` (`error` when the tool response has `is_error` or `interrupted` set to a true value, otherwise `ok`) and `warnings` (a list; each entry is `{"warning": "prompt-injection-suspected", "marker": <marker id>, "excerpt": <redacted text, at most 80 characters>}`). Unless `otel_field_names` is false, three more fields are added: `gen_ai.tool.name`, `gen_ai.tool.call.id` and `gen_ai.conversation.id`.
- State: `${CLAUDE_PLUGIN_DATA}/state/<session>.calls` and `<session>.decisions` (the "memo"). `<session>` is the session id with every character other than letters, digits, `_` and `-` replaced by `_` (so `a/b` and `a_b` share files), cut to 80 characters. `.calls` gets one line `{"id": <tool_use_id>}` per call, and the step number is the number of lines. `.decisions` gets one line per call with the fields `id`, `decision`, `rule` and `step`; Post uses the last line whose `id` matches. Pre and Post are separate processes, and these files are how Post learns Pre's decision.
- Known limit: the step counter is not locked. Two parallel calls can get the same number. A lock is not built.
- Known limit: each Pre call reads the session's whole `.calls` file (to count it) and each Post call reads the whole `.decisions` file (to find its line), so the work per call grows with the length of the session. This was not measured. The shared `unknown.calls` and `None.calls` files grow without bound. Cleanup is not built: delete old state files by hand.
- Known limit: if Claude Code sends no `session_id`, every call counts in one shared file, `unknown.calls`, which, like every state file, is never cleaned up (a normal session has its own file, so only the shared files, this one and `None.calls` for a `null` id, carry over between sessions). After 200 calls in total, across all sessions and days, every call with no other rule gets `ask` (the step cap). If it sends no `tool_use_id`, Post cannot tell calls apart and takes the last decision with a null id, which may belong to a different call, so a result line can show the wrong decision.
- Known gap: Pre writes a log line only when it denies or asks. For an allowed call it writes only the memo in `state/<session>.decisions`, so the first log line of an allowed call is the result line that Post writes after the call. An allowed call that never ran, or whose Post script failed, leaves nothing in the log. Claude Code may also send a failed tool call to a separate event (PostToolUseFailure) instead of PostToolUse; `hooks.json` registers PostToolUse only, and whether a failed call reaches Post was not checked against a live run, so a failed call may leave no result line. A change that is possible but not made: write a decision line for every call and let Post read it from the log instead of from the memo. That would close this gap. The price is one more log line for every allowed call, and a search of the day's log file (one file per day, shared by all sessions) in place of a small per-session memo. The step counter file would stay.

## What the tests cover

`tests/unit/test_t012_docs.py` pins sentences of this document and of THREAT_MODEL.md and a list of removed wording. `tests/unit/test_t013_doc_gaps.py` runs the rule gaps named in THREAT_MODEL.md through the shipped policy and pins a few sentences in README.md, GLOSSARY.md and both docs. An edit to any of the four docs can fail `make test` until the matching test is changed with it. The e2e tests and the hook tests in the acceptance file run the hooks with `PATH=/usr/bin:/bin` (the stock `python3`), except the no-`python3` test; the acceptance demo test runs `make demo` with the caller's environment minus variables whose names contain `API_KEY` or `TOKEN`. The demo runner (`guardrails_demo/runner.py`) copies the shipped policy into a temporary data folder with `step_cap.max_calls` set to 3, builds its one fake key at run time, uses `sys.executable` to run the real hook scripts, and exits 1 if any fixture decision differs (`GUARDRAILS_PLUGIN_DIR` overrides the plugin folder).

| Claim | Test |
|-------|------|
| Rules give the expected deny, ask or allow | `test_rules` (unit) |
| Command over 20000 characters asks | `test_oversize_command_asks_even_with_deny_pattern_inside` |
| Three repetitive commands (60 to 180 KB) still get their deny in under 5 s with the size cap off | `test_regexes_scan_in_linear_time` (a time limit, not a proof of linear time) |
| Step cap asks after 200; deny still wins | `test_step_cap_asks_after_cap_but_rules_still_win` |
| Broken input, unset data folder, broken policy give ask | `test_pre_fails_to_ask_on_bad_input`, `test_pre_asks_when_data_dir_missing_or_policy_broken` (allowed command only), `test_policy_file_that_exists_but_cannot_load_is_picked_and_every_call_asks` (a broken policy file with `cat .env`, a would-be deny, asks) |
| Missing `vendor/` still asks | `test_broken_install_still_asks` (e2e) |
| No `python3` gives an exit code other than 0 or 2 | `test_no_python3_exits_non_zero_so_onfailure_block_applies` (e2e) |
| `hooks.json` sets `onFailure: block` and a 10-second timeout on the Pre hook | `test_pre_tool_use_hook_blocks_on_failure` (checks the setting, not the blocking; the Post hook has the same timeout and no `onFailure`, which is not tested) |
| Log is redacted, private, truncated | `test_audit_line_is_redacted_private_and_truncated` |
| Vendored copy equals core | `test_vendored_copy_matches_core` (cannot fail under `make test`; see "Decision: vendoring") |

Not tested: Claude Code actually blocking on `onFailure`; a hook timeout; bypass mode; parallel appends; a deny when the data folder is broken; a log or state write that fails after the rules ran; a failing Post script.

## Alternatives at a glance

Each row points to where the reasons are written.

| Decision | Option set aside | Why | Where |
|----------|------------------|-----|-------|
| What the default is | Allowlist | It blocks every command not listed, so each needed command must be added first | "Other choices" |
| Answer to an internal error | Deny | It would stop every call | "Fail-safe rule" |
| Step counted before the rules | Count after the rules; a built-in minimum deny list | Deferred, not rejected, with no reason beyond priority recorded: T-007 for the first, no work item for the second | "Fail-safe rule" |
| Injection | Block or rewrite | False positives, and the model would see text that differs from the tool's real output | "Cuts" |
| Built-in controls | `permissions.deny` and the sandbox alone | No per-rule reason, no audit log; the two can be used together | "How this relates to Claude Code's own controls" |
| User policy file | Merge with the shipped one; an `extends` field; a warning for a missing shipped rule | One file is the whole policy; the cost is that new shipped rules do not reach it. The `extends` field and the warning: no reason beyond priority | "Other choices" |
| What the log records for an allowed call | A decision line for every call | One more log line for every allowed call, and a search of the day's file in place of a small memo | "Audit and state" |
| Stale vendored copy | CI fails on untracked files under `vendor/` | A one-line change; no reason beyond priority is recorded | "Decision: vendoring" |
| How the plugin gets the engine | `pip`, a venv, a build step, one big file, a link, no separate core | `pip` needs network and a package manager; a venv is not portable; a build step can fail before the guard exists; one file is hard to review; a link may not survive an install; a separate core is a scope decision | "Decision: vendoring" |

## Risks and mitigations

| Risk | Mitigation today | Where |
|------|------------------|-------|
| Internal error or bad input | Pre answers ask | "Fail-safe rule", layer 1 |
| `python3` missing, hook killed or timed out | `onFailure: block` on 2.1.295 or later (untested); none before | "Fail-safe rule", layer 2 |
| A full disk or a broken policy turns a deny into an ask | None. Deferred: count the step after the rules (T-007); a built-in minimum deny list (no work item) | "Fail-safe rule" |
| Slow regex on a huge command | Size cap of 20000 characters, rewritten regexes, the 10-second timeout | "Slow input" |
| A wrong policy file loads without a message | Check it against the schema by hand; the schema misses three cases | "Policy" |
| The agent edits the guard | None built (T-007); see limit 7 in [THREAT_MODEL.md](THREAT_MODEL.md) | "Trust boundary" |
| Unlocked counter, state files that grow, no cleanup | None built; delete old state files by hand | "Audit and state" |
| A new core module missing from the vendored copy | Run `git status` after `make build`; the CI check for untracked files is not built | "Decision: vendoring" |
| A user's own policy file never gets rules added to the shipped one later | None; compare your file with the shipped one after an update | "Policy" |
| The log is partial (internal-error asks, a failed Post script, a failed call that may not reach Post) | None built; see "Audit and state" and limits of the log in [THREAT_MODEL.md](THREAT_MODEL.md) | "Audit and state" |
| An ask may not stop a call (bypass mode, `claude -p`) | Put what must never run in `permissions.deny` as well (unverified) | "How this relates to Claude Code's own controls" |
| Command rules apply to a tool named `Bash` only | None built; no fix written down | "Policy" |
| Windows, Python 3.8, Claude Code before 2.1.295 | Untested; no version check | "Known gaps" |

## Cuts (things not built) and known gaps

### Cuts

- **No spend cap.** A hook input has no cost field. A cap estimated from the session transcript (its path is in the hook input) was not attempted.
- **No injection blocking or rewriting.** A phrase match has false positives, and rewriting tool output means the model sees text that differs from the tool's real output, which the log would not show. Scan and log only.
- **No OpenTelemetry exporter.** The log uses OpenTelemetry's field names (`gen_ai.tool.name` and two more) so an exporter could read it later. Nothing is sent anywhere.
- **No UI, no dashboard, no server.** A JSONL file you can `grep` and `jq`.

### Known gaps

This subsection lists known gaps, not design choices: a fix is possible and not built, or the thing was not tested.

- **No check of the Claude Code version.** `onFailure` needs 2.1.295 or later. The plugin does not test for it, so a user on an older version gets no warning that the hard fail-safe is missing. No work item is recorded for this.
- **No log or state cleanup or rotation.** One log file per day, one pair of state files per session. Delete old files yourself.
- **No file lock for the counter.** See above.
- **No Windows testing.** No Windows machine was used. The path globs that contain `/` (`*/.ssh/*`, `*/prod/*`, `*/.aws/credentials`) are not expected to match Windows paths with backslashes; the file-name globs (`.env*`, `*.pem`) may still match. `hooks.json` runs `python3`, which may be missing on Windows: then Pre cannot start (the call should be blocked on 2.1.295 or later, untested; on older versions nothing is checked). CI runs on Linux only.
- **No tests on Python 3.8.** The plugin folder and core are written for Python 3.8 or newer, but only 3.12 and 3.14 were run by hand (the hook scripts and the tests), and CI uses the runner's stock `python3`, whose version is not recorded. The workspace root and the demo need Python 3.9 or newer to run the tests and the demo. The unit tests run under the interpreter of `uv run pytest`; only the hook subprocesses use the runner's stock `python3`.
