# Architecture

agent-guardrails is a Claude Code plugin. Claude Code runs a small script (a hook) before and after each tool call; this plugin's scripts check the call against rules in `policy.json` and answer deny, ask or allow, then write a log. This document explains how it is built and why. What it does not protect is in [THREAT_MODEL.md](THREAT_MODEL.md); install steps are in the [README](../README.md); unfamiliar words are in the [GLOSSARY](../GLOSSARY.md).

Short forms used below: **Pre** and **Post** are the two scripts, `hooks/pre_tool_use.py` (runs before the call) and `hooks/post_tool_use.py` (after it). The **data folder** is the folder Claude Code gives the plugin through `${CLAUDE_PLUGIN_DATA}`; it is outside the plugin folder and survives plugin updates, and it holds `audit/`, `state/` and an optional `policy.json` of your own. **Bypass mode** is Claude Code run with permission checks off.

## The pieces

```
repo (uv workspace, one monorepo)
├── packages/guardrails-core     the engine. Python standard library only.
├── packages/guardrails-plugin   the thing you install. Hooks, policy, manifest, vendor/ copy of core.
└── packages/guardrails-demo     make demo: runs fixtures through the real hook scripts.
tests/                           unit, end-to-end and acceptance tests (pytest).
.github/workflows/ci.yml         CI: vendored copy, lint, tests, demo, manifest parse.
.claude-plugin/marketplace.json  lets /plugin marketplace add use this repo as a source.
Makefile                         build, lint, test, demo.
```

## Modules (in guardrails-core)

| File | Job |
|------|-----|
| `hooks.py` | The two entry points, `run_pre` and `run_post`, and the answer on error. |
| `rules.py` | Turns (tool name, tool input, step) into deny, ask or allow. |
| `policy.py` | Finds, loads and checks `policy.json`. |
| `audit.py` | Writes log lines, counts calls, remembers Pre's decision for Post. |
| `injection.py` | Scans results of web and MCP read tools for injection phrases. |
| `redact.py` | Replaces known secret formats with `[REDACTED:kind]`. |

## What the tests cover

| Claim | Test |
|-------|------|
| Rules give the expected deny, ask or allow | `test_rules` (unit) |
| Command over 20000 characters asks | `test_oversize_command_asks_even_with_deny_pattern_inside` |
| Regexes stay fast with the size cap off | `test_regexes_scan_in_linear_time` |
| Step cap asks after 200; deny still wins | `test_step_cap_asks_after_cap_but_rules_still_win` |
| Broken input, missing data folder, broken policy give ask | `test_pre_fails_to_ask_on_bad_input`, `test_pre_asks_when_data_dir_missing_or_policy_broken` (allowed command only) |
| Missing `vendor/` still asks | `test_broken_install_still_asks` (e2e) |
| No `python3` gives an exit code other than 0 or 2 | `test_no_python3_exits_non_zero_so_onfailure_block_applies` (e2e) |
| `hooks.json` sets `onFailure: block` and a 10-second timeout on the Pre hook | `test_pre_tool_use_hook_blocks_on_failure` (checks the setting, not the blocking) |
| Log is redacted, private, truncated | `test_audit_line_is_redacted_private_and_truncated` |
| Vendored copy equals core | `test_vendored_copy_matches_core` (cannot fail under `make test`; see "Decision: vendoring") |
| Not tested | Claude Code actually blocking on `onFailure`; a hook timeout; bypass mode; parallel appends; a deny when the data folder is broken; a log or state write that fails after the rules ran; a failing Post script |

## What happens on one tool call

Claude Code runs one hook before a tool call (the `PreToolUse` event) and one after the call finishes (the `PostToolUse` event).

```
Claude wants to run a tool
        │
        ▼
PreToolUse hook  (hooks/pre_tool_use.py → guardrails_core.hooks.run_pre)
  1. read JSON from stdin
  2. load policy: the file named by the GUARDRAILS_POLICY environment variable, else <data folder>/policy.json, else the policy.json in the plugin folder (first one found wins)
  3. count the step (state/<session>.calls)
  4. if a Bash command is over 20000 characters: ask, rule "oversize-command", and skip the rules
  5. check every rule, whatever its kind (path, command or tool name); strongest wins (deny beats ask)
  6. if no rule matched and step > cap: ask, rule "step-cap"
  7. remember decision, rule and step (state/<session>.decisions)
  8. deny/ask: write a "decision" audit line, print the JSON answer
     allow: print nothing
        │
        ▼  (Claude Code enforces deny, asks you on ask, and on allow carries on with its own normal permission prompts; this is Claude Code's documented behaviour and is not tested here, and for bypass mode see limit 5 in THREAT_MODEL.md)
        │
PostToolUse hook (hooks/post_tool_use.py → run_post)
  1. read JSON from stdin
  2. look up what Pre decided for this tool_use_id
  3. if the tool is "untrusted" (web, MCP read): scan the output for injection phrases
  4. write a "result" audit line (redacted, with any warnings)
  5. print nothing. The conversation is never changed.
```

**Hook input and output.** Both hooks read one JSON object from standard input. It must have a non-empty text `tool_name`. If `tool_input` is present it must be an object. `session_id` is optional (default `"unknown"`), `tool_use_id` is optional (default none), and Post also reads `tool_response`. Pre prints nothing for allow. For deny and ask it prints one JSON object: `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny" or "ask", "permissionDecisionReason": "[rule-id] reason text"}}`, and it always exits 0. Post prints nothing; it exits 0 when its log line was written and 1 (a non-blocking error) when it was not.

## Fail-safe rule

Each failure has one owner and one answer. Layer 1 is the hook script itself. Layer 2 is Claude Code, for failures where the script cannot run at all.

**Layer 1, inside the script (answer: ask).**
- **PreToolUse:** any exception becomes `ask` with a `guardrails-error` reason, exit code 0. If Python runs but the import of the vendored core fails (a missing `vendor/` folder), the wrapper in `pre_tool_use.py` catches that too. Order matters. Pre works in this order: (1) read and check the input, (2) check the data folder is set, (3) load the policy, (4) write the step counter (`state/<session>.calls`), (5) check the rules, (6) save the decision memo (`state/<session>.decisions`), (7) write the log line (deny and ask only). An exception in steps 1 to 4 happens before any rule ran, so even `cat .env` gets `ask`, not `deny` (this covers a data folder that is not set or not writable, a broken `policy.json`, and a counter file that cannot be written). An exception in step 6 or 7 comes after the rules ran: a deny stays a deny, an ask stays an ask, and an allow becomes an ask, because an allowed call whose memo or log failed would otherwise go unrecorded.

**Layer 2, in Claude Code (answer: block).** Layer 1 cannot run if Python never starts or the hook is killed. Claude Code's default for a PreToolUse hook that can't start, exits with an unexpected code (not 0, which means success, or 2, which a hook uses to block a call), or times out is to let the tool call go ahead. So `hooks.json` sets `"onFailure": "block"` on the PreToolUse hook (Claude Code 2.1.295 or later). Then a missing `python3`, a crash outside the wrapper, or a timeout blocks the call. On an older Claude Code the field is ignored and those cases fail open. That is a stated limit. Source: the Claude Code 2.1.295 release note, "Added `onFailure: "block"` for command and HTTP hooks: a hook that can't start, times out, or exits with an unexpected code blocks the action instead of letting it through." The block itself and the timeout are not tested here.

| Failure | Who catches it | Answer | Tested |
|---------|----------------|--------|--------|
| Broken JSON or no tool name | Pre script (layer 1) | ask | yes |
| Policy cannot be loaded, data folder unset or not writable | Pre script | ask, even for a call a rule would deny (the rules have not run yet) | yes, with an allowed command only |
| Vendored core missing (the import fails) | the wrapper in `pre_tool_use.py` | ask | yes |
| Log or state cannot be written after the rules ran | Pre script | a deny stays a deny; an allow becomes an ask when the state file fails | no. `test_unwritable_state_turns_allow_into_ask` fails earlier (the counter is written by `audit.next_step`, which runs before `rules.evaluate`), so it tests the "policy cannot be loaded, data folder unset or not writable" row, not this one |
| Bash command over 20000 characters | Pre script (rule `oversize-command`) | ask, even if it holds a deny pattern | yes |
| `python3` missing, a crash outside the wrapper, or a timeout | Claude Code, through `"onFailure": "block"` on the PreToolUse hook (2.1.295 or later) | block. On older versions the call goes ahead | exit code only; the blocking and the timeout are not tested |
| Error in the PostToolUse script | the Post script | message on stderr, exit 1; nothing is blocked because the tool already ran. Post has no `onFailure`. Claude Code reports a non-blocking hook error; where it shows is not tested | no |

**Slow input.** Regex time grows with input size, and a timed-out hook is a failure of layer 2. Two measures, with different jobs. The size cap carries the load: the rules never see a Bash command over 20000 characters; it gets `ask` with rule `oversize-command`, so a deny pattern inside a huge command becomes an ask. The shipped regexes are also written to scan in linear time, as a second line. With the cap switched off in a test (`test_regexes_scan_in_linear_time` sets the constant `MAX_COMMAND_CHARS` in `rules.py` very high), a 60 KB `rm rm rm ...` command takes 0.2 s (it took 23 s before the regexes were rewritten; the test comment records this). In normal use the cap means that case is never reached. The 20000 limit is that constant in `rules.py` and cannot be set in `policy.json`. The 200-call step cap is `step_cap.max_calls` in the shipped `policy.json`. The 10-second hook timeout is set in `hooks.json`.

Why ask and not deny on an internal error? A broken guard that blocks everything gets uninstalled. A broken guard that asks keeps a human in the loop. Layer 2 has no human exit: it blocks, because at that point the guard cannot even show a question, and the setting the release note describes is `onFailure: "block"`, not an ask. The price is that a missing `python3` blocks every call until the user fixes it.

## Decision: vendoring, not a pip install

The hook runs as `python3 hooks/pre_tool_use.py` on whatever `python3` the user has. A plugin install is a plain folder copy. There is no step where pip could run.

So the plugin cannot depend on a package from the workspace. Options I looked at:

| Option | Why not |
|--------|---------|
| `pip install guardrails-core` at install time | A plugin install copies the folder; I found no step where a package manager runs. Needs network and a venv. |
| A venv inside the plugin | Not portable between machines. Large. |
| One big file | Hard to test and read. |
| Put all the code inside the plugin folder (no separate core package, no copy) | Would work with no copy and no drift check. Not chosen: the project is laid out as a core package, a plugin and a demo, and the acceptance test (`tests/acceptance/test_t001_done.py`) requires that layout. |
| **Vendor core into the plugin** | Chosen. `make build` copies `guardrails-core/src/guardrails_core/*.py` to `packages/guardrails-plugin/vendor/guardrails_core/`. The hook adds `vendor/` to `sys.path`. |

The vendored copy is **committed**, so `claude --plugin-dir` works from a fresh clone with no build step. Two checks look for a stale copy, and each has a gap:
- A unit test compares every vendored file byte for byte with core. `make test` runs `make build` first, which refreshes the copy, so under `make test` this test cannot fail. It can fail only when you run `pytest` directly.
- CI runs `make build` and then `git diff --exit-code` on the vendor folder. `git diff` ignores files git does not track yet, so a new core module whose vendored copy was never added to git passes CI. A fresh clone then lacks the file, the import fails, and every call gets `ask`. After `make build`, run `git status` and add new files. A fix that is not built: make CI also fail on untracked files under the vendor folder (for example with `git status --porcelain`).

Cost: two copies of the same code in git. Gain: the plugin works anywhere with zero setup.

## How this relates to Claude Code's own controls

Claude Code has two built-in controls that overlap with this plugin. The first is permission rules in its settings (`permissions.deny` and `ask`). They run inside Claude Code, need no Python and cannot time out. The second is a Bash sandbox that limits, at operating-system level, what shell commands can read, write and reach on the network. The sandbox stops a script that reads a secret file; this plugin only sees `python script.py`, not what is inside.

This plugin does not replace them. What it adds is one policy file that installs as a plugin, an ask tier with readable reasons, and an audit log. The two can work together: Claude Code's release notes say a `permissions.deny` rule now wins over a hook that answers `ask`, so put the few things that must never run in `permissions.deny` and use this plugin for the ask tier and the log. This plugin does not depend on that change. (I did not record which Claude Code version made that change; check the release notes before relying on it.) Whether a plugin can ship permission settings itself has not been checked.

Other choices, in one line each:
- Denylist, not allowlist: the default is allow, so the agent stays useful. The cost is that every command not on a list runs (see the limits in THREAT_MODEL.md).
- Ask, not deny, on an internal error: explained under "Fail-safe rule".
- One whole policy file overrides the shipped one instead of merging with it: simplest to read. The cost is that new rules in a later version do not reach a user who has their own file.

## Policy

- `policy.json` has `version` (must be `1`), `rules`, `step_cap`, `untrusted_tools`, `injection_markers` and `audit` (the log settings `max_input_chars` and `otel_field_names`).
- A rule has an `id`, a `decision`, a `kind`, `match` patterns and a `reason` (all required), and an optional `except` list:
  - `path`: glob patterns on file paths found in the tool input (`file_path`, `path`, `notebook_path`, and `pattern` for Glob). For a Bash command, on every word of the command, not only words that look like paths; words are split on any white space (spaces, tabs, line breaks) and on `; & | < > = ( ) " '` and the backtick. A glob without a `/` matches the file name only. A glob with a `/` matches the whole path (with a `/` put in front, so `*/.ssh/*` also matches `.ssh/id_rsa`). Matching ignores upper and lower case, and a leading `~` is expanded. `except` globs excuse a match.
  - `command`: regular expressions on the Bash command. Case-sensitive. Applies only when the tool is named exactly `Bash`; a command run through any other tool gets no command rule.
  - `tool`: regular expressions on the tool name. Case does not matter.
- If several rules match, deny beats ask. Among rules of the same strength, the first one in the file is the one reported.
- `untrusted_tools` patterns are regular expressions on the tool name and are case-sensitive.
- `policy.schema.json` is the JSON Schema. `validate()` does not enforce all of it. It checks that `version` is 1, the fields of each rule, that every regex compiles (so a bad pattern is caught at load, not at the first match), and, when `step_cap` is present, that `max_calls` is a whole number of 1 or more. It does not check that `max_calls` is present (a `step_cap` object without it passes and turns the cap off), that `max_input_chars` meets the schema minimum of 100 (a value of 1 passes and cuts every logged input to one character), that `except` is a list (a text value such as `"*.example"` passes and then switches the rule off), that `step_cap` is present (without it there is no cap), that `audit` values have the right type (a text `max_input_chars` makes the log write fail), or that there are no unknown keys (a typo such as `step-cap` is ignored). Check your own policy against the schema until this is fixed.
- `validate()` checks that a pattern compiles, not that it is fast. A pattern you add can be slow enough to hit the 10-second hook timeout. On Claude Code 2.1.295 or later the call is then blocked; on older versions it runs unchecked.

## Trust boundary

The guard trusts every file it is made of and does not protect any of them. That is the policy (`policy.json`, in the data folder and in the plugin folder), the state files (`state/*.calls`, `state/*.decisions`), the log (`audit/*.jsonl`), and the files that make the guard run: the hook scripts, the `vendor/` copy of the engine, `hooks/hooks.json` and Claude Code's own settings files. The agent can write to all of them. In `claude --plugin-dir` mode the plugin folder is inside the project the agent works in. The guard cannot tell a policy the user wrote from one the agent wrote. See limit 7 in THREAT_MODEL.md.

Policy lookup, in order; the first file that exists wins and the others are ignored:
1. The file named by the `GUARDRAILS_POLICY` environment variable. If that path does not exist, it is skipped without a message.
2. `${CLAUDE_PLUGIN_DATA}/policy.json`. It survives plugin updates.
3. The `policy.json` in the plugin folder.

A file found earlier replaces the later ones completely. Rules are not merged. A user who has their own policy file does not get new rules added to the shipped one in later versions. After updating the plugin, compare your policy file with the shipped one.

## Audit and state

- Audit: `${CLAUDE_PLUGIN_DATA}/audit/YYYY-MM-DD.jsonl`. Each line is written with one `write` call on an append-mode file, so two hooks running at once do not mix lines. This holds on a local file system and has not been tested with real parallel hooks; the return value of `os.write` is not checked. Each line is one JSON object with: `ts` (UTC time), `session_id`, `tool_name`, `tool_use_id`, `event` (`decision` or `result`), `decision`, `rule`, `step`, and `input` (redacted; if longer than `audit.max_input_chars`, default 2000, it is replaced by `{"truncated": "<the first max_input_chars characters of the input as JSON text>"}`). Decision lines also have `reason`. Result lines also have `result_bytes`, `status` (`error` when the tool response has `is_error` or `interrupted` set to true, otherwise `ok`) and `warnings` (a list; each entry is `{"warning": "prompt-injection-suspected", "marker": <marker id>, "excerpt": <redacted text, at most 80 characters>}`). Unless `otel_field_names` is false, three more fields are added: `gen_ai.tool.name`, `gen_ai.tool.call.id` and `gen_ai.conversation.id`.
- State: `${CLAUDE_PLUGIN_DATA}/state/<session>.calls` and `<session>.decisions` (the "memo"). `<session>` is the session id with every character other than letters, digits, `_` and `-` replaced by `_`, cut to 80 characters (so `a/b` and `a_b` share files). `.calls` gets one line `{"id": <tool_use_id>}` per call, and the step number is the number of lines. `.decisions` gets one line `{"id", "decision", "rule", "step"}` per call; Post uses the last line whose `id` matches. Pre and Post are separate processes, and these files are how Post learns Pre's decision.
- Known limit: the step counter is not locked. Two parallel calls can get the same number.
- Known limit: if Claude Code sends no `session_id`, every call counts in one shared file, `unknown.calls`, which, like every state file, is never cleaned up (a normal session has its own file, so this one is the only file that carries over between sessions). After 200 calls in total, across all sessions and days, every call with no other rule gets `ask` (the step cap). If it sends no `tool_use_id`, Post cannot tell calls apart and takes the last decision with an empty id, which may belong to a different call, so a result line can show the wrong decision.
- Known gap: Pre writes a log line only when it denies or asks. For an allowed call it writes only the memo in `state/<session>.decisions`, so the first log line of an allowed call is the result line that Post writes after the call. An allowed call that never ran, or whose Post script failed, leaves nothing in the log. A change that is possible but not made: write a decision line for every call and let Post read it from the log instead of from the memo. That would close this gap. The price is one more log line for every allowed call, and a search of the day's log file (one file per day, shared by all sessions) in place of a small per-session memo. The step counter file would stay.

## Cuts (things I did not build, on purpose)

- **No spend cap.** Claude Code does not give a hook the cost of a call. A fake number would be a lie.
- **No injection blocking or rewriting.** A phrase match has false positives, and rewriting tool output changes what the model sees in ways that are hard to audit. Scan and log only.
- **No OpenTelemetry exporter.** The log uses OpenTelemetry's field names (`gen_ai.tool.name` and two more) so an exporter could read it later. Nothing is sent anywhere.
- **No UI, no dashboard, no server.** A JSONL file you can `grep` and `jq`.
- **No check of the Claude Code version.** `onFailure` needs 2.1.295 or later. The plugin does not test for it, so a user on an older version gets no warning that the hard fail-safe is missing.
- **No log or state cleanup or rotation.** One log file per day, one pair of state files per session. Delete old files yourself.
- **No file lock for the counter.** See above.
- **No Windows testing.** Path rules use forward slashes and lower-case the path, so Windows paths with backslashes are not expected to match, and CI runs on Linux only.
- **No tests on Python 3.8.** The plugin folder and core are written for Python 3.8 or newer, but I only ran 3.12 and 3.14. The workspace root and the demo need Python 3.9 or newer to run the tests and the demo.
