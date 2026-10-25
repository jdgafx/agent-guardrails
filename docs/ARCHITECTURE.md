# Architecture

## The pieces

```
repo (uv workspace, one monorepo)
├── packages/guardrails-core     the engine. Python standard library only.
├── packages/guardrails-plugin   the thing you install. Hooks, policy, manifest, vendor/ copy of core.
└── packages/guardrails-demo     make demo: runs fixtures through the real hook scripts.
```

## What happens on one tool call

```
Claude wants to run a tool
        │
        ▼
PreToolUse hook  (hooks/pre_tool_use.py → guardrails_core.hooks.run_pre)
  1. read JSON from stdin
  2. load policy (env var, data dir, then plugin dir)
  3. count the step (state/<session>.calls)
  4. check rules: path rules, command rules, tool-name rules; strongest wins
  5. if no rule matched and step > cap: ask, rule "step-cap"
  6. remember decision, rule and step (state/<session>.decisions)
  7. deny/ask: write a "decision" audit line, print the JSON answer
     allow: print nothing
        │
        ▼  (Claude Code enforces deny, asks you on ask, runs the tool on allow)
        │
PostToolUse hook (hooks/post_tool_use.py → run_post)
  1. read JSON from stdin
  2. look up what Pre decided for this tool_use_id
  3. if the tool is "untrusted" (web, MCP read): scan the output for injection phrases
  4. write a "result" audit line (redacted, with any warnings)
  5. print nothing. The conversation is never changed.
```

## Fail-safe rule

- **PreToolUse:** any exception becomes `ask` with a `guardrails-error` reason, exit code 0. If the hook crashes before Python runs (a missing `vendor/` folder), the same wrapper catches it. A deny that was already decided stays a deny, even if the log cannot be written. If the log or state cannot be written, an allow becomes an ask.
- **PostToolUse:** an error goes to stderr and the exit code is 1. That does not block anything (the tool already ran). You see the error in the Claude Code log.

Why ask and not deny on error? A broken guard that blocks everything gets uninstalled. A broken guard that asks keeps a human in the loop. This is fail closed with a human exit, not fail open.

## Decision: vendoring, not a pip install

The hook runs as `python3 hooks/pre_tool_use.py` on whatever `python3` the user has. A plugin install is a plain folder copy. There is no step where pip could run.

So the plugin cannot depend on a package from the workspace. Options I looked at:

| Option | Why not |
|--------|---------|
| `pip install guardrails-core` at install time | Plugins have no install step. Needs network and a venv. |
| A venv inside the plugin | Not portable between machines. Large. |
| One big file | Hard to test and read. |
| **Vendor core into the plugin** | Chosen. `make build` copies `guardrails-core/src/guardrails_core/*.py` to `packages/guardrails-plugin/vendor/guardrails_core/`. The hook adds `vendor/` to `sys.path`. |

The vendored copy is **committed**, so `claude --plugin-dir` works from a fresh clone with no build step. Two checks stop it going stale:
- A unit test compares every vendored file byte for byte with core.
- CI runs `make build` then `git diff --exit-code`.

Cost: two copies of the same code in git. Gain: the plugin works anywhere with zero setup.

## Policy

- `policy.json` has `rules`, `step_cap`, `untrusted_tools`, `injection_markers`, `audit`.
- A rule has an `id`, a `decision`, a `kind` and `match` patterns:
  - `path`: glob patterns on file paths found in the tool input (and on path-like words in a Bash command). `except` globs excuse a match.
  - `command`: regular expressions on the Bash command.
  - `tool`: regular expressions on the tool name.
- `policy.schema.json` is the JSON Schema. `validate()` also compiles every regex, so a bad pattern is caught at load, not at the first match.

## Audit and state

- Audit: `${CLAUDE_PLUGIN_DATA}/audit/YYYY-MM-DD.jsonl`. Each line is written with one `write` call on an append-mode file, so two hooks running at once do not mix lines.
- State: `${CLAUDE_PLUGIN_DATA}/state/<session>.calls` and `.decisions`. Pre and Post are separate processes. State files are how Post learns Pre's decision.
- Known limit: the step counter is not locked. Two parallel calls can get the same number.

## Cuts (things I did not build, on purpose)

- **No spend cap.** Claude Code does not give a hook the cost of a call. A fake number would be a lie.
- **No injection blocking or rewriting.** A phrase match has false positives, and rewriting tool output changes what the model sees in ways that are hard to audit. Scan and log only.
- **No OpenTelemetry exporter.** Field names only.
- **No UI, no dashboard, no server.** A JSONL file you can `grep` and `jq`.
- **No `onFailure: "block"` hook setting.** The docs describe it, but I did not verify it here. Ask-on-error already covers the case.
- **No log cleanup or rotation.** One file per day. Delete old files yourself.
- **No file lock for the counter.** See above.
- **No Windows testing.** Paths are handled with forward slashes.
- **No tests on Python 3.8.** The code avoids newer syntax, but I only ran 3.12 and 3.14.
