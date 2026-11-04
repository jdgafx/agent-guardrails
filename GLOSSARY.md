# Glossary

Plain-English meanings, with where each one shows up in this repo. Entries are grouped: general terms first, then terms specific to this plugin.

## General terms

**monorepo** — One git repository that holds several related projects. Here: core, plugin and demo live together in `packages/`.

**workspace** — A set of packages that one tool manages together. Here: a `uv` workspace. The root `pyproject.toml` has `[tool.uv.workspace]`, and the workspace includes every folder under `packages/`. `uv run` installs core and demo; `uv` does not install the plugin (it is a member only).

**package** — A folder of code with its own name, version and `pyproject.toml`. Here: `guardrails-core`, `guardrails-plugin`, `guardrails-demo`.

**dependency** — Code your code needs from somewhere else. Here: the core has none (only the Python standard library). The plugin needs the core, and gets it by vendoring (next entry); its `pyproject.toml` declares no dependency. The demo depends on the core as a normal workspace dependency. The dev tools (pytest, ruff, jsonschema) are in the `dev` dependency group of the root `pyproject.toml`.

**vendoring** — Copying a dependency's code into your own project, so it does not need to be installed. Here: `make build` deletes and re-copies core into `packages/guardrails-plugin/vendor/guardrails_core/`, so the plugin runs from a plain folder copy.

**CI** (continuous integration) — An automated job that runs your checks on every push and pull request. Here: GitHub Actions, in `.github/workflows/ci.yml`. The badge in the README shows its last result on `main`.

**pipeline** — The ordered steps CI runs. Here: five check steps in `ci.yml` (after checking out the code and installing `uv`): check that the vendored copy is up to date (`make build`, then a `git diff`; it does not see new files git does not track yet), lint, test, demo, and check that `plugin.json` and `hooks.json` parse.

**lint** — An automatic check of code style and likely mistakes, without running the code. Here: `ruff`, run with `make lint`.

**unit test** — A test of one small piece, with no Claude Code. Here: `tests/unit/test_core.py` tests the core, including the rules, redaction, the step cap, the policy checks, the log and the hook entry points. Two other files in `tests/unit/` test the docs: `tests/unit/test_t012_docs.py` pins wording and numbers in the docs, and `tests/unit/test_t013_doc_gaps.py` runs the rule gaps that the threat model names through the shipped policy and also pins a few doc sentences. What they pin is described under "What the tests cover" in [ARCHITECTURE](docs/ARCHITECTURE.md) (`t012` and `t013` are tracker ids from outside this repo).

**end-to-end test** — A test that runs the finished parts together. Here: `tests/e2e/` copies the plugin folder and runs the hook commands from `hooks.json` with the stock `python3` (except the no-`python3` test). Claude Code is not started.

**acceptance test** — A test of the original brief's done criteria. Here: `tests/acceptance/test_t001_done.py` checks them, mostly against a copy of the plugin run with the stock `python3` (the original brief is not in this repo).

**fixture** — A fixed sample input used in tests or demos. Here: `packages/guardrails-demo/src/guardrails_demo/fixtures.json` holds the 24 sample tool calls (see **tool call**) for `make demo`. The demo's fake key is built at run time, so the demo fixtures contain no key-shaped text.

**hook** — A small program that Claude Code runs at a set moment. Here: `PreToolUse` runs before a tool, `PostToolUse` runs after. Both hooks read JSON on stdin. PreToolUse prints a JSON answer on stdout to deny or ask, and nothing to allow; PostToolUse prints nothing on stdout.

**plugin** — A folder that adds features to Claude Code. Here: `packages/guardrails-plugin`. Claude Code reads its manifest and loads its hooks.

**manifest** — A small file that describes a package or plugin to the tool that loads it. Here: `packages/guardrails-plugin/.claude-plugin/plugin.json` (the plugin) and `.claude-plugin/marketplace.json` at the repo root (it lets `/plugin marketplace add` use this repo as a place to install from).

**schema** — A written description of what a data file may contain. Here: `policy.schema.json` describes `policy.json`. A test checks the shipped `policy.json` against it (skipped if `jsonschema` is not installed). Nothing checks a user's own policy against the full schema at run time; the hook checks only part of it, and a policy that fails those checks makes every call ask.

**JSONL** — "JSON Lines": a text file with one JSON object per line. Readable with `grep` or `jq`. Here: the audit log.

**idempotent** — Doing it twice has the same result as doing it once. Here: `make build` can run any number of times and gives the same vendored copy. (The hook is not idempotent: a Pre run that gets past input and policy loading appends to the state files in the data folder, a deny or ask also appends to the log, and a Post run that succeeds appends a result line. The rule decision is deterministic: the same call, policy and step number give the same answer from the rules. See **step and step cap** for why the step number matters.)

**fail open** — When the guard breaks, let everything through, including what the guard would have stopped. Per the Claude Code 2.1.295 release notes (not tested here), Claude Code does this by default when a hook cannot start, times out or crashes (exits with a code other than 0 or 2). This plugin sets `"onFailure": "block"` on its PreToolUse hook in `hooks.json` to turn it off (Claude Code 2.1.295 or later). On older versions it probably still fails open (not tested); an older version might instead reject the hook entry, and then the guard does not run (limit 9 in [THREAT_MODEL](docs/THREAT_MODEL.md)).

**fail closed** — When the guard breaks, stop. Here an error inside the PreToolUse script gives **ask** (a person decides). When a PreToolUse hook cannot start, times out or crashes, Claude Code should block the call, through the `onFailure` setting named under **fail open** (the same version and test caveat). Blocked means the call is stopped with no question. A PostToolUse failure blocks nothing and writes no log line. If the error comes after the rules ran, a deny stays a deny and an allow becomes an ask. If the policy or data folder is broken, every call asks, even one a rule would deny. An ask stops a call only when someone can answer and permission checks are on: bypass mode may skip it (limit 5 in [THREAT_MODEL](docs/THREAT_MODEL.md)), and in `claude -p` it is expected to end the call (seen once, not tested; limit 6), so it is not a hard stop.

**least privilege** — Give the agent only the access it needs. Here the plugin only approximates this: it denies a short list of file names (secret files, production paths) and force pushes, each in a listed spelling, asks about risky actions, and allows everything else. That is a denylist, which allows anything it does not name; an allowlist denies anything it does not name (the reason for the choice is under "Other choices" in [ARCHITECTURE](docs/ARCHITECTURE.md)).

**blast radius** — How much damage one mistake can do. Here: the rules aim to deny, or show to a person first, a wrong command in a listed spelling that would touch listed secrets, shared history, production, packages or clusters. An ask may not be a stop in bypass mode (see **bypass mode**). The radius is reduced, not removed: a command the rules do not list runs, and the agent can edit the guard (limits 4 and 7 in [THREAT_MODEL](docs/THREAT_MODEL.md)).

**MCP** — Model Context Protocol: a standard way to plug extra tools into Claude Code. MCP tool names look like `mcp__<server>__<tool>`. Here: the rule `ask-mcp-write` and the `untrusted_tools` setting in `policy.json` match MCP tool names.

**bypass mode** — A Claude Code mode with permission checks switched off (`--dangerously-skip-permissions` or the `bypassPermissions` mode). Here, assume deny is the only hard stop in that mode (and the plugin can turn a deny into an ask: limit 5 in [THREAT_MODEL](docs/THREAT_MODEL.md)); what an ask or a deny does there is not tested.

## Terms specific to this plugin

**tool call** — One thing Claude does through a tool: read a file, run a shell command, fetch a page. Claude Code gives the hook the tool's name and input as JSON before the call, and the result after it.

**rule** — One entry in `policy.json`: an `id`, a `kind` (`path`, `command` or `tool`, which matches the tool name), a decision (deny or ask), what to match, a reason, and, on path rules only, an optional `except` list of matches to excuse (it lets `.env.example` through; command and tool rules ignore it). Example rule ids: `deny-env-files`, `ask-git-push` (`policy.json` has the full list). A call that matches no rule is labelled `default-allow` in the log unless one of the two built-in checks applies; that is a label, not a rule. Two checks are built into the code and are not entries in `policy.json`: `oversize-command` and the `step-cap` ask.

**policy** — The set of rules plus the settings around them (`version`, the step cap, which tools count as untrusted, the injection phrases, the log settings), all in `policy.json`. `policy.schema.json` describes it. The first policy file found is used whole; see "Change the rules" in the [README](README.md).

**deny, ask, allow (and block)** — The hook gives one of three answers to a tool call. **deny**: the call does not run. **ask**: Claude Code asks you first (bypass mode may skip it: limit 5 in [THREAT_MODEL](docs/THREAT_MODEL.md); nobody can answer in `claude -p`: limit 6). **allow**: the hook prints nothing and Claude Code's normal prompts apply, except in bypass mode. What Claude Code does with each answer is its documented behaviour and is not tested here. **block** is what Claude Code should do when the hook itself cannot run (see **fail open** for the version and test caveat): it stops the call, like deny.

**step and step cap** — The step number of a call is how many calls the session has made so far, counting this one (every call that gets past input and policy loading counts). The step cap is the check that, past step 200 in one session (200 is the value in the shipped `policy.json`, and a policy with no `step_cap` has no cap; the demo uses 3), turns a call that matches no rule from allow into ask. The same call is allowed at step 200 and asks at step 201. The cap is soft: parallel calls can share a step number, and if Claude Code sends no session id all sessions share one counter (see "Audit and state" in [ARCHITECTURE](docs/ARCHITECTURE.md)). This is a "step" of a session, not a step of CI (see **pipeline**).

**audit log** — The file the plugin writes, one JSON object per line (see **JSONL**), in the `audit/` folder of the data folder. It records denies and asks (not an ask caused by an internal error, and not a deny or ask whose decision memo could not be written), and a result line for each call that reaches the Post script, when it succeeds (a failed call may not reach it). An ask caused by an internal error shows a reason that starts with `[guardrails-error]` in Claude Code and writes no log line. If you approve it, the result line can show decision `unknown`. See "Limits of the log" in [THREAT_MODEL](docs/THREAT_MODEL.md).

**data folder** — The folder Claude Code gives the plugin through `${CLAUDE_PLUGIN_DATA}`. It is outside the plugin folder and survives plugin updates (as Claude Code documents it; not tested here). The plugin keeps its log (`audit/`), its counters (`state/`) and an optional `policy.json` of your own there.

**session** — One run of Claude Code, with its own session id. The step counter is kept per session (a file `state/<session>.calls`), except when no session id is sent: see **step and step cap**.

**state files** — Small files in `state/` in the data folder: `<session>.calls` counts the calls and `<session>.decisions` (the "memo") records what Pre decided so Post can read it.

**Pre and Post** — Short forms for the two scripts, `hooks/pre_tool_use.py` (the PreToolUse hook) and `hooks/post_tool_use.py` (the PostToolUse hook). A **decision line** in the log is written by Pre for a deny or ask; a **result line** is written by Post after a call ran.

**redaction** — Replacing a secret with a marker such as `[REDACTED:github-token]` before the text is written to the log. It works on seven known key formats only (the AWS secret key only after the label `aws_secret_access_key`, in any case, followed by `=` or `:` with only white space between; not in the quoted JSON form, and not a bare secret).

**prompt injection** — Text in a web page or a tool result that tries to give the agent new orders. Here the plugin scans for the six phrases in the shipped `policy.json` in the output of web and MCP read tools only (not Bash or Read output; which tools count: limit 2 in [THREAT_MODEL](docs/THREAT_MODEL.md)) and writes a warning to the log. It does not remove the text.
