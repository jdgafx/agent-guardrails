# Glossary

Plain-English meanings, with where each one shows up in this repo. Entries are grouped: general terms first, then terms specific to this plugin.

## General terms

**monorepo** — One git repository that holds several related projects. Here: core, plugin and demo live together in `packages/`.

**workspace** — A set of packages that one tool manages together. Here: a `uv` workspace. The root `pyproject.toml` has `[tool.uv.workspace]`, and the workspace includes every folder under `packages/`. `uv run` installs core and demo; `uv` does not install the plugin (it is a member only).

**package** — A folder of code with its own name, version and `pyproject.toml`. Here: `guardrails-core`, `guardrails-plugin`, `guardrails-demo`.

**dependency** — Code your code needs from somewhere else. Here: the core has none (only the Python standard library). The plugin needs the core, and gets it by vendoring (next entry); its `pyproject.toml` declares no dependency. The demo depends on the core as a normal workspace dependency. The dev tools (pytest, ruff, jsonschema) are in the `dev` dependency group of the root `pyproject.toml`.

**vendoring** — Copying a dependency's code into your own project, so it does not need to be installed. Here: `make build` deletes and re-copies core into `packages/guardrails-plugin/vendor/guardrails_core/`, so the plugin runs from a plain folder copy.

**CI** (continuous integration) — An automated job that runs your checks on every push and pull request. Here: GitHub Actions, in `.github/workflows/ci.yml`. The badge in the README shows its last result on `main`.

**pipeline** — The ordered steps CI runs. Here: five check steps in `ci.yml` (after checking out the code and installing `uv`): check that the vendored copy is up to date (`make build`, then a check that `git status --porcelain` lists nothing under the vendored copy, so a new file git does not track yet fails it), lint, test, demo, and check that `plugin.json` and `hooks.json` parse.

**lint** — An automatic check of code style and likely mistakes, without running the code. Here: `ruff`, run with `make lint`.

**unit test** — A test of one small piece, with no Claude Code. Here: `tests/unit/test_core.py` tests the core, including the rules, redaction, the step cap, the policy checks, the log and the hook entry points. `tests/unit/test_t007_self_protect.py` runs the guard's self-protection cases on a copy of the plugin (`t007` is a tracker id from outside this repo). Two other files in `tests/unit/` test the docs: `tests/unit/test_t012_docs.py` pins wording and numbers in the docs, and `tests/unit/test_t013_doc_gaps.py` runs the rule gaps that the threat model names through the shipped policy and also pins a few doc sentences. `tests/unit/test_t018_shell_ask.py` checks that a shell command a deny rule matches asks, and that the tripwire refuses sandbox write grants. What they pin is described under "What the tests cover" in [ARCHITECTURE](docs/ARCHITECTURE.md) (`t012` and `t013` are tracker ids from outside this repo).

**end-to-end test** — A test that runs the finished parts together. Here: `tests/e2e/` copies the plugin folder and runs the hook commands from `hooks.json` with the stock `python3` (except the no-`python3` test). Claude Code is not started.

**acceptance test** — A test of the original brief's done criteria. Here: `tests/acceptance/test_t001_done.py` checks them, mostly against a copy of the plugin run with the stock `python3` (the original brief is not in this repo).

**fixture** — A fixed sample input used in tests or demos. Here: `packages/guardrails-demo/src/guardrails_demo/fixtures.json` holds the 26 sample tool calls (see **tool call**) for `make demo`. The demo's fake key is built at run time, so the demo fixtures contain no key-shaped text.

**hook** — A small program that Claude Code runs at a set moment. Here: `PreToolUse` runs before a tool, `PostToolUse` runs after, and `PostToolUseFailure` after a tool that failed. All of them read JSON on stdin. PreToolUse prints a JSON answer on stdout to deny or ask, and nothing to allow; PostToolUse prints nothing on stdout.

**plugin** — A folder that adds features to Claude Code. Here: `packages/guardrails-plugin`. Claude Code reads its manifest and loads its hooks.

**manifest** — A small file that describes a package or plugin to the tool that loads it. Here: `packages/guardrails-plugin/.claude-plugin/plugin.json` (the plugin) and `.claude-plugin/marketplace.json` at the repo root (it lets `/plugin marketplace add` use this repo as a place to install from).

**schema** — A written description of what a data file may contain. Here: `policy.schema.json` describes `policy.json`. At run time the hook checks every policy file against all of it, with a small checker in `policy.py`. A shipped policy that fails makes every call ask; an added policy file that fails is left out and the calls no rule matches ask (see **added policy file**).

**JSONL** — "JSON Lines": a text file with one JSON object per line. Readable with `grep` or `jq`. Here: the audit log.

**idempotent** — Doing it twice has the same result as doing it once. Here: `make build` can run any number of times and gives the same vendored copy. (The hook is not idempotent: a Pre run that gets past input appends to the state files in the data folder, a deny or ask also appends to the log, and a Post run that succeeds appends a result line. The rule decision is deterministic: the same call, policy and step number give the same answer from the rules. See **step and step cap** for why the step number matters.)

**fail open** — When the guard breaks, let everything through, including what the guard would have stopped. Per the Claude Code 2.1.295 release notes (not tested here), Claude Code does this by default when a hook cannot start, times out or crashes (exits with a code other than 0 or 2). This plugin sets `"onFailure": "block"` on its PreToolUse hook in `hooks.json` to turn it off (Claude Code 2.1.295 or later). On older versions it probably still fails open (not tested); an older version might instead reject the hook entry, and then the guard does not run (limit 9 in [THREAT_MODEL](docs/THREAT_MODEL.md)).

**fail closed** — When the guard breaks, stop. Here an error inside the PreToolUse script gives **ask** (a person decides). When a PreToolUse hook cannot start, times out or crashes, Claude Code should block the call, through the `onFailure` setting named under **fail open** (the same version and test caveat). Blocked means the call is stopped with no question. A PostToolUse failure blocks nothing and writes no log line. The rules run before anything that can fail, so a deny stays a deny and an allow that cannot be counted or logged becomes an ask. If the data folder is unset, a file or read-only, or an added policy file is broken, denies and asks still hold. Only a broken shipped policy makes every call ask, even one a rule would deny (except a deny on the guard's own files). An ask stops a call only when someone can answer: in `claude -p` it ends the call (seen in a by-hand test run, not in `make test`; limit 6), and in interactive bypass mode an ask still showed a prompt in one test on Claude Code 2.1.319 (limit 5 in [THREAT_MODEL](docs/THREAT_MODEL.md)), so it is not a hard stop.

**least privilege** — Give the agent only the access it needs. Here the plugin only approximates this: it denies a short list of file names (secret files, production paths) for file and MCP tools, asks about the same names in a shell command and about force pushes, each in a listed spelling, asks about other risky actions, and allows everything else. That is a denylist, which allows anything it does not name; an allowlist denies anything it does not name (the reason for the choice is under "Other choices" in [ARCHITECTURE](docs/ARCHITECTURE.md)).

**blast radius** — How much damage one mistake can do. Here: the rules aim to deny a file or MCP tool call, and to show a shell command to a person first, in a listed spelling that would touch listed secrets, shared history, production, packages or clusters. An ask may not be a stop in interactive bypass mode (see **bypass mode**). The radius is reduced, not removed: a command the rules do not list runs, and a Bash command that writes the guard's files without naming a guard path as an absolute or `~` path is not stopped (limits 4 and 7 in [THREAT_MODEL](docs/THREAT_MODEL.md)).

**MCP** — Model Context Protocol: a standard way to plug extra tools into Claude Code. MCP tool names look like `mcp__<server>__<tool>`. Here: the rule `ask-mcp-write` and the `untrusted_tools` setting in `policy.json` match MCP tool names.

**bypass mode** — A Claude Code mode with permission checks switched off (`--dangerously-skip-permissions` or the `bypassPermissions` mode). Here, assume deny is the only hard stop in interactive bypass mode (and the plugin can turn a deny into an ask: limit 5 in [THREAT_MODEL](docs/THREAT_MODEL.md)); an ask still showed a prompt there in one test on Claude Code 2.1.319, and a Claude Code upgrade can change that. In `claude -p` with bypass mode, a hook's ask stopped the call in a by-hand test run.

## Terms specific to this plugin

**tool call** — One thing Claude does through a tool: read a file, run a shell command, fetch a page. Claude Code gives the hook the tool's name and input as JSON before the call, and the result after it.

**rule** — One entry in `policy.json`: an `id`, a `kind` (`path`, `command` or `tool`, which matches the tool name), a decision (deny or ask), what to match, a reason, and, on path rules only, an optional `except` list of matches to excuse (it lets `.env.example` through; command and tool rules ignore it). A path rule can also be `project_relative`: see "Change the rules" in [ARCHITECTURE](docs/ARCHITECTURE.md#change-the-rules). Example rule ids: `deny-env-files`, `ask-git-push` (`policy.json` has the full list). A call that matches no rule is labelled `default-allow` in the log unless one of the built-in checks applies; that is a label, not a rule. Six checks are built into the code and are not entries in `policy.json`: `deny-guard-files`, `ask-guard-paths`, `ask-claude-settings`, `oversize-command`, the `step-cap` ask and `ask-after-injection` (the ask while a session is marked). Rule ids must be unique within one policy file.

**shipped policy** — The `policy.json` in the plugin folder. It always loads first, and it must pass the schema and have `step_cap.max_calls`. Nothing the user adds can remove or loosen its rules.

**added policy file** — A policy file the user adds: `${CLAUDE_PLUGIN_DATA}/policy.json`, or the file named by the `GUARDRAILS_POLICY` environment variable. It is merged into the shipped policy and can only add rules, add `untrusted_tools`, `trusted_tools` and `injection_markers`, or lower the step cap; its `audit` keys are ignored. `trusted_tools` is the one key that turns something off: the injection scan of a tool (its log warning and the note to Claude, never a deny or an ask). A file that is missing (for the environment variable), unreadable or invalid is left out and the calls no rule matches ask (**guardrails-policy-error**).

**guard paths** — The plugin folder, the data folder and the file named by `GUARDRAILS_POLICY`. The write tools and MCP tools are denied on them (`deny-guard-files`), and a Bash command that names one as an absolute or `~` path asks (`ask-guard-paths`). Paths are compared after `~`, `..` and symbolic links are resolved.

**guardrails-policy-error** — The rule id of the ask that a call gets when no rule matched it and an added policy file was left out. The reason names the file and the error. It is logged like any other decision. Not the same as `[guardrails-error]`, the ask for an internal error, which is logged too (rule `guardrails-error`) when the data folder can be written.

**policy** — The set of rules plus the settings around them (`version`, the step cap, which tools are scanned for injection, which are trusted, the injection phrases, the log settings), all in `policy.json`. `policy.schema.json` describes it. The shipped policy always loads; added policy files are merged into it and can only add (the one exception is `trusted_tools`, which turns off the injection scan of a tool: its log warning and the note to Claude). See "Change the rules" in [ARCHITECTURE](docs/ARCHITECTURE.md#change-the-rules).

**deny, ask, allow (and block)** — The hook gives one of three answers to a tool call. **deny**: the call does not run. **ask**: Claude Code asks you first (in interactive bypass mode an ask still showed a prompt in one test on Claude Code 2.1.319: limit 5 in [THREAT_MODEL](docs/THREAT_MODEL.md); nobody can answer in `claude -p`, so the call is refused: limit 6). A rule that says deny gives an ask for a shell command (Bash, PowerShell, Monitor), because shell text can be spelled in ways no rule matches; a file or MCP tool call keeps the deny. **allow**: the hook prints nothing and Claude Code's normal prompts apply, except in bypass mode. What Claude Code does with each answer is its documented behaviour and is not tested here. **block** is what Claude Code should do when the hook itself cannot run (see **fail open** for the version and test caveat): it stops the call, like deny.

**step and step cap** — The step number of a call is how many calls the session has made so far, counting this one (every call counts once the rules have decided it). The step cap is the check that, past step 200 in one session (200 is the value in the shipped `policy.json`, and the shipped policy must have a `step_cap`; an added policy file can only lower it; the demo uses 3), turns a call that matches no rule from allow into ask. The same call is allowed at step 200 and asks at step 201. The cap is soft: parallel calls can share a step number, and if Claude Code sends no session id all sessions share one counter (see "Audit and state" in [ARCHITECTURE](docs/ARCHITECTURE.md)). This is a "step" of a session, not a step of CI (see **pipeline**).

**audit log** — The file the plugin writes, one JSON object per line (see **JSONL**), in the `audit/` folder of the data folder. It records denies and asks (an ask caused by an internal error too: its reason starts with `[guardrails-error]` in Claude Code and the line has rule `guardrails-error`), and a result line for each call that reaches the Post script, a failed call included, when it succeeds. When the data folder cannot be written, an error ask has no line and the result line of an approved call shows decision `unknown`. Every line is plain ASCII. See "Limits of the log" in [THREAT_MODEL](docs/THREAT_MODEL.md).

**data folder** — The folder Claude Code gives the plugin through `${CLAUDE_PLUGIN_DATA}`. It is outside the plugin folder and survives plugin updates (as Claude Code documents it; not tested here). The plugin keeps its log (`audit/`), its counters (`state/`) and an optional `policy.json` of your own there.

**session** — One run of Claude Code, with its own session id. The step counter is kept per session (a file `state/<session>.calls`), except when no session id is sent: see **step and step cap**.

**state files** — Small files in `state/` in the data folder: `<session>.calls` counts the calls and `<session>.decisions` (the "memo") records what Pre decided so Post can read it.

**Pre and Post** — Short forms for the two scripts, `hooks/pre_tool_use.py` (the PreToolUse hook) and `hooks/post_tool_use.py` (the PostToolUse hook). A **decision line** in the log is written by Pre for a deny or ask; a **result line** is written by Post after a call ran.

**redaction** — Replacing a secret with a marker such as `[REDACTED:github-token]` before the text is written to the log. It works on seven known key formats only (the AWS secret key only after the label `aws_secret_access_key`, in any case, followed by `=` or `:` with only white space between; not in the quoted JSON form, and not a bare secret).

**prompt injection** — Text in a web page or a tool result that tries to give the agent new orders. Here the plugin scans for the six phrases in the shipped `policy.json` in the output of every tool not listed in `trusted_tools` (failed calls too; what it misses: limit 2 in [THREAT_MODEL](docs/THREAT_MODEL.md)). On a hit it tells Claude the result is data, not instructions, and shows you a notice. It does not remove the text. The scan is a signal, not a shield.

**flagged result** — A tool result in which the injection scan found a marker. The log line has `warned: true` (a note was sent to Claude).

**marked session** — A session in which a flagged result came from a tool that reads outside content (WebFetch, WebSearch, an MCP read tool: the `untrusted_tools` patterns). The plugin keeps the mark in `state/<session id>.taint`. While it is set, every tool except the local-file ones asks (rule `ask-after-injection`). It ends with the session id, or when you delete the file. The log field is `tainted`.

**isolation** — Here: an opt-in layer, off by default, that keeps shell commands away from the listed secret files by using Claude Code's own Bash sandbox, not by matching text. It is switched on with `"isolation": true` in an added policy file. It needs **the block** in the project, and it adds the **tripwire**, a check for links, and redaction of known secret formats in shell output. It breaks `ssh` and needs user namespaces, which is why it is opt-in. See "Isolation (opt-in)" in [ARCHITECTURE](docs/ARCHITECTURE.md#isolation-opt-in).

**the block** — The sandbox settings (`sandbox.filesystem.denyRead` and a few flags) that this plugin generates from the secret rules of `policy.json` (`make isolation`) and ships as `isolation/settings.local.json`. The user copies it into a project's `.claude/settings.local.json`. A hidden file gives `Permission denied` and a hidden folder shows as empty. The block never sets `network.allowAllUnixSockets`, `filesystem.allowWrite` or `network.allowedDomains`.

**tripwire** — A check that warns of a user mistake and does not stop a determined attacker. Here two exist. The guard-paths tripwire (`ask-guard-paths`): a Bash command that names a guard path asks. The isolation tripwire (`isolation-not-active`): with isolation on, Pre denies a Bash, PowerShell or Monitor call when the block is not in force in the project's settings files, or when a project setting adds a sandbox write path or host (`allowWrite`, `permissions.additionalDirectories`, an `Edit` allow rule, `allowedDomains`, a `WebFetch(domain:...)` allow rule). Both are bypassed by forms they cannot see.
