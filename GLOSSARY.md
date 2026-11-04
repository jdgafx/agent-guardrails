# Glossary

Plain-English meanings, with where each one shows up in this repo.

**monorepo** — One git repository that holds several related projects. Here: core, plugin and demo live together in `packages/`.

**workspace** — A set of packages that one tool manages together. Here: a `uv` workspace. The root `pyproject.toml` has `[tool.uv.workspace]`, and the workspace lists all three packages. `uv run` installs core and demo; the plugin is a member that is never installed.

**package** — A folder of code with its own name, version and `pyproject.toml`. Here: `guardrails-core`, `guardrails-plugin`, `guardrails-demo`.

**dependency** — Code your code needs from somewhere else. Here: the core has none (only the Python standard library). The plugin needs the core, and gets it by vendoring (next entry). The dev tools (pytest, ruff, jsonschema) are only for development.

**vendoring** — Copying a dependency's code into your own project, so it does not need to be installed. Here: `make build` copies core into `packages/guardrails-plugin/vendor/`, so the plugin runs from a plain folder copy.

**CI** (continuous integration) — An automated job that runs your checks on every push and pull request. Here: GitHub Actions, in `.github/workflows/ci.yml`. The badge in the README shows its last result.

**pipeline** — The ordered steps CI runs. Here: five steps in `ci.yml`: check that the vendored copy is up to date (`make build`, then a `git diff`), lint, test, demo, and check that `plugin.json` and `hooks.json` parse. If a step fails, the run fails.

**lint** — An automatic check of code style and likely mistakes, without running the code. Here: `ruff`, run with `make lint`.

**unit test** — A test of one small piece in isolation. Here: `tests/unit/test_core.py` tests rules, redaction, the step cap and policy checks one by one. `tests/unit/test_t012_docs.py` tests the docs, not the code: it checks that required wording is present in `docs/THREAT_MODEL.md` and `docs/ARCHITECTURE.md`, that removed wording is gone, and that the numbers and test names they give are real (`t012` is a work-item id from the project's own tracker, which is not in this repo).

**end-to-end test** — A test that runs the whole thing the way a user would. Here: `tests/e2e/` copies the plugin folder and runs the real hook commands from `hooks.json` with the stock `python3`.

**fixture** — A fixed sample input used in tests or demos. Here: `fixtures.json` holds the 24 sample tool calls (see **tool call**) for `make demo`. The fake key is built at run time, so no key-shaped text sits in the repo.

**hook** — A small program that Claude Code runs at a set moment. Here: `PreToolUse` runs before a tool, `PostToolUse` runs after. The hook reads JSON on stdin. To deny or ask it prints a JSON answer on stdout; to allow it prints nothing.

**plugin** — A folder that adds features to Claude Code. Here: `packages/guardrails-plugin`. Claude Code reads its manifest and loads its hooks.

**manifest** — A small file that describes a package or plugin to the tool that loads it. Here: `packages/guardrails-plugin/.claude-plugin/plugin.json` (the plugin) and `.claude-plugin/marketplace.json` at the repo root (it lets `/plugin marketplace add` use this repo as a place to install from).

**schema** — A written description of what a data file may contain. Here: `policy.schema.json` describes `policy.json`. A test checks the policy against it.

**JSONL** — "JSON Lines": a text file with one JSON object per line. Easy to append to and to read with `grep` or `jq`. Here: the audit log.

**idempotent** — Doing it twice has the same result as doing it once. Here: `make build` can run any number of times and gives the same vendored copy. (The hook is not idempotent: each run appends to the state files in the data folder, and a deny or ask also appends to the log. It is deterministic: the same call, policy and step number give the same decision. See **step cap** for why the step number matters.)

**fail open** — When the guard breaks, let everything through. Easy to build, and unsafe. Claude Code does this by default when a hook cannot start or times out. This plugin sets `"onFailure": "block"` on its PreToolUse hook in `hooks.json` to turn it off (Claude Code 2.1.295 or later; per the release notes, not tested here). On older versions it still fails open.

**fail closed** — When the guard breaks, stop. Here an error inside the PreToolUse script gives **ask** (a person decides). A PreToolUse hook that cannot start or times out should be **blocked** by Claude Code (2.1.295 or later; per its release notes, not tested here), through the `onFailure` setting named under **fail open**. Blocked means the call is stopped with no question, documented to have the same effect as **deny**. A PostToolUse failure blocks nothing and writes no log line. A deny stays a deny only if the error comes after the rules ran; if the policy or data folder is broken, every call asks, even one a rule would deny.

**least privilege** — Give the agent only the access it needs. Here the plugin only approximates this: it denies a short list (secrets, production), asks about risky actions, and allows everything else. That is a denylist, which allows anything it does not name; an allowlist denies anything it does not name.

**blast radius** — How much damage one mistake can do. Here: the rules aim to stop a common or accidental wrong command from touching listed secrets, shared history or production without a person seeing it first (an ask is not a stop in bypass mode; see **bypass mode**). A command the rules do not list runs, and the agent can edit the guard, so the radius is smaller, not zero (see limits 5 and 7 in [THREAT_MODEL](docs/THREAT_MODEL.md)).

**MCP** — Model Context Protocol: a standard way to plug extra tools into Claude Code. MCP tool names look like `mcp__<server>__<tool>`.

**bypass mode** — A Claude Code mode with permission checks switched off (`--dangerously-skip-permissions`). Here, treat deny as the only hard stop in that mode.

The entries below are terms specific to this plugin.

**tool call** — One thing Claude does through a tool: read a file, run a shell command, fetch a page. Claude Code gives the hook the tool's name and input as JSON before the call, and the result after it.

**rule** — One entry in `policy.json`: an `id`, a `kind` (path, command or tool name), a decision (deny or ask), what to match and a reason. Rule ids: `deny-env-files`, `ask-git-push`. Two checks are built into the code and are not entries in `policy.json`: `oversize-command` and the `step-cap` ask.

**policy** — The set of rules plus the settings around them (the step cap, which tools count as untrusted, the injection phrases, the log settings), all in `policy.json`. `policy.schema.json` describes it. The first policy file found is used whole; see "Change the rules" in the README.

**deny, ask, allow** — The three answers to a tool call. **deny**: the call does not run. **ask**: Claude Code asks you first. **allow**: the hook prints nothing and Claude Code's normal prompts apply (Claude Code's documented behaviour, not tested here). **block** is what Claude Code does when the hook itself cannot run: it stops the call, like deny.

**step and step cap** — The step number of a call is how many calls the session has made so far, counting this one (every call counts). The step cap is the rule that, past step 200 in one session (200 is the default in `policy.json`; the demo uses 3), turns a call that matches no rule from allow into ask. The same call is allowed at step 200 and asks at step 201. The cap is soft: parallel calls can share a step number, and if Claude Code sends no session id all sessions share one counter (see "Limits of the log" in [THREAT_MODEL](docs/THREAT_MODEL.md)). This is a "step" of a session, not a step of CI (see **pipeline**).

**audit log** — The file the plugin writes, one JSON object per line (see **JSONL**), in the `audit/` folder of the data folder. It records denies and asks (not an ask caused by an internal error), and a result line for each call that ran when the Post script succeeds. See "Limits of the log" in [THREAT_MODEL](docs/THREAT_MODEL.md).

**data folder** — The folder Claude Code gives the plugin through `${CLAUDE_PLUGIN_DATA}`. It is outside the plugin folder and survives plugin updates. The plugin keeps its log (`audit/`), its counters (`state/`) and an optional `policy.json` of your own there.

**redaction** — Replacing a secret with a marker such as `[REDACTED:github-token]` before the text is written to the log. It works on seven known key formats only.

**prompt injection** — Text in a web page or a tool result that tries to give the agent new orders. Here the plugin scans for six known phrases in the output of web and MCP read tools only (not Bash or Read output) and writes a warning to the log. It does not remove the text.
