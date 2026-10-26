# Glossary

Plain-English meanings, with where each one shows up in this repo.

**monorepo** — One git repository that holds several related projects. Here: core, plugin and demo live together in `packages/`.

**workspace** — A set of packages that one tool manages together. Here: a `uv` workspace. The root `pyproject.toml` has `[tool.uv.workspace]`, and one `uv run` can see all three packages.

**package** — A folder of code with its own name, version and `pyproject.toml`. Here: `guardrails-core`, `guardrails-plugin`, `guardrails-demo`.

**dependency** — Code your code needs from somewhere else. Here: the core has none (only the Python standard library). The dev tools (pytest, ruff, jsonschema) are only for development.

**vendoring** — Copying a dependency's code into your own project, so it does not need to be installed. Here: `make build` copies core into `packages/guardrails-plugin/vendor/`, so the plugin runs from a plain folder copy.

**CI** (continuous integration) — A robot that runs your checks on every push. Here: GitHub Actions, in `.github/workflows/ci.yml`. The badge in the README shows its last result.

**pipeline** — The ordered steps CI runs. Here: build, drift check, lint, test, demo. If a step fails, the run is red.

**lint** — An automatic check of code style and likely mistakes, without running the code. Here: `ruff`, run with `make lint`.

**unit test** — A test of one small piece in isolation. Here: `tests/unit/test_core.py` tests rules, redaction, the step cap and policy checks one by one.

**end-to-end test** — A test that runs the whole thing the way a user would. Here: `tests/e2e/` copies the plugin folder and runs the real hook commands from `hooks.json` with the stock `python3`.

**fixture** — A fixed sample input used in tests or demos. Here: `fixtures.json` holds the 24 sample tool calls for `make demo`. The fake keys are built at run time, so no key-shaped text sits in the repo.

**hook** — A small program that Claude Code runs at a set moment. Here: `PreToolUse` runs before a tool, `PostToolUse` runs after. The hook reads JSON on stdin and answers on stdout.

**plugin** — A folder that adds features to Claude Code. Here: `packages/guardrails-plugin`. Claude Code reads its manifest and loads its hooks.

**manifest** — A small file that describes a package or plugin to the tool that loads it. Here: `.claude-plugin/plugin.json` (the plugin) and `.claude-plugin/marketplace.json` (the repo as an install source).

**schema** — A written description of what a data file may contain. Here: `policy.schema.json` describes `policy.json`. A test checks the policy against it.

**JSONL** — "JSON Lines": a text file with one JSON object per line. Easy to append to and to read with `grep` or `jq`. Here: the audit log.

**idempotent** — Doing it twice has the same result as doing it once. Here: `make build` can run any number of times and gives the same vendored copy. The hook's decision for the same call and policy is also the same each time.

**fail open** — When the guard breaks, let everything through. Easy to build, and unsafe. Claude Code does this by default when a hook cannot start or times out. This plugin turns it off with `"onFailure": "block"` in `hooks.json` (Claude Code 2.1.295 or later). On older versions it still fails open.

**fail closed** — When the guard breaks, stop. Here a hook error inside the script gives **ask** (a person decides). A hook that cannot start or times out is **blocked** by Claude Code. A deny stays a deny.

**least privilege** — Give the agent only the access it needs. Here: secrets and production are denied. Risky actions need a yes. Everything else is allowed.

**blast radius** — How much damage one mistake can do. Here: the rules keep a wrong command from touching secrets, shared history or production without a person seeing it first.
