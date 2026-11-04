# agent-guardrails

[![CI](https://github.com/jdgafx/agent-guardrails/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jdgafx/agent-guardrails/actions/workflows/ci.yml)

A Claude Code plugin that checks every tool call the agent makes, before it runs.
It denies the dangerous ones on its list, asks you about the risky ones on its list, and writes a log that only you can read (file mode 0600) of what happened. A command that is on no list is allowed. "What this does not do" below lists the known gaps.

Why a hook with a denylist, and not Claude Code's own `permissions.deny` and sandbox or an allowlist? The reasons and the rejected options are in [ARCHITECTURE](docs/ARCHITECTURE.md) ("How this relates to Claude Code's own controls" and "Cuts").

It uses only the Python standard library. No API key. No network. No pip install.

## The seven controls

Words used here (hook, policy, step cap, deny, ask, allow, MCP, bypass mode) are defined in [GLOSSARY](GLOSSARY.md).

| # | Control | What it does | Where |
|---|---------|--------------|-------|
| 1 | Denylist (deny) | Blocks `.env` files, private keys, cloud and SSH credentials, production paths, and force pushes written as `git push --force` (not `git -C repo push --force`). One editable `policy.json` holds all rules. A rule is **deny** or **ask**; everything that matches no rule is allowed. The strongest match wins (deny beats ask). | `deny-*` rules, `policy.json`, `rules.py` |
| 2 | Approval gates (ask) | Stops and asks you before `git push`, recursive `rm`, `git reset --hard`, `terraform apply` and `destroy`, `kubectl apply` and `delete`, `vercel --prod`, package publish, MCP tools with a name part that starts with `send`, `delete`, `pay`, `charge`, `transfer` or `post` right after an underscore, and any Bash command over 20000 characters. Each command rule needs the subcommand right after the program name, so `git -C repo push` and `kubectl -n prod delete pod x` are not asked. | `ask-*` rules, `oversize-command` |
| 3 | Audit trail | One JSON line for each deny, each ask, and each call that ran, file mode 0600, under `${CLAUDE_PLUGIN_DATA}/audit/`. | `audit.py` |
| 4 | Step cap | After 200 calls in one session, any call with no other rule switches to **ask**. | `step-cap` rule |
| 5 | Secret redaction | Seven key formats are replaced with `[REDACTED:kind]` before anything is written to the log. | `redact.py` |
| 6 | Untrusted input | Text from web and MCP read tools is scanned for injection phrases (which tools: limit 2 in [THREAT_MODEL](docs/THREAT_MODEL.md)). Output of Bash commands and of the Read tool is not scanned. A warning goes in the log. Nothing is added to the conversation. | `injection.py` |
| 7 | Fail safe | An internal error, bad input, or a state file that cannot be written gives **ask** instead of allow. If the hook cannot start, crashes, or times out, `"onFailure": "block"` in `hooks.json` should make Claude Code block the call (Claude Code 2.1.295 or later). Details just below. | `hooks.py`, `hooks.json` |

How the fail-safe works. The Pre hook runs these steps in order: read the input, load the policy, count the call (in `state/`, inside the data folder), check the rules, save its decision, write the log. A failure in the first three steps, or inside the rule check, makes the call ask, even a call a rule would deny (a broken policy makes every call ask). A failure in the last two steps keeps a deny a deny and turns an allow into an ask. The `onFailure` behaviour comes from the Claude Code 2.1.295 release notes; only the script's exit code is tested here. It is set on the Pre hook only.

## Try it in 10 seconds (no Claude session needed)

From a clone of this repo, at its root. This needs `make` and `python3`; it does not need `uv`.

```bash
make demo
```

This feeds 24 fixture tool calls to the real hook scripts and prints the decision for each. (The `...` lines below are rows left out of this copy; the command prints all 24.)

```text
#   tool                    input                                           decision  rule                  note
--  ----------------------  ----------------------------------------------  --------  --------------------  ---------------------------------------------------------
1   Read                    {"file_path":"README.md"}                       allow     default-allow
2   Read                    {"file_path":".env"}                            deny      deny-env-files
3   Read                    {"file_path":"/app/.env.production"}            deny      deny-env-files
4   Read                    {"file_path":".env.example"}                    allow     default-allow
5   Bash                    {"command":"cat ~/.ssh/id_rsa"}                 deny      deny-key-files
...
10  Bash                    {"command":"git push origin main"}              ask       ask-git-push
11  Bash                    {"command":"git push --force origin main"}      deny      deny-force-push
12  Bash                    {"command":"rm -rf build"}                      ask       ask-rm-recursive
...
18  Bash                    {"command":"echo [REDACTED:anthropic-key]"}     allow     default-allow        secret redacted in log
19  WebFetch                {"url":"https://example.com/page"}              allow     default-allow        injection warning: ignore-previous (logged, not injected)
...
23  Bash                    {"command":"ls"}                                ask       step-cap
24  Bash                    {"command":"ls"}                                ask       step-cap

24 calls: 10 allow, 8 ask, 6 deny. Step cap for this demo: 3.
All decisions matched the fixtures.
```

(The demo copies the shipped policy into a throwaway data folder and sets `step_cap.max_calls` to 3, so you can see the cap fire. The real default is 200. Rows 20 to 24 share one session, so the counter reaches 4 at row 23; every other row has its own session. The key in row 18 is a fake built at run time.)

## Install

Try it in a throwaway session, nothing installed:

```bash
claude --plugin-dir packages/guardrails-plugin
```

Or install it from this repo:

```text
/plugin marketplace add jdgafx/agent-guardrails
/plugin install agent-guardrails@agent-guardrails
```

(`agent-guardrails@agent-guardrails` is plugin@marketplace.) The plugin needs `python3` on PATH. CI runs on Linux; Windows is not tested.

`--plugin-dir` loads a plugin from a local folder. If you start Claude Code in a project and give it a plugin folder inside that project, the agent can edit the plugin's rules and scripts with its normal file permissions. Install it from the marketplace, or copy it outside the project (see limit 7 in [THREAT_MODEL](docs/THREAT_MODEL.md)).

The plugin folder is self-contained. You can copy `packages/guardrails-plugin` anywhere and it works with the stock `python3` on your PATH (tested on 3.12 and 3.14; the code avoids syntax newer than 3.8, but 3.8 was not run, and the root `pyproject.toml` asks for 3.9 or newer).

## Real log from a real session

I ran `claude -p` (Claude Code's non-interactive print mode, with Haiku) with `--plugin-dir packages/guardrails-plugin` and told it to read a `.env` file, run `git push origin main`, and run `ls`. These are three lines from the audit file the plugin wrote, copied as written (I left out only the first line, an allowed read of my prompt file):

```json
{"ts": "2026-10-25T22:55:13Z", "session_id": "092e3bfc-6908-4866-8f6a-fc8874c50da8", "tool_name": "Read", "tool_use_id": "toolu_015j8TNTLXykJHQ7beYmVD67", "event": "decision", "decision": "deny", "rule": "deny-env-files", "step": 2, "input": {"file_path": "/tmp/ag-live/.env"}, "reason": "Environment files hold secrets. Claude may not read or touch them.", "gen_ai.tool.name": "Read", "gen_ai.tool.call.id": "toolu_015j8TNTLXykJHQ7beYmVD67", "gen_ai.conversation.id": "092e3bfc-6908-4866-8f6a-fc8874c50da8"}
{"ts": "2026-10-25T22:55:14Z", "session_id": "092e3bfc-6908-4866-8f6a-fc8874c50da8", "tool_name": "Bash", "tool_use_id": "toolu_011jjerSfvDs1vqytJDTFkrW", "event": "decision", "decision": "ask", "rule": "ask-git-push", "step": 3, "input": {"command": "git push origin main", "description": "Push local main branch to origin"}, "reason": "A push publishes commits. Confirm the branch.", "gen_ai.tool.name": "Bash", "gen_ai.tool.call.id": "toolu_011jjerSfvDs1vqytJDTFkrW", "gen_ai.conversation.id": "092e3bfc-6908-4866-8f6a-fc8874c50da8"}
{"ts": "2026-10-25T22:55:14Z", "session_id": "092e3bfc-6908-4866-8f6a-fc8874c50da8", "tool_name": "Bash", "tool_use_id": "toolu_01JrVTEMMsNazQoJM8Z3f77B", "event": "result", "decision": "allow", "rule": "default-allow", "step": 4, "input": {"command": "ls /tmp/ag-live", "description": "List files in /tmp/ag-live"}, "result_bytes": 104, "status": "ok", "warnings": [], "gen_ai.tool.name": "Bash", "gen_ai.tool.call.id": "toolu_01JrVTEMMsNazQoJM8Z3f77B", "gen_ai.conversation.id": "092e3bfc-6908-4866-8f6a-fc8874c50da8"}
```

What happened in that session (a single run, not a test):
- The `.env` read was **denied**.
- The `git push` was **asked**. In `-p` (headless) mode nobody can answer. In this run the push did not run: the log has no result line for it.
- The `ls` ran. Step 1 (reading the prompt file) was also allowed and logged as a `result` line.

## Audit log format

- Path: `${CLAUDE_PLUGIN_DATA}/audit/YYYY-MM-DD.jsonl` (UTC date). Folder mode 0700, file mode 0600. `${CLAUDE_PLUGIN_DATA}` is the data folder: Claude Code sets this variable for plugin hooks, it is outside the plugin folder and it survives plugin updates. The plugin keeps its log (`audit/`) and counters (`state/`) there. Claude Code picks the folder; I did not look up its default path.
- `event: "decision"` lines come from the PreToolUse hook. Only deny and ask are written there.
- `event: "result"` lines come from the PostToolUse hook, for every call that ran. They carry the decision, rule and step that PreToolUse recorded.
- Secrets in the input are replaced with `[REDACTED:<kind>]` before writing and before the 2000-character cut below. Kinds: private-key, anthropic-key, openai-key, aws-access-key, aws-secret-key, github-token, bearer-token.
- If the JSON text of the input is longer than 2000 characters (the default of `audit.max_input_chars` in `policy.json`), the whole `input` field is replaced by `{"truncated": "<the first 2000 characters>"}`.
- Field names `gen_ai.tool.name`, `gen_ai.tool.call.id` and `gen_ai.conversation.id` follow the OpenTelemetry GenAI naming style. There is no exporter.

## Change the rules

The rules live in `policy.json` (the shipped copy is `packages/guardrails-plugin/policy.json`; it holds the patterns and the step cap of 200). Two checks are built into the code, not into `policy.json`: `oversize-command` (the 20000-character limit is a constant in `rules.py`) and the `step-cap` ask itself (only its number, `step_cap.max_calls`, is in `policy.json`).

The hook looks for a policy in this order; the first file that exists is used and the others are ignored:
1. The file named in the `GUARDRAILS_POLICY` environment variable (set it in the environment that starts Claude Code; use an absolute path). If that path does not exist, it is skipped without a message.
2. `${CLAUDE_PLUGIN_DATA}/policy.json`.
3. The `policy.json` that ships in the plugin.

[`policy.schema.json`](packages/guardrails-plugin/policy.schema.json) describes the format. A bad policy file makes the hook ask, not allow (every call asks, even one a rule would deny). The first file found is used whole; it is not merged with the shipped one.

## What this does not do (read this)

- **No spend cap.** It counts calls, not money. Use your provider's limits for spend.
- **The step cap is soft.** Parallel calls can share a step number. If Claude Code sends no session id, all sessions share one counter, so the cap counts every call on the machine.
- **It only sees tool calls.** It does not stop the model from saying things. It does not protect against attacks from outside Claude Code (a malicious package you install yourself, for example).
- **Untrusted output is scanned and logged, not blocked.** A web page can still talk to the model. The plugin writes a warning line in the log (you see nothing in the Claude Code window); it does not stop the model reading the page.
- **Pattern rules can be bypassed** by a crafted command (an encoded string, a script that reads the file). They stop the common and the accidental, not a determined attacker. See [THREAT_MODEL](docs/THREAT_MODEL.md).
- **The agent can edit the guard.** No rule protects `policy.json`, the hook scripts, `vendor/`, the log or Claude Code's settings. An agent that may write files can weaken or switch off the guard. Fix on hold, not built, no date (limit 7 in [THREAT_MODEL](docs/THREAT_MODEL.md)).
- **Nothing controls what leaves the machine.** `curl`, `wget` and WebFetch can send anything the agent has read (limit 8 in [THREAT_MODEL](docs/THREAT_MODEL.md)).
- **Secrets are protected by name, not by content.** The rules block the listed file names. They do not stop `grep -r API_KEY .`, the Grep tool, a directory path such as `~/.ssh`, `printenv`, `curl -d @.env.production`, or credential files not on the list (`~/.netrc`, `~/.npmrc`, `~/.git-credentials`). Fix on hold, not built, no date.
- **Rules match the command text.** `git -C repo push --force` and `git -C repo push` are allowed with no prompt. `kubectl -n prod delete pod x` and `terraform -chdir=infra apply` are allowed too. `gh pr merge`, `docker push`, `helm upgrade` and `git clean -fdx` have no rule. Command rules read only the tool named `Bash`. Fix on hold, not built, no date: widen the regexes in `policy.json`.
- **Bypass mode.** I did not verify what `ask` does when Claude Code runs with permissions bypassed. Treat deny as the only hard stop there.
- **Over-matching.** The `*/prod/*` rule denies any path, absolute or relative, with a `prod` folder. For Bash, every word of the command is treated as a possible path, so `git commit -m "fix production/config"` is denied by `*/production/*`. The MCP write rule is a name pattern and may ask for harmless tools.
- **Needs Claude Code 2.1.295 or later for the hard fail-safe.** Per the 2.1.295 release notes (not tested here), older versions ignore `onFailure`, and a hook that cannot start or times out lets the call through. The plugin also needs `python3` on PATH. Without it, 2.1.295 and later should block every call; older versions allow them.
- **Long commands ask.** A Bash command over 20000 characters is not checked by the rules. It always gets **ask** (rule `oversize-command`), even if it holds a deny pattern.
- **Logs are partial.** If you decline an ask, only the `decision` line exists. Allowed calls that never ran are not logged. An ask caused by an internal error writes no log line. State files in `state/` are not cleaned up.

## Develop

```bash
make lint     # ruff
make test     # unit + end-to-end + acceptance tests, i.e. `uv run pytest` (runs make build first)
make demo     # the table above
make build    # copy packages/guardrails-core into the plugin's vendor/ folder
```

Needs [uv](https://docs.astral.sh/uv/) for `make lint` and `make test`. "Core" is `packages/guardrails-core`, the engine. "Vendor" is its copy in `packages/guardrails-plugin/vendor/`. Run `make build` after you edit core, commit the result, and run `git status` to add any new file under `vendor/`. A direct `uv run pytest` fails if the copy drifts; `make test` rebuilds the copy first, so it cannot catch this. CI runs `git diff --exit-code` on `packages/guardrails-plugin/vendor`, which ignores files git does not track yet.

More: [ARCHITECTURE](docs/ARCHITECTURE.md) · [THREAT_MODEL](docs/THREAT_MODEL.md) · [GLOSSARY](GLOSSARY.md)

License: [MIT](LICENSE).
