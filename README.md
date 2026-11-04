# agent-guardrails

[![CI](https://github.com/jdgafx/agent-guardrails/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jdgafx/agent-guardrails/actions/workflows/ci.yml)

A Claude Code plugin that checks every tool call the agent makes, before it runs.
It denies the dangerous ones, asks you about the risky ones, and writes a private log of what happened.

It uses only the Python standard library. No API key. No network. No pip install.

## The seven controls

| # | Control | What it does | Where |
|---|---------|--------------|-------|
| 1 | Least privilege (deny) | Blocks `.env` files, private keys, cloud and SSH credentials, production paths, force pushes. One editable `policy.json` holds all rules. A rule is **deny** or **ask**; everything that matches no rule is allowed. The strongest match wins (deny beats ask). | `deny-*` rules, `policy.json`, `rules.py` |
| 2 | Approval gates (ask) | Stops and asks you before `git push`, recursive `rm`, `git reset --hard`, `terraform apply`, `kubectl apply`, production deploys, package publish, MCP tools that send or delete, and any Bash command over 20000 characters. | `ask-*` rules, `oversize-command` |
| 3 | Audit trail | One JSON line per decision or result, file mode 0600, under `${CLAUDE_PLUGIN_DATA}/audit/`. | `audit.py` |
| 4 | Step cap | After 200 calls in one session, any call with no other rule switches to **ask**. | `step-cap` rule |
| 5 | Secret redaction | Seven key formats are replaced with `[REDACTED:kind]` before anything is written to the log. | `redact.py` |
| 6 | Untrusted input | Text from web and MCP read tools is scanned for injection phrases. A warning goes in the log. Nothing is added to the conversation. | `injection.py` |
| 7 | Fail safe | An internal error, bad input, or a state file that cannot be written gives **ask**, never allow. A deny stays a deny. If the hook cannot start (no `python3`), crashes outside its own error handling, or times out, `"onFailure": "block"` in `hooks.json` makes Claude Code block the call. That setting needs Claude Code 2.1.295 or later. | `hooks.py`, `hooks.json` |

## Try it in 10 seconds (no Claude session needed)

```
make demo
```

This feeds 24 fixture tool calls to the real hook scripts and prints the decision for each:

```
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

(The demo uses a step cap of 3 so you can see the cap fire. The real default is 200. The key in row 18 is a fake built at run time.)

## Install

Try it in a throwaway session, nothing installed:

```
claude --plugin-dir packages/guardrails-plugin
```

Or install it from this repo:

```
/plugin marketplace add jdgafx/agent-guardrails
/plugin install agent-guardrails@agent-guardrails
```

The plugin folder is self-contained. You can copy `packages/guardrails-plugin` anywhere and it works with the stock `python3` on your PATH (3.8 or newer is the design target; I tested 3.12 and 3.14).

## Real log from a real session

I ran `claude -p` (Haiku) with `--plugin-dir packages/guardrails-plugin` and told it to read a `.env` file, run `git push origin main`, and run `ls`. These are three lines from the audit file the plugin wrote, copied as written (I left out only the first line, an allowed read of my prompt file):

```json
{"ts": "2026-10-25T22:55:13Z", "session_id": "092e3bfc-6908-4866-8f6a-fc8874c50da8", "tool_name": "Read", "tool_use_id": "toolu_015j8TNTLXykJHQ7beYmVD67", "event": "decision", "decision": "deny", "rule": "deny-env-files", "step": 2, "input": {"file_path": "/tmp/ag-live/.env"}, "reason": "Environment files hold secrets. Claude may not read or touch them.", "gen_ai.tool.name": "Read", "gen_ai.tool.call.id": "toolu_015j8TNTLXykJHQ7beYmVD67", "gen_ai.conversation.id": "092e3bfc-6908-4866-8f6a-fc8874c50da8"}
{"ts": "2026-10-25T22:55:14Z", "session_id": "092e3bfc-6908-4866-8f6a-fc8874c50da8", "tool_name": "Bash", "tool_use_id": "toolu_011jjerSfvDs1vqytJDTFkrW", "event": "decision", "decision": "ask", "rule": "ask-git-push", "step": 3, "input": {"command": "git push origin main", "description": "Push local main branch to origin"}, "reason": "A push publishes commits. Confirm the branch.", "gen_ai.tool.name": "Bash", "gen_ai.tool.call.id": "toolu_011jjerSfvDs1vqytJDTFkrW", "gen_ai.conversation.id": "092e3bfc-6908-4866-8f6a-fc8874c50da8"}
{"ts": "2026-10-25T22:55:14Z", "session_id": "092e3bfc-6908-4866-8f6a-fc8874c50da8", "tool_name": "Bash", "tool_use_id": "toolu_01JrVTEMMsNazQoJM8Z3f77B", "event": "result", "decision": "allow", "rule": "default-allow", "step": 4, "input": {"command": "ls /tmp/ag-live", "description": "List files in /tmp/ag-live"}, "result_bytes": 104, "status": "ok", "warnings": [], "gen_ai.tool.name": "Bash", "gen_ai.tool.call.id": "toolu_01JrVTEMMsNazQoJM8Z3f77B", "gen_ai.conversation.id": "092e3bfc-6908-4866-8f6a-fc8874c50da8"}
```

What happened in that session:
- The `.env` read was **denied**. Claude said it was blocked and did not try another way.
- The `git push` was **asked**. In `-p` (headless) mode nobody can answer, so the push did not run.
- The `ls` ran. Step 1 (reading the prompt file) was also allowed and logged as a `result` line.

## Audit log format

- Path: `${CLAUDE_PLUGIN_DATA}/audit/YYYY-MM-DD.jsonl` (UTC date). Folder mode 0700, file mode 0600.
- `event: "decision"` lines come from the PreToolUse hook. Only deny and ask are written there.
- `event: "result"` lines come from the PostToolUse hook, for every call that ran. They carry the decision, rule and step that PreToolUse recorded.
- Secrets in the input are replaced with `[REDACTED:<kind>]` before writing. Kinds: private-key, anthropic-key, openai-key, aws-access-key, aws-secret-key, github-token, bearer-token.
- Inputs longer than 2000 characters are cut.
- Field names `gen_ai.tool.name`, `gen_ai.tool.call.id` and `gen_ai.conversation.id` follow the OpenTelemetry GenAI naming style. There is no exporter.

## Change the rules

The hook looks for a policy in this order:
1. The file named in the `GUARDRAILS_POLICY` environment variable.
2. `${CLAUDE_PLUGIN_DATA}/policy.json`.
3. The `policy.json` that ships in the plugin.

`policy.schema.json` describes the format. A bad policy file makes the hook ask, not allow.

## What this does not do (read this)

- **No spend cap.** It counts calls, not money. Use your provider's limits for spend.
- **The step cap is soft.** Parallel calls can share a step number.
- **It only sees tool calls.** It does not stop the model from saying things. It does not protect against attacks from outside Claude Code (a malicious package you install yourself, for example).
- **Untrusted output is scanned and logged, not blocked.** A web page can still talk to the model. The plugin tells you it tried; it does not stop the model reading it.
- **Pattern rules can be bypassed** by a clever command (an encoded string, a script that reads the file). They stop the common and the accidental, not a determined attacker. See `docs/THREAT_MODEL.md`.
- **Bypass mode.** I did not verify what `ask` does when Claude Code runs with permissions bypassed. Treat deny as the only hard stop there.
- **Over-matching.** The `*/prod/*` rule denies any absolute path with a `prod` folder. For Bash, every word of the command is treated as a possible path, so `git commit -m "fix production/config"` is denied by `*/production/*`. The MCP write rule is a name pattern and may ask for harmless tools.
- **Needs Claude Code 2.1.295 or later for the hard fail-safe.** On older versions `onFailure` is ignored, and a hook that cannot start or times out lets the call through. The plugin also needs `python3` on PATH. Without it, 2.1.295 and later block every call; older versions allow them.
- **Long commands ask.** A Bash command over 20000 characters is not checked by the rules. It always gets **ask** (rule `oversize-command`), even if it holds a deny pattern.
- **Logs are partial.** If you decline an ask, only the `decision` line exists. Allowed calls that never ran are not logged. State files in `state/` are not cleaned up.

## Develop

```
make lint     # ruff
make test     # unit + end-to-end + the acceptance check (runs make build first)
make demo     # the table above
make build    # copy packages/guardrails-core into the plugin's vendor/ folder
```

Needs `uv` (https://docs.astral.sh/uv/). Run `make build` after you edit core, and commit the result. A test fails if the copy drifts.

More: [ARCHITECTURE](docs/ARCHITECTURE.md) · [THREAT_MODEL](docs/THREAT_MODEL.md) · [GLOSSARY](GLOSSARY.md)

License: MIT.
