# agent-guardrails

[![CI](https://github.com/jdgafx/agent-guardrails/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jdgafx/agent-guardrails/actions/workflows/ci.yml)

A Claude Code plugin that checks the tool calls the agent makes, before they run (Claude Code sends each call to the hook).
It denies the calls its rules list as dangerous, asks you about the ones they list as risky, and writes a log of denies, asks and calls that ran (with gaps: see "Logs are partial"). A call that matches no rule is allowed (apart from the built-in checks: `deny-guard-files`, `ask-guard-paths`, `ask-claude-settings`, `oversize-command` and `step-cap`). The plugin creates the log with mode 0600, so other users cannot read it; the agent can. "What this does not do" below lists the main known gaps.

Alternatives set aside, one line each (full reasons: [ARCHITECTURE](docs/ARCHITECTURE.md), "Alternatives at a glance"). An allowlist would block every command not listed. A deny on every internal error would stop all work, so an error asks. Blocking injected text has false positives, and rewriting it makes the model see text that differs from the tool's real output, so it is scanned and logged. Claude Code's own `permissions.deny` and sandbox show no per-rule reason and are not known to keep a per-call decision log (not checked), and they can be used together with this plugin. Isolation (a container or a separate account) is the stronger control for what the rules cannot see, and was not weighed against this plugin. A user's policy file is merged into the shipped policy and can only add: a file that could replace or loosen the shipped rules would let the agent switch the guard off (a full copy that replaced the shipped policy was the old design). `pip` for the engine would need a package-manager step that a plugin install is not expected to run, and a venv is not portable between machines, so the engine is copied in. A small shell tokeniser in place of the regexes was not tried (it would catch quoted flags; see "What this does not do"). The step is counted after the rules, so a deny stays a deny when the counter cannot be written. A built-in minimum deny list for a broken shipped policy is not built.

It uses only the Python standard library. No API key. No network. No pip install.

## The seven controls

Words used here (hook, policy, step cap, deny, ask, allow, MCP, bypass mode) are defined in [GLOSSARY](GLOSSARY.md).

| # | Control | What it does | Where |
|---|---------|--------------|-------|
| 1 | Denylist (deny) | Denies `.env` files, private keys, cloud and SSH credentials, production paths, and force pushes written as `git push` followed by `--force`, `--force-with-lease`, `-f` or `+branch`. The rules are in one editable `policy.json`. A rule is **deny** or **ask**; deny beats ask; a call that matches no rule is allowed; a Bash command over 20000 characters is not checked and always asks. Option words before the subcommand are allowed (`git -C repo push --force` is denied). Gaps (quoted or hidden spellings): see "What this does not do". | `deny-*` rules, `policy.json`, `rules.py` |
| 2 | Approval gates (ask) | Asks you before `git push`, recursive `rm`, `git reset --hard`, `terraform apply` and `destroy`, `kubectl apply` and `delete`, `vercel --prod`, package publish (`npm`, `pnpm` or `yarn publish`, `twine upload`, `cargo publish`, `uv publish`, `gem push`), MCP tools with `send`, `delete`, `post`, `pay`, `charge` or `transfer` at the start of a word of the tool name (`mcp__gmail__send_email`, `mcp__x__bulkDelete` and `mcp__x__make-payment` ask; `mcp__x__get_posts` and `mcp__x__list_payments` do not; the server name does not count), and any Bash command over 20000 characters. Option words may sit before the subcommand (`git -C repo push`, `kubectl -n prod delete`, `terraform -chdir=infra apply`, `npm --tag x publish` all ask). It also asks before `git clean -f`, `gh pr merge`, `gh release create`, `docker push`, `helm install`, `upgrade` and `uninstall`, `find -delete`, a `python -c` one-liner that deletes files, `aws s3 rm`, `cp`, `mv` and `sync`, `aws` operations (the word after the service name, as in `aws ec2 terminate-instances`) starting `delete-`, `put-`, `create-`, `update-` or `terminate-`, and `vercel --target=production`. | `ask-*` rules, `oversize-command` |
| 3 | Audit trail | One JSON line for each deny, each ask, and each call that ran (with gaps: see "Logs are partial" below), file mode 0600, under `${CLAUDE_PLUGIN_DATA}/audit/`. | `audit.py` |
| 4 | Step cap | After 200 calls in one session, any call with no other rule switches to **ask**. | `step-cap` rule |
| 5 | Secret redaction | Seven key formats (the AWS secret key only after `aws_secret_access_key=` or `:`, not in the quoted JSON form) are replaced with `[REDACTED:kind]` before anything is written to the log. | `redact.py` |
| 6 | Untrusted input | Text from web and MCP read tools is scanned for injection phrases (which tools: limit 2 in [THREAT_MODEL](docs/THREAT_MODEL.md)). Output of Bash commands and of the Read tool is not scanned. A warning goes in the log. Nothing is added to the conversation. | `injection.py` |
| 7 | Fail safe | An internal error, bad input or an unwritable state file gives **ask**, not allow, but only for a call no rule denies or asks about: the rules run first, so a deny stays a deny when the data folder is unset, unwritable or a file, or an added policy file is broken. If the hook cannot start, crashes or times out, `"onFailure": "block"` in `hooks.json` should make Claude Code block the call (2.1.295 or later; untested here). See "How the fail-safe works". | `hooks.py`, `hooks.json` |

### How the fail-safe works

The Pre hook runs these steps in order: read the input, check the guard paths (below), load the policy, check the rules, count the call (in `state/`, inside the data folder), save its decision, write the log. The rules run before anything that touches the data folder, so a deny stays a deny and an ask stays an ask when the data folder is unset, a file or read-only. Only a call that no rule matched becomes an ask when it cannot be counted, saved or logged. A shipped policy that cannot load makes every call ask, except the denies on the guard's own files. An added policy file that is missing, unreadable or invalid is left out and the shipped rules still apply (details under "Change the rules").

Three built-in checks guard the guard itself. They compare paths after `~`, `..` and symbolic links are resolved.
- `deny-guard-files`: the Write, Edit, MultiEdit and NotebookEdit tools, and any MCP tool, are denied on a path inside the plugin folder, the data folder or the `GUARDRAILS_POLICY` file. (An MCP tool is denied there even when it only reads; the Read tool is not affected, so you can still read the log with it.) Claude may not edit your policy file either: edit it yourself.
- `ask-guard-paths`: a Bash command asks when one of its words is an absolute or `~` path inside those places, for example `tail ~/.claude/plugins/data/agent-guardrails/audit/x.jsonl` or `sed -i s/deny/ask/ /opt/agent-guardrails/policy.json`. This is a tripwire, not a barrier: see "The agent can still change the guard from the shell" below.
- `ask-claude-settings`: a write tool asks before it changes `.claude/settings.json` or `.claude/settings.local.json` in the project, or the same two files in your home folder (or in `CLAUDE_CONFIG_DIR` when that is set), because those files can switch the plugin off. The `onFailure` setting is on the Pre hook only; its version and test caveat is under "What this does not do".

## Try it (no Claude session needed)

From a clone of this repo, at its root. This needs `make` and `python3` (3.9 or newer); it does not need `uv`. It runs `make build` first (which re-copies `vendor/`).

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
18  Bash                    {"command":"echo [REDACTED:anthropic-key]"}     allow     default-allow         secret redacted in log
19  WebFetch                {"url":"https://example.com/page"}              allow     default-allow         injection warning: ignore-previous (logged, not injected)
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

(`agent-guardrails@agent-guardrails` is plugin@marketplace.) The plugin needs `python3` on PATH. CI runs on Linux; macOS and Windows are not tested. To see your Claude Code version, run `claude --version` (2.1.295 or later is needed for the hard fail-safe).

`--plugin-dir` loads a plugin from a local folder. The write tools are denied on the plugin folder, so with a plugin folder inside your project Claude cannot edit it with them (it also cannot edit the plugin while you develop it in that session). Bash can still write there; install the plugin from the marketplace or copy it outside the project, and see limit 7 of [THREAT_MODEL](docs/THREAT_MODEL.md).

The plugin folder is self-contained. You can copy `packages/guardrails-plugin` anywhere and it is meant to run with the stock `python3` on your PATH. Tested on: 3.12 and 3.14 by hand, and the runner's stock `python3` in CI (version not recorded). The code avoids syntax newer than 3.8, but 3.8 was not run, and the root `pyproject.toml` asks for 3.9 or newer.

## Log from one live session

One `claude -p` run (Claude Code's non-interactive print mode, with Haiku, with `--plugin-dir packages/guardrails-plugin`) was told to read a `.env` file, run `git push origin main`, and run `ls`. These are three lines from the audit file the plugin wrote, copied as written (only the first line, an allowed read of the prompt file, is left out):

```text
{"ts": "2026-10-25T22:55:13Z", "session_id": "092e3bfc-6908-4866-8f6a-fc8874c50da8", "tool_name": "Read", "tool_use_id": "toolu_015j8TNTLXykJHQ7beYmVD67", "event": "decision", "decision": "deny", "rule": "deny-env-files", "step": 2, "input": {"file_path": "/tmp/ag-live/.env"}, "reason": "Environment files hold secrets. Claude may not read or touch them.", "gen_ai.tool.name": "Read", "gen_ai.tool.call.id": "toolu_015j8TNTLXykJHQ7beYmVD67", "gen_ai.conversation.id": "092e3bfc-6908-4866-8f6a-fc8874c50da8"}
{"ts": "2026-10-25T22:55:14Z", "session_id": "092e3bfc-6908-4866-8f6a-fc8874c50da8", "tool_name": "Bash", "tool_use_id": "toolu_011jjerSfvDs1vqytJDTFkrW", "event": "decision", "decision": "ask", "rule": "ask-git-push", "step": 3, "input": {"command": "git push origin main", "description": "Push local main branch to origin"}, "reason": "A push publishes commits. Confirm the branch.", "gen_ai.tool.name": "Bash", "gen_ai.tool.call.id": "toolu_011jjerSfvDs1vqytJDTFkrW", "gen_ai.conversation.id": "092e3bfc-6908-4866-8f6a-fc8874c50da8"}
{"ts": "2026-10-25T22:55:14Z", "session_id": "092e3bfc-6908-4866-8f6a-fc8874c50da8", "tool_name": "Bash", "tool_use_id": "toolu_01JrVTEMMsNazQoJM8Z3f77B", "event": "result", "decision": "allow", "rule": "default-allow", "step": 4, "input": {"command": "ls /tmp/ag-live", "description": "List files in /tmp/ag-live"}, "result_bytes": 104, "status": "ok", "warnings": [], "gen_ai.tool.name": "Bash", "gen_ai.tool.call.id": "toolu_01JrVTEMMsNazQoJM8Z3f77B", "gen_ai.conversation.id": "092e3bfc-6908-4866-8f6a-fc8874c50da8"}
```

What happened in that session (a single run, not a test):
- The `.env` read was **denied**.
- The `git push` was **asked**. In `-p` (headless) mode nobody can answer. The log has no result line for the push, so it probably did not run (a result line is also missing when the Post script fails).
- The `ls` ran. Step 1 (reading the prompt file) was also allowed and logged as a `result` line.

## Audit log format

- Path: `${CLAUDE_PLUGIN_DATA}/audit/YYYY-MM-DD.jsonl` (UTC date). Folder mode 0700, file mode 0600 when the plugin creates them (an existing folder or file keeps its mode). `${CLAUDE_PLUGIN_DATA}` is the data folder: Claude Code sets this variable for plugin hooks, it is outside the plugin folder and it survives plugin updates (as Claude Code documents it; not tested here). The plugin keeps its log (`audit/`) and counters (`state/`) there. Claude Code picks the folder. For plugins installed from a marketplace, the data folders on one Linux machine were under `~/.claude/plugins/data/<plugin>-<marketplace>/`.
- `event: "decision"` lines come from the PreToolUse hook. Only deny and ask are written there.
- `event: "result"` lines come from the PostToolUse hook, for every call that ran when the Post script works (if it fails, the call leaves no result line). They carry the decision, rule and step that PreToolUse recorded.
- Secrets in the input are replaced with `[REDACTED:<kind>]` before writing and before the 2000-character cut below. Kinds: private-key, anthropic-key, openai-key, aws-access-key, aws-secret-key, github-token, bearer-token.
- If the JSON text of the input is longer than 2000 characters (the default of `audit.max_input_chars` in `policy.json`), the whole `input` field is replaced by `{"truncated": "<the first 2000 characters>"}`.
- Field names `gen_ai.tool.name`, `gen_ai.tool.call.id` and `gen_ai.conversation.id` follow the OpenTelemetry GenAI naming style. There is no exporter. Setting `audit.otel_field_names` to false in `policy.json` leaves the three fields out.

## Change the rules

The rules live in `policy.json` (the shipped copy is `packages/guardrails-plugin/policy.json`; it holds the patterns and the step cap of 200). Five checks are built into the code, not into `policy.json`: `deny-guard-files`, `ask-guard-paths` and `ask-claude-settings` (see "How the fail-safe works"), `oversize-command` (the 20000-character limit is a constant in `rules.py`) and the `step-cap` ask itself (only its number, `step_cap.max_calls`, is in `policy.json`).

The shipped policy always loads first. Your own policy files are added to it, and they can only add:
1. The file named in the `GUARDRAILS_POLICY` environment variable (set it in the environment that starts Claude Code; use an absolute path).
2. `${CLAUDE_PLUGIN_DATA}/policy.json`.

Both are optional and both are used if both exist. A missing or broken added policy file is left out, the shipped rules still apply, and calls no rule matches ask. The ask names the file and the error (rule `guardrails-policy-error`) until you fix or remove the file. A `GUARDRAILS_POLICY` that names a missing path or a folder counts as broken; no file at all in the data folder is normal. A file in the data folder that is a folder, a dangling link or a pipe is broken too.

What an added file can do:
- Add rules. Shipped rules run first; the strongest rule that matches wins (deny over ask). An added rule cannot weaken or remove a shipped one, and it cannot turn a shipped deny into an ask. To relax a rule you must edit the shipped file by hand (a plugin update undoes that edit).
- Lower the step cap with `step_cap.max_calls`. A higher value is ignored.
- Add `untrusted_tools` names and `injection_markers`. This makes more output scanned.
- `audit` keys in an added file are ignored: a smaller value would weaken the log.

You no longer need a full copy of the shipped file, only your added rules. If you made a full copy earlier, it still loads (its rules sit beside the shipped ones), but a copy that fails the check below is left out.

[`policy.schema.json`](packages/guardrails-plugin/policy.schema.json) describes the format, and the hook checks every policy file against all of it: wrong types, unknown keys, a `version` other than the whole number 1 (`true` and `1.0` fail), a text `except`, an empty `rules` list. The shipped policy must also have `step_cap.max_calls`.

To add a rule:
1. Write `${CLAUDE_PLUGIN_DATA}/policy.json` (or keep the file anywhere and point `GUARDRAILS_POLICY` at its absolute path) with `{"version": 1, "rules": [...]}`. Claude cannot write these files for you: the write tools are denied there, so edit them yourself.
2. A rule has an `id`, a `decision`, a `kind` (`path`, `command` or `tool`), `match` patterns and a `reason`, and, for `path` rules only, may have an `except` list that excuses matches. On a `command` or `tool` rule `except` is ignored without a message; change its `match` pattern instead. Rule ids must be unique within a file.
3. The policy is read on every hook call, so the change takes effect at once. If the file is wrong, the next call that no rule matches asks and says why.

A new regex is checked to compile, not to be fast, and the hook times out after 10 seconds. The shipped rules come first and the rule loop stops at the first deny, so a slow regex in your file cannot delay a shipped deny. It can delay an ask or an allow past the timeout. Deleting your policy file removes its rules with no message. Changing the 20000-character limit means editing core and running `make build`.

Release note for upgrades: check your own policy file against the schema. You no longer need a full copy of the shipped file, only your added rules. A copy that breaks the strict check (for example a `$schema` key added for an editor) is left out, and calls no rule matches ask until you fix it.

## What this does not do

T-006 to T-009 below are work-item ids from the project's own tracker (they are not in this repo). T-006 (command spellings and missing commands) and T-007 (the guard protects itself) are built. "Fix not built yet" means a fix is written down in the tracker and is not built.

- **No spend cap.** It counts calls, not money. Use your provider's limits for spend.
- **The step cap is soft.** Parallel calls can share a step number. If Claude Code sends no session id (or a JSON `null` one), every such call shares one counter file (`state/unknown.calls`, or `state/None.calls`), so the cap counts every call that uses this plugin's data folder, across all sessions and days. Delete that file to reset it.
- **It only sees tool calls.** It does not stop the model from saying things. It does not protect against attacks from outside Claude Code (a malicious package you install yourself, a script the agent writes and runs; limit 3 in [THREAT_MODEL](docs/THREAT_MODEL.md)). Use a container or a separate user for those.
- **Untrusted output is scanned and logged, not blocked.** A web page can still talk to the model. The plugin writes a warning line in the log (you see nothing in the Claude Code window); it does not stop the model reading the page. To limit what an injected order can reach, run the agent in a container or as a separate user with no access to your secrets (limit 2 in [THREAT_MODEL](docs/THREAT_MODEL.md)); a wider scan is a fix not built yet (T-009).
- **Pattern rules can be bypassed** by a crafted command (an encoded string, a script that reads the file). They stop the listed commands and file names in the listed spellings, not a determined attacker. For hard isolation use a container or a separate user (limit 4 in [THREAT_MODEL](docs/THREAT_MODEL.md)).
- **The agent can still change the guard from the shell (limit 7 in [THREAT_MODEL](docs/THREAT_MODEL.md)).** The write tools are denied on the guard's files, and an added policy file can only add rules. A Bash command can still write a file in many ways (a redirect, `sed -i`, `python3 -c`, a path in a variable, a relative path after `cd`), so matching on the command text can never catch all of them, and the plugin does not try. Only a command that names a guard path as an absolute or `~` path asks. Such a write can rewrite the shipped policy, the hook scripts or `vendor/`, delete an added policy file or the step counter, edit the log, or add a slow regex. Examples that are allowed: `rm "$CLAUDE_PLUGIN_DATA"/state/s.calls`, `cd ~/.claude/plugins/data && rm agent-guardrails/policy.json`, a guard path with a space, a quote or a backslash in it (the command is split into words there), a glob such as `~/.claude/plugins/data/*/policy.json`, and a parent folder such as `mv ~/.claude/plugins/data /tmp/x`. The barrier meant for these writes is Claude Code's own Bash sandbox with unsandboxed commands switched off (`sandbox.enabled` true and `sandbox.allowUnsandboxedCommands` false; per the Claude Code docs, Claude Code then ignores `dangerouslyDisableSandbox`), plus `permissions.deny` rules such as `Edit(//path/to/plugin/**)` for the plugin folder and the data folder. **Not tested here.** The sandbox limits writes to the working folder, so it does not cover a plugin folder inside the project; install the plugin outside the project. Also not covered: Python start-up files in an activated virtualenv inside the project (limit 7), and a repository's own Claude Code settings beyond the `ask-claude-settings` check.
- **Nothing controls what leaves the machine.** `curl`, `wget` and WebFetch can send anything the agent has read (limit 8 in [THREAT_MODEL](docs/THREAT_MODEL.md)).
- **Secrets are protected by name, not by content.** The rules deny the listed file names. They do not stop `grep -r API_KEY .`, a content search with the Grep tool, or `printenv`, and no fix is written down for content search or environment variables. Also not denied: a directory path such as `~/.ssh`, the Grep tool's `glob` field, credential files not on the list (`~/.netrc`, `~/.npmrc`, `~/.git-credentials`) and names glued to other characters (`curl -d @.env.production`). Fix not built yet (T-008) for these.
- **Rules match the command text.** Option words before the subcommand are seen (`git -C repo push --force` is denied), up to 8 of them. Quoted or hidden spellings are not: `"rm" -r x` and `git "push" -f` are allowed, `git push "-f"` and `bash -c "git push -f"` ask instead of denying, and `vercel` with `--prod` on the next line is allowed. `rm -f`, `kubectl patch`, `docker buildx build --push` and a script that deletes files have no rule. Command rules and the word-by-word file-name check read only the tool named `Bash` (`cat .env` sent through another shell tool is allowed). The limits are listed once in "Gaps in the rules" in [THREAT_MODEL](docs/THREAT_MODEL.md) (T-006 in the project's tracker). For other tool names no fix is written down.
- **An MCP tool name that starts with a reading word can hide a money-moving word.** The MCP rule excuses a name that starts with a reading word (`get`, `list`, `find`, `search`, `fetch`...) followed directly by a write word, and it then excuses every later write word in the name too. `mcp__x__get_payment_then_transfer` and `mcp__x__list_payments_and_charge` are allowed, although they move money. The rule does not ask on them.
- **Bypass mode.** Not verified: what `ask` or `deny` does when Claude Code runs with permissions bypassed. Assume only deny is a hard stop there, and that this plugin can turn a deny into an ask (a command padded past 20000 characters; limit 5 in [THREAT_MODEL](docs/THREAT_MODEL.md)). Put what must never run in Claude Code's own `permissions.deny` too (check its release notes first; see "How this relates to Claude Code's own controls" in [ARCHITECTURE](docs/ARCHITECTURE.md)).
- **Over-matching.** The `deny-prod-config` patterns `*/prod/*` and `*/production/*` deny any path, absolute or relative, with a `prod` or `production` folder. For Bash, every word of the command is treated as a possible path, so `git commit -m "fix production/config"` is denied by `*/production/*`. Other false positives are listed in "Known false positives" in [THREAT_MODEL](docs/THREAT_MODEL.md) (for example `echo .env >> .gitignore` is denied). The MCP write rule is a name pattern and may ask for harmless tools (`mcp__x__postal_lookup`, `mcp__x__payment_status` and `mcp__x__get_user_payments` ask; the server name does not count, so `mcp__my_sender__list` is allowed); `except` does not work on it (see "Change the rules"), so narrow its `match` pattern.
- **Needs Claude Code 2.1.295 or later for the hard fail-safe.** Older versions have no `onFailure` setting (it was added in 2.1.295, per the release notes; not tested here), so a hook that cannot start or times out lets the call through. Not tested: whether an older version ignores the unknown key or rejects the hook entry, which would turn the guard off there. The plugin also needs `python3` on PATH. Without it, 2.1.295 and later should block every call; older versions allow them.
- **You cannot loosen a shipped rule from your own policy file.** A user who copied the shipped file and changed a deny to an ask keeps getting the deny. A switch kept in a file the agent can write is a switch the agent can flip. Edit the shipped file by hand if you must (a plugin update undoes the edit).
- **Long commands ask.** A Bash command over 20000 characters is not checked by the rules. It always gets **ask** (rule `oversize-command`), even if it holds a deny pattern.
- **Logs are partial.** If you decline an ask, only the `decision` line exists. Allowed calls that never ran are not logged. If the Post script fails (a broken shipped policy or an unset data folder also break it), a call that ran leaves no result line. A call that failed may not reach the Post script at all, because Claude Code may send it to a separate event (not checked). Without a `tool_use_id`, a result line can show another call's decision. An ask caused by an internal error writes no log line; if you approve it, the result line shows decision `unknown`. If the decision memo cannot be written, the log line of a deny or ask is lost too. State files in `state/` are not cleaned up, and Pre reads the whole counter file on every call, so a shared file that is never deleted makes every call do more work (not measured). The write tools are denied on the log, but a Bash command can still edit it (limit 7 in [THREAT_MODEL](docs/THREAT_MODEL.md)). A secret in a format redaction does not know is written to the log as it is, so do not rely on redaction alone.

## Develop

```bash
make lint     # ruff
make test     # unit + end-to-end + acceptance tests (`uv run pytest`); runs make build first
make demo     # the table above
make build    # delete vendor/guardrails_core and re-copy core's *.py files into it
```

Needs [uv](https://docs.astral.sh/uv/) for `make lint` and `make test`. "Core" is `packages/guardrails-core`, the engine. "Vendor" is its copy in `packages/guardrails-plugin/vendor/`. `make test` includes the doc tests, so an edit to README, GLOSSARY or docs/ can fail it. Run `make build` after you edit core, commit the result, and run `git status` to add any new file under `vendor/`. A direct `uv run pytest` fails if the copy drifts; `make test` rebuilds the copy first, so it cannot catch this. CI runs `git diff --exit-code` on `packages/guardrails-plugin/vendor`, which ignores files git does not track yet.

More: [ARCHITECTURE](docs/ARCHITECTURE.md) · [THREAT_MODEL](docs/THREAT_MODEL.md) · [GLOSSARY](GLOSSARY.md)

License: [MIT](LICENSE).
