# Threat model

What this plugin is for, what it stops, and what it does not.

## How it works

Claude Code can run a small script, called a hook, before and after every tool call (reading a file, running a shell command, fetching a page). This plugin is two such scripts. Before the call, it checks the call against a list of rules and answers **deny** (the call does not run), **ask** (Claude Code asks you first) or **allow** (nothing is printed, and Claude Code's normal prompts still apply). After the call, it writes a log line and scans web and MCP results for injection phrases. More detail is in ARCHITECTURE.md.

Words used below:
- **MCP**: a standard way to plug extra tools into Claude Code. MCP tools are named `mcp__<server>__<tool>`.
- **Vendor folder**: a copy of the engine code inside the plugin folder, so the plugin works with no install step.
- **Decision line and result line**: the two kinds of log line. A decision line is written when a call is denied or asked. A result line is written after a call has run.
- **State files**: small files in the data folder where the plugin counts calls and remembers its decision for the second hook.
- **Step cap**: after 200 tool calls in one session, a call that matches no rule gets `ask`.

## What it protects

- Your secrets, as far as they sit in files with the listed names (`.env`, keys, cloud credentials).
- Shared and live systems (git history, production, packages, clusters, other people's inboxes).
- Your time: a runaway agent that loops.

## Who or what to worry about

1. **A confused agent.** It means well and does something destructive (`rm -rf`, a force push). This is the main case.
2. **A prompt injection.** Text in a web page or tool result tries to give the agent new orders.
3. **A mistake in the guard itself.** A crash, a bad policy file, a full disk.
4. **An agent that edits the guard.** On purpose after an injection, or by accident while it tries to get past a false positive.

This plugin does not try to stop a skilled human attacker who already has a shell on your machine.

## What each control covers

| Threat | Control | How well |
|--------|---------|----------|
| Agent reads `.env` or a key | `deny-env-files`, `deny-key-files`, `deny-credential-dirs` | Stops direct reads of the listed file names, and any shell command that names the file (`cat .env`, `cp .env x`). Does not stop: searching file contents (`grep -r API_KEY .`), globs that expand to secrets (`cat config/*`), secrets in environment variables (`env`, `printenv`), or credential files not on the list (`~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`, `~/.config/gh/hosts.yml`, `~/.config/gcloud`). |
| Agent rewrites shared git history | `deny-force-push` | Stops `--force`, `--force-with-lease`, `-f` and `+branch` when the command starts with `git push`. It misses options placed before `push`: `git -C repo push --force` and `git -c key=value push -f` are allowed with no prompt. `git push -f;echo` asks instead of denying. |
| Agent publishes or deploys | `ask-*` rules | A human sees the command first, but only for the listed commands: `git push`, `rm -r`, `git reset --hard`, `terraform apply` and `destroy`, `kubectl apply` and `delete`, `vercel --prod`, `npm`/`pnpm`/`yarn publish`, `twine upload`, `cargo publish`, `uv publish`, `gem push`, and MCP tools whose names contain `send`, `delete`, `pay`, `charge`, `transfer` or `post`. Not covered: `gh pr merge`, `gh release create`, `docker push`, `helm upgrade`, `aws ...`, `git clean -fdx`, and MCP tools such as `push_files`, `merge_pull_request` or `create_issue`. |
| Agent touches production config | `deny-prod-config` | Path based. Over-matches (any `/prod/` folder). |
| Hook errors inside its own code, or gets bad input | Fail safe (ask) | Tested with broken JSON, a missing `vendor/` folder and a data folder that is a file (checked with an allowed command only). If the policy or data folder is broken, every call asks, including calls a rule would have denied. |
| Hook cannot start (no `python3`), crashes outside its handler, or times out | `"onFailure": "block"` in `hooks.json` (Claude Code 2.1.295+) | On older versions the call goes ahead (see limit 9). Tested: with no `python3`, the hook script exits with a code other than 0 or 2 and prints nothing. That Claude Code then blocks the call comes from its release notes (2.1.295), not from a test here. A timeout is not tested live. |
| Huge command that makes the regex scan slow | `oversize-command` ask over 20000 characters, linear-time regexes | A long command that also holds a deny pattern gets ask, not deny. |
| Agent loops forever | Step cap (ask after 200 calls in one session) | Soft cap. Counts calls, not cost. |
| Injection in a web page | Scan and log | **Detects some, stops none.** |
| Need to see what happened | Redacted audit log | Partial (see limits). |
| Agent edits the guard's rules, counter, log, scripts or Claude Code settings | None yet | Not covered. See limit 7. |

## What it does NOT cover

Limits 7, 8 and 9 matter most.

### 1. No spend cap
The plugin counts calls. It does not know what a call costs. A loop of expensive calls under the cap can still run up a bill. Set limits at your model provider.

### 2. The model can still follow bad instructions inside allowed tools
Prompt injection is not solved here. The scan looks for six known phrases in the output of web and MCP read tools. It writes a warning to the log. You see nothing during the session; the warning is only in the log. The scan covers only WebFetch, WebSearch and MCP tools whose names contain read, get, fetch, search, list, query, browse, scrape or download. The output of Bash commands (`curl`, `gh issue view`) and files read with the Read tool are not scanned. It does not remove the text, and it does not tell the model. A page can say the same thing in other words and pass. Only the first 200000 characters of a result are scanned. When a tool returns a structured result, it is scanned as JSON text, so a phrase broken by a real line break is missed. If the injected order then asks for a tool call, the policy rules still apply to that call. They judge the action, not the text that caused it. That stops plain, careless orders only: the rules match text, and an injected order can ask for an encoded or indirect command (see 4). The real control against a determined injection is isolation: a container or a separate user with no access to your secrets.

### 3. Attacks outside Claude Code
Hooks only see Claude Code tool calls. These are out of reach:
- A dependency you install that runs code at install time.
- A script the agent writes and then runs. The hook sees `python script.py`, not what is inside it.
- Anything you do in your own terminal.

### 4. Pattern rules are not a sandbox
Rules match text. A determined agent or attacker can get around them: build a path in a variable, encode a command, read a file through a program the rules do not know. The rules stop the common and the accidental. For hard isolation, use a container or a separate user with no access to the secrets.

### 5. Bypass mode
Claude Code can run with permission checks off (the `--dangerously-skip-permissions` flag, or the `bypassPermissions` mode). Nobody has tested here what an `ask` answer does in that mode, and the docs do not say. Assume only `deny` is a hard stop there. That makes four controls soft: every `ask` rule, the fail-safe `ask` on internal errors, the `oversize-command` ask (padding a command past 20000 characters turns a deny into an ask), and the step cap.

### 6. Headless runs
In `claude -p`, nobody can answer an ask. The call does not run. This is safe, but the task may stop. This was seen once in a real `claude -p` run (the log in the README, 2026-10-25); no automated test covers it.

### 7. The agent can change the guard itself
The guard is made of files, and the agent can write to every one of them. Some hold its working state: the rules (`policy.json`, in the plugin folder and in the data folder), the step counter (`state/`) and the log (`audit/`). Others decide whether the guard runs at all: the two hook scripts (`hooks/pre_tool_use.py`, `hooks/post_tool_use.py`), the copy of the engine code (`vendor/`), the hook list (`hooks/hooks.json`), and Claude Code's own settings files, where plugins and hooks are switched on and off. No rule protects any of them: a file write to each is allowed, and so are shell commands such as `echo > policy.json` and `sed -i`. An agent that may write files can replace `policy.json` with a weaker one, delete the counter to start again from zero, edit the log, or rewrite a hook script so that it allows everything. Claude Code's own prompt for file writes is the only thing in the way, and it is off in bypass mode (see 5). If you start the plugin with `claude --plugin-dir` from a folder the agent works in, the plugin folder is inside the project, so the agent's normal permission to edit project files already covers it. Until this is fixed: keep the plugin folder outside the project (copy it elsewhere, or install it from the marketplace), keep Claude Code's file-write prompts switched on, and do not add the plugin folder, the data folder or Claude Code's settings folders to its allowed paths.

### 8. Nothing controls what leaves the machine
The rules block reading secret files. They do not control sending. `curl`, `wget` and the WebFetch tool can reach any address. Secrets held in environment variables can be printed with `env` or `printenv`, and anything the agent already read can be sent on. The one exception is a command that names a protected file while sending it (`curl -d @.env` is denied). If you need control over what leaves, use a limit outside this plugin: a container with no network, or a firewall.

### 9. Old Claude Code versions fail open
The hard fail-safe needs Claude Code 2.1.295 or later (that release added `onFailure`). On an older version, if `python3` is missing or the hook times out, the call goes ahead with no check. The plugin does not test the version and does not warn you. See "Fail-safe rule" in ARCHITECTURE.md.

## Limits of the log

- A declined ask leaves only the `decision` line, not a result line.
- Allowed calls that never ran (for example, an error before they started) are not logged.
- An allowed call gets no line when it starts. Its only record is the result line written after it finishes. If the Post script fails, an allowed call that ran leaves no trace.
- An `ask` caused by an internal error (reason starts with `[guardrails-error]`) writes no log line. If you approve it, the result line can show decision `unknown`.
- The agent can edit or delete the log files (limit 7). Treat the log as a help for you, not as proof of what happened.
- State files are not cleaned up.
- Redaction uses seven patterns (private key, Anthropic key, OpenAI key, AWS access key, AWS secret key, GitHub token, bearer token). A secret in another format is written as is. Do not rely on redaction as the only protection for the log; the files are mode 0600.

## Known false positives

- `*/prod/*` and `*/production/*` deny any path, absolute or relative, that contains those folder names (`prod/x.txt` is denied too). For Bash, every word of the command counts as a possible path, so `git commit -m "fix production/config"` is denied too.
- `deny-env-files` matches any word of a Bash command that looks like an env file name, even when the command only writes the name. `echo .env >> .gitignore` and `cp .env.example .env` are both denied (the second because of the target `.env`).
- The MCP rule matches names like `..._post`, so a harmless tool such as `get_post` can trigger an ask.
- `ask-git-push` asks for every push, including safe ones. That is on purpose.

## Least privilege and blast radius

The design assumes the agent is useful but fallible. Deny the few things that are never right. Ask for the things that are sometimes right and hard to undo. Allow the rest. That keeps the blast radius of a mistake small without making the agent useless.
