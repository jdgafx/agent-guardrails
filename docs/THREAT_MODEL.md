# Threat model

What this plugin (agent-guardrails, a Claude Code plugin) is for, what it stops, and what it does not. For the install steps and the demo, see the [README](../README.md).

## How it works

Claude Code can run a small script, called a hook, before and after every tool call (reading a file, running a shell command, fetching a page). This plugin is two such scripts. Before the call, it checks the call against a list of rules and answers **deny** (the call does not run), **ask** (Claude Code asks you first) or **allow** (nothing is printed, and Claude Code's normal prompts still apply, except in bypass mode, limit 5). After the call, it writes a log line and scans the results of web and MCP read tools for injection phrases. The scripts are `hooks/pre_tool_use.py` ("the Pre script") and `hooks/post_tool_use.py` ("the Post script"). The plugin needs `python3` on PATH. More detail is in [ARCHITECTURE.md](ARCHITECTURE.md).

Words used below:
- **MCP**: a standard way to plug extra tools into Claude Code. MCP tools are named `mcp__<server>__<tool>`.
- **Vendor folder**: a copy of the engine code (the Python package that makes the decisions) inside the plugin folder, at `vendor/`, so the plugin works with no install step.
- **Data folder**: the folder Claude Code gives the plugin through `${CLAUDE_PLUGIN_DATA}`, outside the plugin folder. The plugin keeps its log (`audit/`), its counters (`state/`) and an optional policy file of your own there. A `policy.json` in the data folder is used instead of the one in the plugin folder (the full lookup order is in [ARCHITECTURE.md](ARCHITECTURE.md), "Trust boundary"). The [GLOSSARY](../GLOSSARY.md) defines the other terms.
- **Decision line and result line**: the two kinds of log line. A decision line is written when a call is denied or asked. A result line is written after a call has run.
- **State files**: small files in the data folder where the plugin counts calls and remembers its decision for the second hook.
- **Step cap**: after 200 tool calls in one session (every call counts, whether or not a rule matched it), a call that matches no rule gets `ask`. A new session has a new id and starts at zero. (If Claude Code sends no session id, all calls share one counter; see "Limits of the log".)

## What it protects

- Your secrets, as far as they sit in files with the listed names (`.env`, keys, cloud credentials).
- Shared and live systems (git history, production, packages, clusters, other people's inboxes), for the listed commands and spellings only ("Gaps in the rules" lists what is missed).
- Your time: a runaway agent that loops. The cap is soft (a question after 200 calls, not a stop).

## Who or what to worry about

1. **A confused agent.** It means well and does something destructive (`rm -rf`, a force push). This is the main case.
2. **A prompt injection.** Text in a web page or tool result tries to give the agent new orders.
3. **A mistake in the guard itself.** A crash, a bad policy file, a full disk.
4. **An agent that edits the guard.** On purpose after an injection, or by accident while it tries to get past a false positive.

This plugin does not try to stop a skilled human attacker who already has a shell on your machine.

## What each control covers

| Threat | Control | How well |
|--------|---------|----------|
| Agent reads `.env` or a key | `deny-env-files`, `deny-key-files`, `deny-credential-dirs` | Stops direct reads of the listed file names, and any shell command that names the file as a whole word (`cat .env`, `cp .env x`). Easy to get around by content search, globs, environment variables, unlisted credential files, the Grep tool and names glued to other characters: see "Gaps in the rules", secrets. |
| Agent rewrites shared git history | `deny-force-push` | Stops `--force`, `--force-with-lease`, `-f` and `+branch` when `push` comes right after `git`, anywhere in the command (`cd r && git push --force` is denied). Misses options placed before `push`: see "Gaps in the rules", command spellings. |
| Agent publishes or deploys | `ask-*` rules | A human sees the command first, but only for the listed commands: `git push`, `rm -r`, `git reset --hard`, `terraform apply` and `destroy`, `kubectl apply` and `delete`, `vercel --prod`, `npm`/`pnpm`/`yarn publish`, `twine upload`, `cargo publish`, `uv publish`, `gem push`, and MCP tools with a name part that starts with `send`, `delete`, `pay`, `charge`, `transfer` or `post` right after an underscore (`mcp__gmail__send_email` asks; `mcp__x__resend` does not). `policy.json` is the full list. Other commands and spellings are not covered: see "Gaps in the rules". |
| Agent touches production config | `deny-prod-config` | Path based. Over-matches (any `/prod/` folder); see "Known false positives". |
| Hook errors inside its own code, or gets bad input | Fail safe (ask) | Tested with broken JSON, a missing `vendor/` folder and a data folder that is a file (checked with an allowed command only). If the policy or data folder is broken, every call asks, including calls a rule would have denied. |
| Hook cannot start (no `python3`), crashes outside its handler, or times out | `"onFailure": "block"` in `hooks.json` (Claude Code 2.1.295+) | On older versions the call goes ahead (see limit 9). Tested: with no `python3`, the hook command (the shell command in `hooks.json`; the script never starts) exits with a code other than 0 or 2 and prints nothing (0 is success and 2 is the code a hook uses to block a call, so any other code means the hook failed). That Claude Code then blocks the call comes from its release notes (2.1.295), not from a test here. A timeout is not tested live. |
| Huge command that makes the regex scan slow | `oversize-command` ask over 20000 characters, regexes rewritten to avoid the slow case seen on a 60 KB `rm` input | A long command that also holds a deny pattern gets ask, not deny. |
| Agent loops forever | Step cap (ask after 200 calls in one session) | Soft cap. Counts calls, not cost. The counter file has no lock, so parallel calls can share a step number. |
| Injection in a web page | Scan and log | **Detects some, stops none.** |
| Need to see what happened | Redacted audit log | Partial. An allowed call has no line until it finishes, an internal-error ask has none, and the agent can edit the files (see "Limits of the log"). |
| Agent edits the guard's rules, counter, log, scripts or Claude Code settings | None yet | Not covered. See limit 7. |

## Gaps in the rules

These are the gaps behind the three rows above. Each was run against the shipped `policy.json` during the review that produced this text. Where a gap has a fix on hold, the work item is named (see the start of "What it does NOT cover").

**Secrets (fix on hold, T-008).**
- Not stopped: searching file contents (`grep -r API_KEY .`), globs that expand to secrets (`cat config/*`), secrets in environment variables (`env`, `printenv`), or credential files not on the list (`~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`, `~/.config/gh/hosts.yml`, `~/.config/gcloud`).
- The listed names are the patterns of `deny-env-files` (`.env*` and `*.env`, with `*.example`, `*.sample` and `*.template` excused), `deny-key-files`, `deny-credential-dirs` and `deny-prod-config` in `policy.json`. A Bash command is cut into words, and each word is matched whole. The cut happens at white space and at `; & | < > = ( ) " '` and the backtick. Other characters do not cut a word, so a name glued to one of them is a different word. The word in `curl -d @.env` is `@.env`: the `*.env` pattern matches it and the call is denied. The word in `curl -d @.env.production` is `@.env.production`: neither `.env*` nor `*.env` matches it, so the call is allowed. The same holds for `scp host:.env.local .` and `git show HEAD:.env.production`.
- The Grep tool is not checked on its content search (a `pattern` with `path: "."` reads `.env` contents) and its `glob` field is ignored. A directory path such as `Read ~/.ssh` is allowed.
- The fix on hold checks every string of the tool input, matches directory paths, checks the Grep `glob` and adds the credential files. It does not cover content search or environment variables (limit 8).

**Command spellings (fix on hold, T-006).**
- Each command rule needs the program name, then the subcommand, with nothing between. An option placed before the subcommand slips through, for every rule that has this shape, not only for git:
  - It misses options placed before `push`: `git -C repo push --force` and `git -c key=value push -f` are allowed with no prompt.
  - `git -C repo push` without a force flag also gets no ask, so the ask tier has the same gap.
  - The same holds for `git -C repo reset --hard` (and `git reset HEAD~1 --hard`), `kubectl -n prod delete pod x`, `kubectl --context prod apply -f x`, `terraform -chdir=infra apply`, `npm --prefix x publish`, `cargo +nightly publish`, `uv --directory x publish`, `twine --verbose upload d` and `yarn --cwd x publish`: all are allowed with no prompt.
  - `git push -f;echo` asks instead of denying: the force pattern wants white space or the end of the text after a short flag like `-f`, and `;` is neither, so only the ask rule matches. `git push --force;echo` is denied.
- A leading `+` on a branch (`+main`) is git's way of forcing a push.
- The fix is a change to the regexes in `policy.json`. It is not a shell parser, because a parser would have to model every way to write a command.

**Commands with no rule (fix on hold, T-006).**
- Not covered: `gh pr merge`, `gh release create`, `docker push`, `helm upgrade`, `aws ...`, `git clean -fdx`, `find -delete`, `rm -f`, a script that deletes files, and MCP tools such as `push_files`, `merge_pull_request` or `create_issue`. (`aws s3 rm --recursive` asks, but only because the recursive-delete rule matches the words `rm --recursive` inside it.)

**Other tools (no fix on hold).**
- Command rules and the word-by-word path check read only a tool named exactly `Bash`. A shell started through any other tool name (a different shell tool, or an MCP server that runs commands) gets neither: `cat .env` sent through such a tool is allowed, because the path rules only read the fields `file_path`, `path` and `notebook_path` (and `pattern` for Glob). Run during this review with the tool names `PowerShell`, `Shell` and `bash`.

## What it does NOT cover

Limits 7, 8 and 9 matter most. Limits 7 and 8 apply to any setup. Limit 9 applies only to Claude Code older than 2.1.295 (check with `claude --version`). Limit 5 needs bypass mode, which a user must switch on. Limit 4 can matter more on a machine where the agent runs shell commands through a tool other than `Bash`.

Where a gap has a fix that is written down but not built, the text says "Fix on hold, not built" and gives the number of the held work item (the project's own numbering; the work items are not in this repo): T-006 (command spellings and missing commands), T-007 (the agent edits the guard), T-008 (secrets reachable under other names) and T-009 (the injection scan). All four are on hold.

### 1. No spend cap
The plugin counts calls. It does not know what a call costs. A loop of expensive calls under the cap can still run up a bill. Set limits at your model provider.

### 2. The model can still follow bad instructions inside allowed tools
Prompt injection is not solved here. The scan looks for six known phrases in the output of web and MCP read tools. It writes a warning to the log. You see nothing during the session; the warning is only in the log. The scan covers only WebFetch, WebSearch and MCP tools whose names contain read, get, fetch, search, list, query, browse, scrape or download (the server name counts: `mcp__target__x` is scanned because `target` contains `get`). The output of Bash commands (`curl`, `gh issue view`) and files read with the Read tool are not scanned. It does not remove the text, and it does not tell the model. A page can say the same thing in other words and pass. Only the first 200000 characters of a result are scanned. When a tool returns a structured result, it is scanned as JSON text, so a phrase broken by a real line break is missed. If the injected order then asks for a tool call, the policy rules still apply to that call. They judge the action, not the text that caused it. That stops plain, careless orders only: the rules match text, and an injected order can ask for an encoded or indirect command (see limit 4). The real control against a determined injection is isolation: a container or a separate user with no access to your secrets. A wider scan (every tool, not only web and MCP read tools) is a fix on hold, not built (T-009).

### 3. Attacks outside Claude Code
Hooks only see Claude Code tool calls. These are out of reach:
- A dependency you install that runs code at install time.
- A script the agent writes and then runs. The hook sees `python script.py`, not what is inside it.
- Anything you do in your own terminal.

### 4. Pattern rules are not a sandbox
Rules match text. A determined agent or attacker can get around them: build a path in a variable, encode a command, read a file through a program the rules do not know. The rules stop the common and the accidental. For hard isolation, use a container or a separate user with no access to the secrets. Command rules read only a tool named `Bash`: a shell started through any other tool (a different shell tool, or an MCP server that runs commands) gets no command rule at all. No fix for this is planned yet.

### 5. Bypass mode
Claude Code can run with permission checks off (the `--dangerously-skip-permissions` flag, or the `bypassPermissions` mode). Nobody has tested here what an `ask` answer does in that mode, and Claude Code's documentation does not say. Assume only `deny` is a hard stop there. That makes four controls soft: every `ask` rule, the fail-safe `ask` on internal errors, the `oversize-command` ask (padding a command past 20000 characters turns a deny into an ask), and the step cap. One chain follows from this and was not tested: a full disk or an unwritable data folder makes every call ask, even a call a rule would deny (threat 3), so if `ask` is soft in bypass mode, a full disk could let a would-be deny through there.

### 6. Headless runs
In `claude -p`, nobody can answer an ask. In the one run seen, the call did not run, and the task may stop. This was seen once in a real `claude -p` run (the log in the README, 2026-10-25); no automated test covers it, so treat it as observed once, not guaranteed.

### 7. The agent can change the guard itself
The guard is made of files, and the agent can write to every one of them. Some hold its working state: the rules (`policy.json`, in the plugin folder and in the data folder), the step counter (`state/`) and the log (`audit/`). Others decide whether the guard runs at all: the two hook scripts (`hooks/pre_tool_use.py`, `hooks/post_tool_use.py`), the copy of the engine code (`vendor/`), the hook list (`hooks/hooks.json`), and Claude Code's own settings files, where plugins and hooks are switched on and off. No rule protects any of them: a file write to each is allowed, and so are shell commands such as `echo > policy.json` and `sed -i`. An agent that may write files can replace `policy.json` with a weaker one, delete the counter to start again from zero, edit the log, or rewrite a hook script so that it allows everything. Claude Code's own prompt for file writes is the only thing in the way, and it is off in bypass mode (see 5). If you start the plugin with `claude --plugin-dir` from a folder the agent works in, the plugin folder is inside the project, so the agent's normal permission to edit project files already covers it. Until this is fixed: keep the plugin folder outside the project (copy it elsewhere, or install it from the marketplace), keep Claude Code's file-write prompts switched on, and do not add the plugin folder, the data folder or Claude Code's settings folders to its allowed paths. Fix on hold, not built (T-007): deny writes to these files and make the shipped deny rules impossible to override. Claude Code's own `permissions.deny` rules and Bash sandbox are described in ARCHITECTURE.md ("How this relates to Claude Code's own controls"); I did not test whether they protect the guard's files.

### 8. Nothing controls what leaves the machine
The rules block reading secret files. They do not control sending. `curl`, `wget` and the WebFetch tool can reach any address. Secrets held in environment variables can be printed with `env` or `printenv`, and anything the agent already read can be sent on. The one exception is a command that names a protected file while sending it (`curl -d @.env` is denied; `curl -d @.env.production` is not, see the secrets row in the table). If you need control over what leaves, use a limit outside this plugin: a container with no network, or a firewall.

### 9. Old Claude Code versions fail open
The hard fail-safe needs Claude Code 2.1.295 or later (that release added `onFailure`). On an older version, if `python3` is missing or the hook times out, the call goes ahead with no check. The plugin does not test the version and does not warn you. See "Fail-safe rule" in ARCHITECTURE.md.

## Limits of the log

- A declined ask leaves only the `decision` line, not a result line.
- Allowed calls that never ran (for example, an error before they started) are not logged.
- An allowed call gets no line when it starts. Its only record is the result line written after it finishes. If the Post script fails, an allowed call that ran leaves no trace.
- An `ask` caused by an internal error (reason starts with `[guardrails-error]`) writes no log line. If you approve it, the result line can show decision `unknown`.
- The agent can edit or delete the log files (limit 7). Treat the log as a help for you, not as proof of what happened.
- State files are not cleaned up. Each session has its own counter file, so an old file does not affect a new session; only the shared `unknown` file (see ARCHITECTURE.md, "Audit and state") carries over.
- Redaction uses seven patterns (private key, Anthropic key, OpenAI key, AWS access key, AWS secret key, GitHub token, bearer token). The AWS secret key is caught only after the label `aws_secret_access_key=` (or `:`); a bare 40-character secret is not. A secret in another format is written as is. Do not rely on redaction as the only protection for the log; the files are mode 0600.

## Known false positives

- `*/prod/*` and `*/production/*` deny any path, absolute or relative, that contains those folder names (`prod/x.txt` is denied too). For Bash, every word of the command counts as a possible path, so `git commit -m "fix production/config"` is denied too.
- `deny-env-files` matches any word of a Bash command that looks like an env file name, even when the command only writes the name. `echo .env >> .gitignore` and `cp .env.example .env` are both denied (the second because of the target `.env`).
- The MCP rule matches names like `..._post`, so a harmless tool such as `get_post` can trigger an ask.
- The command rules read the whole command text, including quoted text: `git commit -m "never git push --force"` is denied by `deny-force-push`. The production rule also covers `*.prod.yaml`, `*.prod.yml`, `*.prod.json` and `*.prod.tfvars`, so a file such as `app.prod.json` is denied.
- `.env*` also denies `.envrc` and `.environment`. `*.key` denies any file that ends in `.key`. `cat ~/.ssh/id_rsa.pub` is denied by `*/.ssh/*`, although the key-file rule excepts `*.pub`.
- `ask-git-push` asks for every push written as `git push`, including safe ones. That is on purpose.

## Design stance: a denylist, not least privilege

The design assumes the agent is useful but fallible. Deny the listed things that are rarely right (the false positives above show the rules are not exact). Ask for the listed things that are sometimes right and hard to undo. Allow the rest, including every command with no rule. This is a denylist: it approximates least privilege and does not reach it (see the [GLOSSARY](../GLOSSARY.md), "least privilege" and "blast radius"). A mistake on a listed target is made smaller; a mistake anywhere else is not covered.

Other designs were weighed in [ARCHITECTURE.md](ARCHITECTURE.md): an allowlist instead of a denylist, ask or deny on an internal error ("Fail-safe rule"), scan and log instead of block for injection ("Cuts"), and Claude Code's own `permissions.deny` and sandbox ("How this relates to Claude Code's own controls").
