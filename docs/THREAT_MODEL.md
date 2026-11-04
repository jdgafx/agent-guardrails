# Threat model

What this plugin (agent-guardrails, a Claude Code plugin) is for, what it stops, and what it does not. For the install steps and the demo, see the [README](../README.md).

## How it works

Claude Code can run a small script, called a hook, before and after every tool call (reading a file, running a shell command, fetching a page). This plugin is two such scripts, plus the policy and the engine code they use. Before the call, it checks the call against a list of rules and answers **deny** (the call does not run), **ask** (Claude Code asks you first) or **allow** (nothing is printed, and Claude Code's normal prompts still apply, except in bypass mode, limit 5; this is Claude Code's documented behaviour and is not tested here). A deny or ask is logged before the call. After the call, it writes a log line for the call that ran, when the Post script runs and works, and scans the results of web and MCP read tools for injection phrases. The scripts are `hooks/pre_tool_use.py` ("the Pre script") and `hooks/post_tool_use.py` ("the Post script"). The plugin needs `python3` on PATH. More detail is in [ARCHITECTURE.md](ARCHITECTURE.md).

Words used below:
- **MCP**: a standard way to plug extra tools into Claude Code. MCP tools are named `mcp__<server>__<tool>`.
- **Vendor folder**: a copy of the engine code (the Python package that makes the decisions) inside the plugin folder, at `vendor/`, so the plugin works with no install step.
- **Data folder**: the folder Claude Code gives the plugin through `${CLAUDE_PLUGIN_DATA}`, outside the plugin folder. The plugin keeps its log (`audit/`), its counters (`state/`) and an optional policy file of your own there. A `policy.json` in the data folder is used instead of the one in the plugin folder, and a file named by the `GUARDRAILS_POLICY` environment variable comes before both (if that path does not exist or is a folder it is skipped without a message, but a file that exists and cannot be read or parsed is used anyway, fails to load, and makes every call ask; the full lookup order is in [ARCHITECTURE.md](ARCHITECTURE.md), "Trust boundary"). The [GLOSSARY](../GLOSSARY.md) defines the other terms.
- **Decision line and result line**: the two kinds of log line. A decision line is written when a call is denied or asked (not for an ask caused by an internal error, and not when the decision memo cannot be written; see "Limits of the log"). A result line is written after a call has run.
- **State files**: small files in the data folder where the plugin counts calls and remembers its decision for the second hook.
- **Step cap**: after 200 tool calls in one session (every call that gets past input and policy loading counts, whether or not a rule matched it), a call that matches no rule gets `ask`. A new session has a new id and starts at zero. (If Claude Code sends no session id, all calls share one counter file, so after 200 calls in total, across all sessions and days, every call that matches no rule asks; see ARCHITECTURE.md, "Audit and state".)

## What it protects

- Your secrets, as far as they sit in files with the listed names (`.env`, keys, cloud credentials).
- Shared and live systems (git history, production, packages, clusters, other people's inboxes), for the listed commands and spellings only ("Gaps in the rules" lists what is missed).
- Your time: a runaway agent that loops. The cap is soft (a question after 200 calls, not a stop).

## Who or what to worry about

1. **A confused agent.** It tries to do the task and does something destructive (`rm -rf`, a force push). This is the case the design assumes (see "Design stance").
2. **A prompt injection.** Text in a web page or tool result tries to give the agent new orders.
3. **A mistake in the guard itself.** A crash, a bad policy file, a full disk.
4. **An agent that edits the guard.** On purpose after an injection, or by accident while it tries to get past a false positive.
5. **Hostile content in a repository you open.** A repository can ship files and Claude Code project settings of its own. Whether those settings can set `GUARDRAILS_POLICY` (which comes before every other policy file) or switch the plugin off was not checked here; see limit 7.

This plugin does not try to stop a skilled human attacker who already has a shell on your machine.

## What each control covers

| Threat | Control | How well |
|--------|---------|----------|
| Agent reads `.env` or a key | `deny-env-files`, `deny-key-files`, `deny-credential-dirs` | Stops reads and writes of the listed file names through a tool's path field (`Read`, `Write`, `Edit`, `Grep` with `path` on the file), and any shell command that names the file as a whole word (`cat .env`, `cp .env x`). Does not stop content search (the Grep tool's too), globs, environment variables, unlisted credential files, the Grep `glob` field or names glued to other characters: see "Gaps in the rules", secrets. |
| Agent rewrites shared git history | `deny-force-push` | Stops `--force`, `--force-with-lease`, `-f` and `+branch` (a leading `+` is git's way of forcing a push) when `push` follows `git`, with option words allowed between them (`git -C repo push --force` is denied), anywhere in the command (`cd r && git push --force` is denied). Misses quoted or hidden spellings: see "Gaps in the rules", command spellings. |
| Agent publishes or deploys | `ask-*` rules | A human sees the command first, but only for the listed commands, with option words allowed before the subcommand (T-006): `git push`, `rm -r`, `git reset --hard`, `git clean -f`, `terraform apply` and `destroy`, `kubectl apply` and `delete`, `vercel --prod` and `--target=production`, `npm`/`pnpm`/`yarn publish`, `twine upload`, `cargo publish`, `uv publish`, `gem push`, `gh pr merge`, `gh release create`, `docker push`, `helm install`, `upgrade` and `uninstall`, `find -delete`, a `python -c` one-liner that deletes files, `aws s3 rm`, `cp`, `mv` and `sync` and `aws` subcommands starting `delete-`, `put-`, `create-`, `update-` or `terminate-`, and MCP tools with a write word (`send`, `delete`, `post`, `pay`, `charge`, `transfer`) at the start of a word of the tool name (`mcp__gmail__send_email`, `mcp__x__bulkDelete` and `mcp__x__make-payment` ask; `mcp__x__get_posts`, `mcp__x__list_payments` and `mcp__x__resend` do not). `policy.json` is the full list. Other commands and spellings are not covered: see "Gaps in the rules". |
| Agent touches production config | `deny-prod-config` | Path based. Over-matches (any `/prod/` folder); see "Known false positives". |
| Internal error or bad input in the hook | Fail safe (ask) | Tested with broken JSON, a missing `vendor/` folder, a data folder that is a file, an unset data folder and a broken `{}` policy (checked with an allowed command, or with no command for bad input); a broken `GUARDRAILS_POLICY` file is also tested with `cat .env`, a would-be deny, which asks. If the policy or data folder is broken, every call asks, including calls a rule would have denied. A policy that loads but is wrong in ways the loader does not check (a text `except`, a missing `step_cap`, a misspelled key) weakens the guard without any message; see ARCHITECTURE.md, "Policy". |
| Hook cannot start (no `python3`), crashes outside its handler, or times out | `"onFailure": "block"` in `hooks.json` (Claude Code 2.1.295+) | On older versions the call probably goes ahead (per the release notes; not tested; see limit 9). Tested: with no `python3`, the hook command (the shell command in `hooks.json`; the script never starts) exits with a code other than 0 or 2 and prints nothing (0 is success and 2 is the code a hook uses to block a call, so any other code means the hook failed). That Claude Code then blocks the call comes from its release notes (2.1.295), not from a test here. A timeout is not tested live. |
| Huge command that makes the regex scan slow | `oversize-command` ask over 20000 characters, regexes rewritten to avoid the slow case seen on a 60 KB `rm` input | A long command that also holds a deny pattern gets ask, not deny. |
| Agent loops forever | Step cap (ask after 200 calls in one session) | Soft cap. Counts calls, not cost. The counter file has no lock, so parallel calls can share a step number. |
| Injection in a web page | Scan and log | **Detects six known phrases in web and MCP read output; stops none.** |
| Need to see what happened | Redacted audit log | Partial. An allowed call has no line until it finishes, an internal-error ask has none, and the agent can edit the files (see "Limits of the log"). |
| Agent edits the guard's rules, counter, log, scripts or Claude Code settings | None yet | Not covered. See limit 7. |
| Hostile content in a repository you open (threat 5) | None | Not covered; not checked. See limit 7. |
| A shell started through a tool not named `Bash` | None | Not covered. See "Gaps in the rules", other tools, and limit 4. |

## Gaps in the rules

These are the gaps behind the table rows above that point here. Each was run against the shipped `policy.json` on 2026-11-04, and the cases are kept as a test (`tests/unit/test_t013_doc_gaps.py`, which records today's behaviour: when a fix changes a case, update the test and this text together). Where a gap has a fix that is written down but not built, the work item is named (see the start of "What it does NOT cover").

**Secrets (fix not built yet, T-008).**
- Not stopped: searching file contents (`grep -r API_KEY .`), globs that expand to secrets (`cat config/*`), secrets in environment variables (`env`, `printenv`), or credential files not on the list (`~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`, `~/.config/gh/hosts.yml`, `~/.config/gcloud`).
- The listed names are the patterns of `deny-env-files` (`.env*` and `*.env`, with `*.example`, `*.sample` and `*.template` excused), `deny-key-files`, `deny-credential-dirs` and `deny-prod-config` in `policy.json`. A Bash command is split into words, and each word is matched whole. The split happens at white space and at `; & | < > = ( ) " '` and the backtick. Other characters do not split a word, so a name glued to one of them is a different word. The word in `curl -d @.env` is `@.env`: the `*.env` pattern matches it and the call is denied. The word in `curl -d @.env.production` is `@.env.production`: neither `.env*` nor `*.env` matches it, so the call is allowed. The same holds for `scp host:.env.local .` and `git show HEAD:.env.production`.
- The Grep tool is not checked on its content search (a `pattern` with `path: "."` reads `.env` contents) and its `glob` field is ignored. A directory path such as `Read ~/.ssh` is allowed.
- Paths are matched as written, not cleaned up first. `~/.aws/credentials` is denied, but `~/.aws/./credentials` and `~/.kube//config` are allowed, because the glob `*/.aws/credentials` does not match the longer text. The same holds in a Bash command (`cat ~/.aws/./credentials`). The file-name globs (`.env*`, `id_rsa*`) and `*/.ssh/*` still match.
- The fix written down checks every string of the tool input, matches directory paths, checks the Grep `glob` and adds the credential files. It does not cover content search or environment variables, and no fix is written down for either (environment variables: limit 8).

**Command spellings (T-006 built; what is left).**
- Fixed: the command rules accept option words between the program and its subcommand. An option word starts with `-` (for `cargo`, also `+`, as in `cargo +nightly publish`), may be followed by one value word that does not start with `-`, never crosses `;`, `&`, `|` or a line break, and at most 8 may sit between the program and the subcommand. This holds for every command rule that has a subcommand: `git`, `kubectl`, `terraform`, `npm`, `pnpm`, `yarn`, `cargo`, `uv`, `twine`, `gem`, `gh`, `docker` and `helm`.
  - `git -C repo push --force`, `git -c key=value push -f`, `git --no-pager push -f` and `git --git-dir=x push -f` are denied.
  - `git -C repo push`, `git -C repo reset --hard`, `git reset HEAD~1 --hard`, `kubectl -n prod delete pod x`, `kubectl --context prod apply -f x`, `terraform -chdir=infra apply`, `npm --tag x publish`, `pnpm -r publish`, `yarn --cwd x publish`, `cargo +nightly publish`, `uv --directory x publish` and `twine --verbose upload d` ask.
  - A short force flag now ends at white space, `;`, `&`, `|`, `)` or the end of the text, so `git push -f;echo` and `git push -f|cat` are denied (before, they only asked).
  - `vercel --target=production` asks, as `vercel --prod` does.
- The price: the rules cannot tell an option's value from the subcommand, so `git --no-pager log --grep push` asks, although it only reads.
- Still missed (these forms are out of scope and are stated here once; the rules match plain text, see limit 4):
  - Quoting or escaping of the program, the subcommand or a flag: `"rm" -r x`, `rm "-rf" build` and ``git "push" -f`` are allowed with no ask. `git push "--force"`, `git push "-f"`, `git push '--force'` and `bash -c "git push -f"` ask instead of denying.
  - A flag hidden in a variable, an alias or a line continuation (`F=--force; git push $F`, `alias gp='git push -f'; gp`, a backslash before a line break): ask, not deny.
  - A flag after a redirection (`git push -f>/dev/null`, `git push origin main 2>&1 --force`): ask, not deny.
  - `vercel` and `--prod` on different lines (`vercel` then a line break, then `--prod`): allowed.
  - More than 8 option words between the program and the subcommand: allowed.
- The fix is a change to the regexes in `policy.json`. A shell parser is not planned: an earlier parser attempt did not converge in three rounds, and the regex change needed no engine change.

**Commands with no rule (T-006 added some).**
- Now ask: `gh pr merge`, `gh release create` and `gh release delete`, `gh repo delete`, `docker push` (also `docker image push`, `docker manifest push`, `docker compose push`), `helm install`, `helm upgrade`, `helm uninstall` (also `helm delete` and `helm rollback`), `git clean` with a force flag (`git clean -fdx`; `git clean -n` does not ask), `find` with `-delete` or `-exec rm`, a `python -c` one-liner that names `rmtree`, `unlink`, `rmdir`, `removedirs` or `os.remove`, `aws s3 rm`, `cp`, `mv` and `sync`, and any `aws` subcommand that starts with `delete-`, `put-`, `create-`, `update-` or `terminate-`. Read commands such as `aws s3 ls`, `gh pr view`, `helm list`, `docker build .` and `find . -name x` are allowed.
- Still no rule: `rm -f`, a script that deletes files (`python3 script.py`), `aws s3 rb` and other `aws` subcommands outside the list above, `kubectl patch` and `scale`, `gh api -X DELETE`, `git branch -D`, `docker buildx build --push`, and MCP tools such as `push_files`, `merge_pull_request` or `create_issue`.
- MCP tool names are read at the start of a word of the tool part of the name (after the server name): after `_` or `-`, at a change from lower to upper case (`bulkDelete`, `createPost`) and at the start. `send` and `delete` ask; `post`, `pay`, `charge` and `transfer` ask unless the name starts with a reading word (`get`, `list`, `read`, `fetch`, `search`, `query`, `find`, `describe`, `view`, `show`, `check`, `count`, `browse`, `lookup`), so `get_posts` and `list_payments` are allowed. A write word with no word break (`createpost`, `resend`) is not seen, and a name like `getAndPost` is excused by its first word. The server name no longer counts (`mcp__my_pay__list` is allowed).

**Your own policy file (two fixes named in ARCHITECTURE.md, no work item).**
- A policy file of your own (in the data folder, or named by `GUARDRAILS_POLICY`) replaces the shipped one completely. Rules and fixes added to the shipped file later (T-006, T-008) never reach it, and nothing warns you. After an update, compare your file with the shipped one.

**Other tools (no fix written down).**
- Command rules and the word-by-word path check read only a tool named exactly `Bash`. A shell started through any other tool name (a different shell tool, or an MCP server that runs commands) gets neither: `cat .env` sent through such a tool is allowed, because the path rules only read the fields `file_path`, `path` and `notebook_path` (and `pattern` for Glob). Tested with the tool names `PowerShell`, `Shell` and `bash`.

## What it does NOT cover

Limits 1 to 4, 7 and 8 apply to any setup. Limit 5 needs bypass mode, which a user must switch on. Limit 6 needs `claude -p`. Limit 9 applies only to Claude Code older than 2.1.295 (check with `claude --version`).

The text gives the aim of each fix, not its design: the mechanism (for example how deny rules are made impossible to override) is left open in those work items. Where a gap has a fix that is written down but not built, the text says "Fix not built yet" and gives the number of the open work item (the project's own numbering; the work items are not in this repo): T-007 (the agent edits the guard; it also covers counting the step after the rules, so a counter file that cannot be written no longer turns a would-be deny into an ask), T-008 (secrets reachable under other names) and T-009 (the injection scan). None of the three is built. T-006 (command spellings and missing commands) is built; what it leaves is listed under "Gaps in the rules". A broken policy still turns a would-be deny into an ask; the built-in minimum deny list that would cover it is not built and has no work item.

### 1. No spend cap
The plugin counts calls. It does not know what a call costs. A loop of expensive calls under the cap can still run up a bill. Set limits at your model provider.

### 2. The model can still follow bad instructions inside allowed tools
Prompt injection is not solved here. The scan looks for six known phrases in the output of web and MCP read tools. It writes a warning to the log. You see nothing during the session; the warning is only in the log. The scan covers only WebFetch, WebSearch and MCP tools whose names contain read, get, fetch, search, list, query, browse, scrape or download (the server name counts: `mcp__target__x` is scanned because `target` contains `get`). The output of Bash commands (`curl`, `gh issue view`) and files read with the Read tool are not scanned. Instruction files that Claude Code loads into the conversation by itself (for example a `CLAUDE.md` in the project) are not scanned either, because no tool call carries them. It does not remove the text, and it does not tell the model. A page can say the same thing in other words and pass. Only the first 200000 characters of a result are scanned. When a tool returns a structured result, it is scanned as JSON text, so a phrase broken by a real line break is missed. If the injected order then asks for a tool call, the policy rules still apply to that call. They judge the action, not the text that caused it. That stops only orders written in a listed spelling: the rules match text, and an injected order can ask for an encoded or indirect command (see limit 4). Isolation is the control against a determined injection, and this plugin does not provide it: use a container or a separate user with no access to your secrets. A wider scan (every tool, not only web and MCP read tools) is a fix not built yet (T-009).

### 3. Attacks outside Claude Code
Hooks only see Claude Code tool calls. These are out of reach:
- A dependency you install that runs code at install time.
- A script the agent writes and then runs. The hook sees `python script.py`, not what is inside it.
- Anything you do in your own terminal.
- Files the agent writes that other programs run later, outside Claude Code and with no hook involved: `.git/hooks/*`, shell start-up files such as `~/.bashrc`, `package.json` scripts, a `Makefile`, `.github/workflows/*`. No rule covers them, so one session's injection can leave code that keeps running after the session. Whether calls made by subagents reach these hooks was not checked.

Use a container or a separate user with no access to your secrets for these (limits 2 and 4).

### 4. Pattern rules are not a sandbox
Rules match text. A determined agent or attacker can get around them: build a path in a variable, encode a command, read a file through a program the rules do not know. The rules stop the listed commands and file names in the listed spellings. For hard isolation, use a container or a separate user with no access to the secrets. Command rules read only a tool named `Bash`: a shell started through any other tool (a different shell tool, or an MCP server that runs commands) gets no command rule at all. No fix is written down for this. Claude Code's own Bash sandbox is another layer (see "How this relates to Claude Code's own controls" in [ARCHITECTURE.md](ARCHITECTURE.md); its defaults were not tested here).

### 5. Bypass mode
Claude Code can run with permission checks off (the `--dangerously-skip-permissions` flag, or the `bypassPermissions` mode). No test in this repository covers what an `ask` answer does in that mode, or whether a hook's `deny` is honoured there, and neither was found stated in Claude Code's documentation. Assume only `deny` is a hard stop there; if `deny` is also ignored in that mode, the plugin stops nothing there (it still logs). A live check (a Read of `.env` run with `--dangerously-skip-permissions`) has not been run. That makes four controls soft: every `ask` rule, the fail-safe `ask` on internal errors, the `oversize-command` ask (padding a command past 20000 characters turns a deny into an ask), and the step cap. One chain follows from this and was not tested: a full disk or an unwritable data folder makes every call ask, even a call a rule would deny (threat 3), so if `ask` is soft in bypass mode, a full disk could let a would-be deny through there. Fix not built yet (T-007). Meanwhile, put what must never run in Claude Code's own `permissions.deny` as well ("How this relates to Claude Code's own controls" in [ARCHITECTURE.md](ARCHITECTURE.md); check its release notes first).

### 6. Headless runs
In `claude -p`, nobody can answer an ask. Plan for an ask to end that call when nobody is there to answer. This was seen once in a real `claude -p` run (the log in the README, 2026-10-25): the log shows no result line for the asked call, so the call probably did not run (a result line is also missing when the Post script fails). The session went on with the next call. No automated test covers it, so treat it as observed once, not guaranteed.

### 7. The agent can change the guard itself
The guard is made of files, and the agent can write to every one of them. Some hold its rules and records: the rules (`policy.json`, in the plugin folder and in the data folder, or the file named by `GUARDRAILS_POLICY`), the step counter (`state/`) and the log (`audit/`). Others decide whether the guard runs at all: the two hook scripts (`hooks/pre_tool_use.py`, `hooks/post_tool_use.py`), the copy of the engine code (`vendor/`), the hook list (`hooks/hooks.json`), and Claude Code's own settings files, where plugins and hooks are switched on and off.

No rule protects any of them: a file write to each is allowed, and so are shell commands such as `echo > policy.json` and `sed -i`. An agent that may write files can replace `policy.json` with a weaker one, delete the counter to start again from zero, edit the log, or rewrite a hook script so that it allows everything.

Claude Code's own prompt for file writes is the only known barrier, and it is off in bypass mode (see limit 5). If you pass `--plugin-dir` a folder inside the project the agent works in, the agent's normal permission to edit project files should already cover it (not tested). The hook runs whichever `python3` comes first on `PATH`. Files that Python loads at start-up (for example `.pth` files and `sitecustomize` in its `site-packages`) can change what the Pre script does, including an exit 0 with no output, which Claude Code should read as allow; this was not tested. If Claude Code is started from an activated virtualenv inside the project, those files are in the project. A repository you open can also ship Claude Code project settings; whether those can set `GUARDRAILS_POLICY`, `PATH` or `PYTHONPATH` for the hooks, or switch the plugin off, was not checked here. Claude Code's trust prompt for a new folder is the only barrier known (not tested); reading `.claude/settings*.json` in an untrusted repository before you accept it is a step for you to take (untested).

Until this is fixed (these steps are untested; they reduce the exposure and may not remove it): keep the plugin folder outside the project (copy it elsewhere, or install it from the marketplace), keep Claude Code's file-write prompts switched on, and do not add the plugin folder, the data folder or Claude Code's settings folders to its allowed paths. Also do not pre-approve shell commands that can write files (interpreters such as `python3`, `sed`, `tee`, redirection): the policy file in the data folder is outside the project whatever the install method, so only not pre-approving file-writing commands and the allowed-paths step limit writes to it.

Fix not built yet (T-007): deny writes to these files and make the shipped deny rules impossible to override. Claude Code's own `permissions.deny` rules and Bash sandbox are described in ARCHITECTURE.md ("How this relates to Claude Code's own controls"). Whether they protect the guard's files was not tested.

### 8. Nothing controls what leaves the machine
The rules deny reading the files with the listed names. They do not control sending. `curl`, `wget` and the WebFetch tool can reach any address. Secrets held in environment variables can be printed with `env` or `printenv`, and anything the agent already read can be sent on. The one exception is a command that names a protected file while sending it (`curl -d @.env` is denied; `curl -d @.env.production` is not, see the secrets row in the table). If you need control over what leaves, use a limit outside this plugin: a container with no network, or a firewall. Claude Code's Bash sandbox can also limit network access (described in ARCHITECTURE.md; not tested here).

### 9. Old Claude Code versions fail open
The hard fail-safe needs Claude Code 2.1.295 or later (per its release notes, that release added `onFailure`; not tested here). On an older version, if `python3` is missing or the hook times out, the call probably goes ahead with no check (per the release notes; not tested). Run `claude --version` and upgrade to 2.1.295 or later; the plugin does not check the version and does not warn you. Not tested: whether an older version ignores the unknown `onFailure` key and still runs the hook. If one rejected the hook entry instead, the guard would not run there at all. See "Fail-safe rule" in ARCHITECTURE.md.

## Limits of the log

- A declined ask leaves only the `decision` line, not a result line.
- A logged input longer than 2000 characters (the default of `audit.max_input_chars`) is replaced by `{"truncated": "<first 2000 characters>"}`, so the log shows only the start of a long command.
- Allowed calls that never ran (for example, an error before they started) are not logged.
- With no `tool_use_id`, Post cannot tell calls apart, and a result line can show another call's decision (ARCHITECTURE.md, "Audit and state").
- A call that ran and failed may leave no result line. Claude Code may send a failed tool call to a separate event (PostToolUseFailure), and `hooks.json` registers PostToolUse only; this was not checked against a live run. A fix not built: register the failure event too.
- An allowed call gets no line when it starts. Its only record is the result line written after it finishes. If the Post script fails, an allowed call that ran leaves no trace.
- If the decision memo cannot be written after the rules ran, the log line of a deny or ask is lost too (they share one `try` block in `hooks.py`).
- An `ask` caused by an internal error (reason starts with `[guardrails-error]`) writes no log line. If you approve it and the Post script still works (it reads the policy and the data folder too, so it fails after a broken policy or an unset data folder), the result line can show decision `unknown`.
- The agent can edit or delete the log files (limit 7). Treat the log as a help for you, not as proof of what happened.
- State files are not cleaned up. Each session has its own counter file, so an old file does not affect a new session; only the shared files for a missing or null session id (`unknown.calls`, `None.calls`; see ARCHITECTURE.md, "Audit and state") carry over. Pre reads the whole `.calls` file and Post the whole `.decisions` file on every call, so the work per call grows with the file (not measured; a hook that runs past its 10-second timeout is blocked, for Pre, or loses its result line, for Post). Delete old state files.
- Redaction uses seven patterns (private key, Anthropic key, OpenAI key, AWS access key, AWS secret key, GitHub token, bearer token). The AWS secret key is caught only after the label `aws_secret_access_key=` or `aws_secret_access_key:` (with white space only between); the quoted JSON form `"aws_secret_access_key": "..."` and a bare 40-character secret are not. A secret in another format is written as is. Do not rely on redaction as the only protection for the log. New files are created with mode 0600, which keeps other users out and not the agent; an existing file keeps the mode it has.

## Known false positives

- `*/prod/*` and `*/production/*` deny any path, absolute or relative, that contains those folder names (`prod/x.txt` is denied too). For Bash, every word of the command counts as a possible path, so `git commit -m "fix production/config"` is denied too.
- `deny-env-files` matches any word of a Bash command that looks like an env file name, even when the command only writes the name. `echo .env >> .gitignore` and `cp .env.example .env` are both denied (the second because of the target `.env`).
- The MCP rule matches names like `..._post`, so a harmless tool such as `mcp__blog__get_post` asks, and so does a server name with an underscore before a listed word (`mcp__my_sender__list`).
- The command rules read the whole command text, including quoted text: `git commit -m "never git push --force"` is denied by `deny-force-push`.
- The production rule also covers `*.prod.yaml`, `*.prod.yml`, `*.prod.json` and `*.prod.tfvars`, so a file such as `app.prod.json` is denied.
- The recursive-delete ask has no command boundary: `git rm -r x` asks, and so does `rm a; ls -R` (the pattern runs past the `;` to a later `-R`).
- `.env*` also denies `.envrc` and `.environment`. `*.key` denies any file that ends in `.key`. `cat ~/.ssh/id_rsa.pub` is denied by `*/.ssh/*`, although the key-file rule excepts `*.pub`.
- `ask-git-push` asks for every push written as `git push`, including safe ones. That is on purpose.

## Design stance: a denylist, not least privilege

The design assumes the agent is useful but fallible. Deny the listed things that are rarely right (the false positives above show the rules are not exact). Ask for the listed things that are sometimes right and hard to undo. Allow the rest, including every command with no rule. This is a denylist: it approximates least privilege and does not reach it (see the [GLOSSARY](../GLOSSARY.md), "least privilege" and "blast radius"). A mistake is stopped or shown to a person only when it is written in a listed spelling, on a listed target, and (for an ask) when someone can answer; anywhere else it is not covered.

## Alternatives considered

Other designs were weighed in [ARCHITECTURE.md](ARCHITECTURE.md) ("Alternatives at a glance"). Two are deferred, not rejected: counting the step after the rules (T-007) and a built-in minimum deny list (no work item); the reason is priority only. Not weighed as alternatives: isolation instead of this plugin (isolation is the control for limits 2 to 4 and 8, and this plugin adds an ask with a reason and a log on top of it), and showing the injection warning to the user (the design logs it and shows nothing; no reason is recorded).

Set aside, with reasons:

- An allowlist instead of a denylist: it blocks every command not listed, so each command the agent needs must be added first ("Other choices" in ARCHITECTURE.md).
- Deny instead of ask on an internal error: a deny on every error would stop all work, and an ask lets a person continue ("Fail-safe rule").
- Block or rewrite instead of scan and log for injection: a phrase match has false positives, and rewriting makes the model see text that differs from the tool's real output ("Cuts").
- Claude Code's own `permissions.deny` and sandbox instead of this plugin: they need no Python and do not depend on a hook timeout, but they show no per-rule reason and are not known to keep an audit log (not checked); the two can be used together ("How this relates to Claude Code's own controls").
