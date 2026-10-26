# Threat model

What this plugin is for, what it stops, and what it does not.

## What we protect

- Your secrets (`.env`, keys, cloud credentials).
- Shared and live systems (git history, production, packages, clusters, other people's inboxes).
- Your time: a runaway agent that loops.

## Who or what we worry about

1. **A confused agent.** It means well and does something destructive (`rm -rf`, a force push). This is the main case.
2. **A prompt injection.** Text in a web page or tool result tries to give the agent new orders.
3. **A mistake in the guard itself.** A crash, a bad policy file, a full disk.

We do not try to stop a skilled human attacker who already has a shell on your machine.

## What each control covers

| Threat | Control | How well |
|--------|---------|----------|
| Agent reads `.env` or a key | `deny-env-files`, `deny-key-files`, `deny-credential-dirs` | Stops direct reads and common shell forms (`cat .env`). |
| Agent rewrites shared git history | `deny-force-push` | Stops `--force`, `--force-with-lease`, `-f`, and `+branch`. |
| Agent publishes or deploys | `ask-*` rules | A human sees the command first. |
| Agent touches production config | `deny-prod-config` | Path based. Over-matches (any `/prod/` folder). |
| Hook errors inside its own code, or gets bad input | Fail safe (ask) | Tested with broken JSON, a missing `vendor/` folder and an unwritable state folder. |
| Hook cannot start (no `python3`), crashes outside its handler, or times out | `"onFailure": "block"` in `hooks.json` (Claude Code 2.1.295+) | On older versions the call goes ahead. Tested: no `python3` gives a non-zero exit, which Claude Code blocks. A timeout is not tested live. |
| Huge command that makes the regex scan slow | `oversize-command` ask over 20000 characters, linear-time regexes | A long command that also holds a deny pattern gets ask, not deny. |
| Agent loops forever | Step cap (ask after 200) | Soft cap. Counts calls, not cost. |
| Injection in a web page | Scan and log | **Detects some, stops none.** |
| Need to see what happened | Redacted audit log | Partial (see limits). |

## What it does NOT cover

### 1. No spend cap
The plugin counts calls. It does not know what a call costs. A loop of expensive calls under the cap can still run up a bill. Set limits at your model provider.

### 2. The model can still follow bad instructions inside allowed tools
Prompt injection is not solved here. The scan looks for six known phrases in the output of web and MCP read tools. It writes a warning to the log. It does not remove the text, and it does not tell the model. A page can say the same thing in other words and pass. If the injected order then asks for a tool call, the policy rules still apply to that call. That is the real defence: the rules judge the action, not the text that caused it.

### 3. Attacks outside Claude Code
Hooks only see Claude Code tool calls. These are out of reach:
- A dependency you install that runs code at install time.
- A script the agent writes and then runs. The hook sees `python script.py`, not what is inside it.
- Anything you do in your own terminal.

### 4. Pattern rules are not a sandbox
Rules match text. A determined agent or attacker can get around them: build a path in a variable, encode a command, read a file through a program the rules do not know. The rules stop the common and the accidental. For hard isolation, use a container or a separate user with no access to the secrets.

### 5. Bypass mode
Claude Code can run with permission checks off. I did not verify what an `ask` answer does in that mode. The docs do not say. Assume only `deny` is a hard stop there.

### 6. Headless runs
In `claude -p`, nobody can answer an ask. The call does not run. This is safe, but the task may stop. The live log in the README shows it.

## Limits of the log

- A declined ask leaves only the `decision` line, not a result line.
- Allowed calls that never ran (for example, an error before they started) are not logged.
- State files are not cleaned up.
- Redaction uses seven patterns (private key, Anthropic key, OpenAI key, AWS access key, AWS secret key, GitHub token, bearer token). A secret in another format is written as is. Do not rely on redaction as the only protection for the log; the files are mode 0600.

## Known false positives

- `*/prod/*` and `*/production/*` deny any absolute path that contains those folder names. For Bash, every word of the command counts as a possible path, so `git commit -m "fix production/config"` is denied too.
- The MCP rule matches names like `..._post`, so a harmless tool such as `get_post` can trigger an ask.
- `ask-git-push` asks for every push, including safe ones. That is on purpose.

## Least privilege and blast radius

The design assumes the agent is useful but fallible. Deny the few things that are never right. Ask for the things that are sometimes right and hard to undo. Allow the rest. That keeps the blast radius of a mistake small without making the agent useless.
