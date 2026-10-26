# Interview guide

How to explain this project. Everything here matches the code. If a claim is not in the repo, do not say it.

## 30 seconds

"I built a Claude Code plugin that checks every tool call before it runs. A policy file says what to deny, what to ask about, and what to allow. If the guard itself breaks, it asks a human or blocks the call instead of failing open. It keeps a redacted audit log, caps runaway sessions, and scans web output for injection phrases. It runs on stock Python with no install step, and I wrote down what it does not cover."

## 3 minutes

1. **Problem.** An AI coding agent runs shell commands and reads files for you. Most of the time that is fine. Sometimes it reads your `.env`, force-pushes, or deploys to production.
2. **Idea.** Claude Code lets a hook run before every tool call and answer deny, ask or allow. I put the rules in a JSON policy and the engine in a small library.
3. **Seven controls.** Least privilege (deny), approval gates (ask), audit trail, step cap, secret redaction, untrusted input, fail safe.
4. **Hard part: packaging.** A plugin is a folder copy. Hooks run on whatever `python3` the user has. No pip step. So I vendor the library into the plugin and check by test and CI that the copy has not drifted.
5. **Proof.** Unit tests for each rule. End-to-end tests that copy the plugin and run the real hook commands on stock Python. A demo with 24 calls. A real Claude session whose audit log is pasted in the README.
6. **Honesty.** No spend cap. Injection is logged, not blocked. Pattern rules are not a sandbox. Those limits are in the README and the threat model.

## Decisions and tradeoffs

| Decision | Why | What I gave up |
|----------|-----|----------------|
| Ask on internal error, not deny or allow | Allow lets danger through. Deny breaks the user's work and gets the plugin removed. Ask keeps a human in charge. | A broken hook interrupts the user. |
| Vendor core into the plugin | Plugins have no install step. | Two copies of the code in git; I added a drift test and a CI check. |
| Standard library only | Runs anywhere with `python3`. Nothing to install or audit. | No fast JSON schema library or regex extras in the hook. |
| Strongest rule wins | Easy to explain. Deny can never be weakened by a later allow. | You cannot write an allow exception for a deny. |
| Scan and log injection, never inject or rewrite | A phrase match gives false positives. Changing tool output is hard to audit. | It does not stop an injection. |
| JSONL file, no server | `grep` and `jq` work. No part to run. | No dashboard or search. |
| Soft step cap | A file lock adds code and failure modes. | Parallel calls can share a number. |

## Questions you will get

**1. Why a plugin and not a settings file with permission rules?**
Claude Code's own permission rules are good for simple allow and deny lists. A hook can also fail safe, count steps, redact and write an audit log, and scan output. They work together. I did not replace the built-in rules.

**2. What if the hook crashes?**
Two layers. Inside the script: bad input, a broken policy, a missing vendor folder or an unwritable state folder all end in `ask`, with tests for each, and a deny stays a deny. Outside the script: Claude Code lets a call through by default when a hook cannot start or times out, so `hooks.json` sets `"onFailure": "block"` (Claude Code 2.1.295 or later). A reviewer found that gap in my first version: a 60 KB command made the regex scan run past the timeout. I fixed the regexes, added a 20000-character `ask` limit and turned on `onFailure`.

**3. Why ask and not deny when it breaks?**
A guard that blocks everything when it is broken gets uninstalled. Ask keeps the human in the loop. This is "fail closed" with a way out.

**4. Can the agent get around the rules?**
Yes, if it tries. Rules match text, so an encoded command or a script that reads the file can slip through. The rules stop common and accidental harm. For hard isolation, use a container. This is in the threat model.

**5. Does it stop prompt injection?**
No. It scans the output of web and MCP read tools for six phrases and logs a warning. It never changes what the model sees. The real defence is that the rules judge the action, whatever caused it.

**6. Why is there no spend cap?**
A hook does not receive the cost of a call. I could only count calls, and a count is not money. I did not claim more than I built.

**7. How do you know the plugin works from a plain folder copy?**
The end-to-end test copies the plugin to a temp folder and runs the commands from `hooks.json` with `PATH=/usr/bin:/bin`. There is also a test that removes `vendor/` and checks the answer is `ask`.

**8. How do you keep the vendored copy honest?**
A unit test compares each file with core byte for byte. CI runs `make build` and `git diff --exit-code`.

**9. How do secrets stay out of the log?**
Seven patterns are replaced with `[REDACTED:kind]` before the line is written. The file is mode 0600. A secret in a format I do not match would be logged. That limit is documented.

**10. What would you do next?**
Test on Python 3.8. Add a file lock for an exact step cap. Check what `ask` does in bypass mode. Add a policy test command so users can try a rule before they ship it.

**11. What went wrong while building it?**
My first broken-install test passed for the wrong reason: the test ran under a virtualenv that had the library installed, so a missing vendor folder did not fail. I fixed the test to run the same `python3` command the hook config uses.

## Things not to claim

- That it "prevents prompt injection".
- That it caps spend.
- That it is a sandbox.
- That it works on Python 3.8 (untested).
- That it fails closed on Claude Code older than 2.1.295 (`onFailure` is ignored there).
