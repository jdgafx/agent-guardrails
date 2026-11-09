"""A $SHELL for agents that run commands through the user's shell (Codex, Aider, OpenHands):

    python3 -m guardrails_core.shell_guard -c "<cmd>"

The command goes through the Bash rules and the audit log (secrets replaced), then the real shell
(GUARDRAILS_REAL_SHELL, else /bin/bash) takes this process's place. Nobody can be asked from
here, so an ask is refused like a deny: the reason goes to stderr and the exit code is 126.

Only -c commands are checked. Started any other way (a login shell, a script file, commands on
stdin) the real shell runs unchanged. One parent process is one session (GUARDRAILS_SESSION names
another); GUARDRAILS_AGENT is the agent name in the log (default "shell").
"""
import os
import re
import sys

from . import adapters, audit
from .policy import load_policy

_C_FLAG = re.compile(r"-[A-Za-z]*c[A-Za-z]*")  # -c, -lc, -ic ...


def command_of(argv):
    """The text after the first -c style option, or None. A "-c" that belongs to a script's own
    arguments is read as a command too: that only adds a check, it never skips one."""
    for i, a in enumerate(argv[:-1]):
        if _C_FLAG.fullmatch(a):
            return argv[i + 1]
    return None


def _check(cmd):
    """(decision, reason). An allowed command gets its log line here: nothing runs after exec."""
    root, data = adapters.plugin_root(), adapters.data_dir()
    agent = os.environ.get("GUARDRAILS_AGENT") or "shell"
    sid = os.environ.get("GUARDRAILS_SESSION") or "shell-%d" % os.getppid()
    tid = "sh-%d" % os.getpid()
    call = {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": sid,
            "tool_use_id": tid, "cwd": os.getcwd(), "agent": agent}
    _, decision, reason = adapters.check("generic", call, root, data)
    if decision == "allow":
        prior = audit.recall_decision(data, sid, tid)
        audit.write_audit(data, {
            "session_id": sid, "tool_name": "Bash", "tool_use_id": tid, "event": "result",
            "decision": "allow", "rule": prior.get("rule"), "step": prior.get("step"),
            "input": call["tool_input"], "status": "started", "agent": agent},
            load_policy(root, data)[0])
    return decision, reason


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    real = os.environ.get("GUARDRAILS_REAL_SHELL") or (
        "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh")
    cmd = command_of(argv)
    if cmd is not None:
        try:
            decision, reason = _check(cmd)
        except Exception as e:  # an unchecked or unlogged command does not run
            decision, reason = "ask", "[guardrails-error] %s: %s" % (type(e).__name__, e)
        if decision != "allow":
            sys.stderr.write("agent-guardrails: not run (%s). %s%s\n" % (
                decision, reason, adapters.NO_ASK % "A shell wrapper" if decision == "ask" else ""))
            return 126
    sys.stdout.flush()
    os.execv(real, [real] + list(argv))


if __name__ == "__main__":
    sys.exit(main())
