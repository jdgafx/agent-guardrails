"""Rule matching: turn (tool name, tool input, step number) into deny / ask / allow."""
import fnmatch
import os
import re
from collections import namedtuple

Decision = namedtuple("Decision", "decision rule reason step")

MAX_COMMAND_CHARS = 20000
PATH_KEYS =("file_path", "path", "notebook_path")
_SPLIT = re.compile(r"[\s;&|<>=()\"'`]+")
_RANK = {"deny": 2, "ask": 1}


def candidate_paths(tool_name, tool_input):
    """Strings that might be file paths. Bash gets every word of the command."""
    if tool_name == "Bash":
        return [t for t in _SPLIT.split(str(tool_input.get("command", ""))) if t]
    keys = PATH_KEYS + (("pattern",) if tool_name == "Glob" else ())
    return [str(tool_input[k]) for k in keys if isinstance(tool_input.get(k), str)]


def _glob_hit(path, glob):
    """Globs without a slash match the file name. Others match the whole path."""
    path, glob = path.lower(), glob.lower()
    if "/" in glob:
        full = "/" + path.lstrip("/")  # so "*/.ssh/*" also matches ".ssh/id_rsa"
        return fnmatch.fnmatchcase(full, glob)
    return fnmatch.fnmatchcase(os.path.basename(path), glob)


def path_hit(path, rule):
    variants = {path, os.path.expanduser(path)}
    hit = any(_glob_hit(v, g) for v in variants for g in rule["match"])
    return hit and not any(_glob_hit(v, g) for v in variants for g in rule.get("except", []))


def rule_hit(rule, tool_name, tool_input):
    kind = rule["kind"]
    if kind == "tool":
        return any(re.search(m, tool_name, re.I) for m in rule["match"])
    if kind == "command":
        cmd = tool_input.get("command")
        return (tool_name == "Bash" and isinstance(cmd, str)
                and any(re.search(m, cmd) for m in rule["match"]))
    return any(path_hit(p, rule) for p in candidate_paths(tool_name, tool_input))


def evaluate(policy, tool_name, tool_input, step):
    """Strongest rule wins (deny over ask). The first rule of that strength is reported."""
    cmd = tool_input.get("command") if tool_name == "Bash" else None
    if isinstance(cmd, str) and len(cmd) > MAX_COMMAND_CHARS:
        # Regex time grows with input size, and a hook that times out lets the call through.
        return Decision("ask", "oversize-command",
                        "Command is over %d characters, too long to check. Confirm it."
                        % MAX_COMMAND_CHARS, step)
    best = None
    for r in policy["rules"]:
        if rule_hit(r, tool_name, tool_input) and (
                best is None or _RANK[r["decision"]] > _RANK[best["decision"]]):
            best = r
    cap = policy.get("step_cap", {}).get("max_calls")
    if best is None and cap and step > cap:
        why = "Step cap reached: %d tool calls this session (cap %d)." % (step, cap)
        return Decision("ask", "step-cap", why, step)
    if best is None:
        return Decision("allow", "default-allow", "No rule matched.", step)
    return Decision(best["decision"], best["id"], best["reason"], step)
