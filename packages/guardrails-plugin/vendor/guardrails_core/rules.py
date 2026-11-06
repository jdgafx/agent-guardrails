"""Rule matching: turn (tool name, tool input, step number) into deny / ask / allow."""
import fnmatch
import os
import re
from collections import namedtuple

Decision = namedtuple("Decision", "decision rule reason step")

SHELL_TOOLS = ("Bash", "PowerShell", "Monitor")
SHELL_NOTE = (" This is a shell command, so the guard asks instead of denying: shell text can be "
              "spelled in ways no rule matches (README, \"What holds each threat\").")

MAX_COMMAND_CHARS = 20000
PATH_KEYS = ("file_path", "path", "notebook_path")
_SPLIT = re.compile(r"[\s;&|<>=()\"'`]+")
_RANK = {"deny": 2, "ask": 1}


# Text fields of built-in tools: text the tool writes, searches for or sends, never a local path it
# opens. The walk skips them, so "add .env to .gitignore" can be written. Every other string is a
# candidate. `command` is split into words instead of being walked. "*" skips the whole input
# (StructuredOutput carries the workflow's own free-form answer fields). Names come from the tool
# schemas of Claude Code; a tool missing here is checked in full (a visible deny, never silent).
TEXT_FIELDS = {
    "Bash": ("description", "command"), "Write": ("content",), "Edit": ("old_string", "new_string"),
    "MultiEdit": ("edits",), "NotebookEdit": ("new_source",), "Grep": ("pattern",),
    "WebFetch": ("url", "prompt"), "WebSearch": ("query",), "Agent": ("prompt", "description"),
    "Task": ("prompt", "description"), "TodoWrite": ("todos",), "AskUserQuestion": ("questions",),
    "ExitPlanMode": ("plan", "allowedPrompts"), "ToolSearch": ("query",),
    "SendMessage": ("message", "summary"), "PushNotification": ("message",),
    "TaskCreate": ("subject", "description", "activeForm", "metadata"),
    "TaskUpdate": ("subject", "description", "activeForm", "metadata"),
    "CronCreate": ("prompt",), "Skill": ("args",), "StructuredOutput": "*",
}


def _named_paths(tool_name, tool_input):
    """The guard check's strings: the three named path fields, or every word of a Bash command."""
    if tool_name == "Bash":
        return [t for t in _SPLIT.split(str(tool_input.get("command", ""))) if t]
    keys = PATH_KEYS + (("pattern",) if tool_name == "Glob" else ())
    return [str(tool_input[k]) for k in keys if isinstance(tool_input.get(k), str)]


def candidate_paths(tool_name, tool_input):
    """Strings that might be file paths: every string of the input at any depth, dict keys
    included, except the text fields of built-in tools. Bash also gets every word of the command.
    An explicit stack, no size cap: deep or padded input must not turn a deny into an error or ask.
    """
    skip = TEXT_FIELDS.get(tool_name, ())
    if skip == "*":
        return []
    todo = [x for k, v in tool_input.items() if k not in skip for x in (k, v)]
    out = _named_paths(tool_name, tool_input) if tool_name == "Bash" else []
    while todo:
        x = todo.pop()
        if isinstance(x, str):
            if x:
                out.append(x)
        elif isinstance(x, dict):
            todo.extend(y for kv in x.items() for y in kv)
        elif isinstance(x, (list, tuple)):
            todo.extend(x)
    return out


def _glob_hit(path, glob):
    """Globs without a slash match the file name. Others match the whole path."""
    path, glob = path.lower(), glob.lower()
    if "/" in glob:
        full = "/" + path.lstrip("/")  # so "*/.ssh/*" also matches ".ssh/id_rsa"
        return fnmatch.fnmatchcase(full, glob)
    return fnmatch.fnmatchcase(os.path.basename(path), glob)


def _forms(path):
    """As written, with ~ expanded, and both cleaned up (/./ and // and a trailing / removed)."""
    try:
        forms = {path, os.path.expanduser(path)}
    except ValueError:  # a NUL byte after ~ cannot name a file; the other forms still count
        forms = {path}
    return forms | {os.path.normpath(f) for f in forms}


def path_hit(path, rule):
    """A form is denied when it matches and no except glob of the same rule excuses that form."""
    return any(_glob_hit(f, g) for f in _forms(path) for g in rule["match"]
               if not any(_glob_hit(f, e) for e in rule.get("except", [])))


def rule_hit(rule, tool_name, tool_input, paths=None):
    kind = rule["kind"]
    if kind == "tool":
        return any(re.search(m, tool_name, re.I) for m in rule["match"])
    if kind == "command":
        cmd = tool_input.get("command")
        return (tool_name == "Bash" and isinstance(cmd, str)
                and any(re.search(m, cmd) for m in rule["match"]))
    if paths is None:
        paths = candidate_paths(tool_name, tool_input)
    return any(path_hit(p, rule) for p in paths)


def _link_targets(tool_name, tool_input, cwd):
    """The resolved form of each path field of a non-Bash tool, where a link was followed.

    A path with no link in it is skipped, so a project under a folder named "production" does not
    get its plain files denied. The check only adds denies (the link check of isolation).
    """
    if tool_name == "Bash":
        return []
    base = _real("", cwd)
    out = []
    for p in _named_paths(tool_name, tool_input):
        real = _real(p, cwd)
        try:
            plain = os.path.normpath(os.path.join(base, os.path.expanduser(p)))
        except ValueError:
            continue
        if real is not None and real != plain:
            out.append(real)
    return out


def match(policy, tool_name, tool_input, cwd=None):
    """Strongest rule wins (deny over ask). The first rule of that strength is reported.

    A deny of kind path or command on a shell tool (Bash, PowerShell, Monitor) is returned as ask.

    Returns None when no rule matches. The shipped rules come first, so a slow regex in an added
    policy file cannot delay a shipped deny. With cwd, a path field of a non-Bash tool is also
    matched in its resolved form (a link to a listed file).
    """
    cmd = tool_input.get("command") if tool_name == "Bash" else None
    if isinstance(cmd, str) and len(cmd) > MAX_COMMAND_CHARS:
        # Regex time grows with input size, and a hook that times out lets the call through.
        return Decision("ask", "oversize-command",
                        "Command is over %d characters, too long to check. Confirm it."
                        % MAX_COMMAND_CHARS, None)
    best = None
    paths = candidate_paths(tool_name, tool_input)  # once per call, not once per rule
    if cwd:
        paths += _link_targets(tool_name, tool_input, cwd)
    for r in policy["rules"]:
        if rule_hit(r, tool_name, tool_input, paths) and (
                best is None or _RANK[r["decision"]] > _RANK[best["decision"]]):
            best = r
            if r["decision"] == "deny":
                break
    if best is None:
        return None
    d = Decision(best["decision"], best["id"], best["reason"], None)
    # Shell text can be spelled another way, so a text match there is an ask, never a refusal.
    # A tool rule matches the tool's name, which cannot be respelled, so it stays a deny.
    if d.decision == "deny" and best["kind"] != "tool" and tool_name in SHELL_TOOLS:
        d = d._replace(decision="ask", reason=d.reason + SHELL_NOTE)
    return d


def cap(policy, step):
    """Ask once the session has made more tool calls than the step cap."""
    limit = policy.get("step_cap", {}).get("max_calls")
    if limit and step is not None and step > limit:
        why = "Step cap reached: %d tool calls this session (cap %d)." % (step, limit)
        return Decision("ask", "step-cap", why, step)
    return None


def evaluate(policy, tool_name, tool_input, step):
    d = match(policy, tool_name, tool_input) or cap(policy, step)
    if d is None:
        return Decision("allow", "default-allow", "No rule matched.", step)
    return d._replace(step=step)


def stronger(a, b):
    """The stronger of two decisions or None; on a tie the first wins."""
    if a is None or b is None:
        return a or b
    return b if _RANK[b.decision] > _RANK[a.decision] else a


# ---- guard paths: the plugin folder, the data folder and the GUARDRAILS_POLICY file

Guard = namedtuple("Guard", "dirs files")
WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
SETTINGS = ("settings.json", "settings.local.json")


def guard_paths(root, data, env_file):
    dirs = [os.path.realpath(d) for d in (root, data) if d]
    return Guard(dirs, [os.path.realpath(env_file)] if env_file else [])


def _inside(path, guard):
    return path is not None and (path in guard.files or any(
        path == d or path.startswith(d.rstrip("/") + "/") for d in guard.dirs))


def _real(path, cwd):
    """The resolved path, or None for a string that cannot name a file (a NUL byte)."""
    try:
        return os.path.realpath(os.path.join(cwd, os.path.expanduser(path)))
    except ValueError:
        return None


def guard_check(tool_name, tool_input, guard, cwd):
    """Deny a write tool on a guard path, ask for a Bash word that names one.

    shortcut: Bash gets only words that are absolute or ~ paths. Bash writes through variables,
    relative paths or interpreters are not seen (docs/THREAT_MODEL.md, limit 7); the barrier for
    those is Claude Code's sandbox. Do not add more spellings.
    """
    if tool_name == "Bash":
        words = [w for w in _named_paths(tool_name, tool_input) if w[0] in "/~"]
        if any(_inside(_real(w, cwd), guard) for w in words):
            return Decision("ask", "ask-guard-paths",
                            "This command names a file of the guard (plugin folder, data folder "
                            "or policy file). Confirm it.", None)
        return None
    if tool_name not in WRITE_TOOLS and not tool_name.startswith("mcp__"):
        return None
    paths = [_real(p, cwd) for p in _named_paths(tool_name, tool_input)]
    if any(_inside(p, guard) for p in paths):
        return Decision("deny", "deny-guard-files",
                        "Claude may not change the guard's own files (plugin folder, data folder, "
                        "policy file). Edit them yourself.", None)
    homes = [os.path.join(h, ".claude") for h in
             (cwd, os.environ.get("CLAUDE_PROJECT_DIR") or cwd, os.path.expanduser("~"))]
    cfg = os.environ.get("CLAUDE_CONFIG_DIR")  # Claude Code's user settings folder when set
    if cfg and "\0" not in cfg:
        homes.append(os.path.join(cwd, cfg))
    mine = {os.path.realpath(os.path.join(h, n)) for h in homes for n in SETTINGS}
    if any(p in mine for p in paths):
        return Decision("ask", "ask-claude-settings",
                        "This changes a Claude Code settings file, which can switch the guard "
                        "off. Confirm it.", None)
    return None
