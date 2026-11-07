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


def _text_path(path, cwd):
    """The path as the tool would name it: ~ expanded, joined to cwd, cleaned. No disk call."""
    try:
        return os.path.normpath(os.path.join(cwd, os.path.expanduser(path)))
    except ValueError:  # a NUL byte cannot name a file
        return None


def _roots(cwd):
    """The project folder (CLAUDE_PROJECT_DIR, else cwd), as written and resolved. Two disk-free
    texts and one realpath of one short string per call, never one per candidate."""
    proj = os.environ.get("CLAUDE_PROJECT_DIR") or cwd
    return {r for r in (_text_path(proj, cwd), _real(proj, cwd)) if r}


def _below(path, roots, cwd):
    """The part of the path below the project root, or None when the path is not inside it.

    Text only, no disk call, so big or hostile input costs no more than normpath: ~ expanded,
    joined to the hook's working folder, cleaned (a ".." is folded away), then compared with a "/"
    boundary, never a text prefix. A sibling named like the project and a ".." that leaves it are
    outside. Links are not followed here: the caller passes the resolved form of a named path
    field of a file tool (from _link_targets) as `path`, and every other string as written.
    """
    p = _text_path(path, cwd) if roots and cwd else None
    for root in roots if p else ():
        r = root.rstrip("/")
        if p == root or p.startswith(r + "/"):
            return p[len(r):]
    return None


def _path_forms(path, roots=None, cwd=None, real=None):
    """(whole, below) pairs, one per spelling. Every spelling shares the below part of the path as
    written (placed by text); a resolved form (links followed) is passed in as its own path and
    places itself, so a link that leaves the project is matched whole."""
    below = _below(path, roots, cwd)  # the text spelling places itself
    return [(f, f if below is None else below) for f in _forms(path)]


def path_hit(forms, rule):
    """A form is denied when it matches and no except glob of the same rule excuses that form.

    forms are (whole, below) pairs. A rule with "project_relative": true is matched on the part
    below the project root; every other rule on the whole path.
    """
    i = 1 if rule.get("project_relative") is True else 0
    return any(_glob_hit(f[i], g) for f in forms for g in rule["match"]
               if not any(_glob_hit(f[i], e) for e in rule.get("except", [])))


def rule_hit(rule, tool_name, tool_input, paths=None):
    """paths: the candidate paths as lists of (whole, below) forms; computed here when not given."""
    kind = rule["kind"]
    if kind == "tool":
        return any(re.search(m, tool_name, re.I) for m in rule["match"])
    if kind == "command":
        cmd = tool_input.get("command")
        return (tool_name == "Bash" and isinstance(cmd, str)
                and any(re.search(m, cmd) for m in rule["match"]))
    if paths is None:
        paths = [_path_forms(p) for p in candidate_paths(tool_name, tool_input)]
    return any(path_hit(p, rule) for p in paths)


def _link_targets(tool_name, tool_input, cwd):
    """{path field: its resolved path} for a non-Bash tool: the only place links are followed.

    The resolved path is matched like any other path, as its own entry, and places itself: one
    that resolves inside the project is matched below the root, one that leaves it (a link out)
    in full. The text spelling places itself too, so the check only adds denies to what the text
    spelling gets, but with isolation off the text spelling alone decides: in a project under a
    "prod" folder a link out is then allowed, where the whole path was denied before this rule.
    Every other candidate (Bash words, MCP strings) is placed by text.
    """
    if tool_name == "Bash":
        return {}
    reals = {p: _real(p, cwd) for p in _named_paths(tool_name, tool_input)}
    return {p: r for p, r in reals.items() if r is not None}


def match(policy, tool_name, tool_input, cwd=None, links=True):
    """Strongest rule wins (deny over ask). The first rule of that strength is reported.

    A deny of kind path or command on a shell tool (Bash, PowerShell, Monitor) is returned as ask.

    Returns None when no rule matches. The shipped rules come first and the loop stops at the
    first deny, so a slow regex in an added policy file cannot delay a deny on a file tool or a
    tool rule. A shell text rule only asks and an ask does not stop the loop, so such a regex can
    delay a shipped shell ask. With cwd, a rule with "project_relative": true matches a path
    inside the project root (CLAUDE_PROJECT_DIR, else cwd) below that root, so a project that
    sits in or behind a folder named "prod" keeps its files; that placement is text only. With
    links, a path field of a non-Bash tool is also matched in its resolved form (a link to a
    listed file); that is the only disk call per candidate.
    """
    cmd = tool_input.get("command") if tool_name == "Bash" else None
    if isinstance(cmd, str) and len(cmd) > MAX_COMMAND_CHARS:
        # Regex time grows with input size, and a hook that times out lets the call through.
        return Decision("ask", "oversize-command",
                        "Command is over %d characters, too long to check. Confirm it."
                        % MAX_COMMAND_CHARS, None)
    best = None
    roots = _roots(cwd) if cwd else None
    # once per call, not once per rule
    reals = _link_targets(tool_name, tool_input, cwd) if cwd and links else {}
    paths = [_path_forms(p, roots, cwd, reals.get(p))
             for p in candidate_paths(tool_name, tool_input)]
    paths += [_path_forms(r, roots, cwd) for r in reals.values()]
    for r in policy["rules"]:
        if not rule_hit(r, tool_name, tool_input, paths):
            continue
        dec, reason = r["decision"], r["reason"]
        # Shell text can be spelled another way, so a text match there is an ask, never a refusal.
        # A tool rule matches the tool's name, which cannot be respelled, so it stays a deny. The
        # change is made before ranking, so a later tool deny still wins over an earlier ask.
        if dec == "deny" and r["kind"] != "tool" and tool_name in SHELL_TOOLS:
            dec, reason = "ask", reason + SHELL_NOTE
        if best is None or _RANK[dec] > _RANK[best.decision]:
            best = Decision(dec, r["id"], reason, None)
            if dec == "deny":
                break
    return best


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
