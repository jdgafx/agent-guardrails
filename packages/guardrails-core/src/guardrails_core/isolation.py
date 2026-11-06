"""Opt-in isolation: the sandbox settings block, and the check that it is in force.

The plugin builds no sandbox. It generates the settings block for Claude Code's own Bash sandbox
from two rules of the shipped policy (`sandbox_block`), and Pre refuses shell calls when the block
is not in the project's settings files (`block_in_force`). The tripwire is a check for user
mistakes, not a barrier: managed settings, `--settings` and user settings are invisible to it.
"""
import json
import os
import sys

from . import rules

# The secret list: the `match` globs of these two shipped rules. `deny-key-files` is left out
# (a mask on every *.pem would hide certifi's cacert.pem in a project virtual environment).
ISOLATED_RULES = ("deny-env-files", "deny-credential-dirs")
# Project anywhere below, directly in the home folder, directly in ~/.config. Never `~/**` or
# `/**`: that made every sandboxed command take 100 to 187 s on a large home folder.
ANCHORS = ("./**/", "~/", "~/.config/")
SHELL_TOOLS = rules.SHELL_TOOLS

_FLAGS = (("enabled", True), ("failIfUnavailable", True), ("allowUnsandboxedCommands", False),
          ("autoAllowBashIfSandboxed", False))
# The keys a project may have under "sandbox" and still count as the block: the block's own, and
# the ones that can only narrow it. Any other key does not: allowWrite and network.allowedDomains
# widen it, and so do excludedCommands, network.allowAllUnixSockets, enableWeakerNestedSandbox and
# a key a later Claude Code adds.
_ALLOWED = {"enabled": None, "failIfUnavailable": None, "allowUnsandboxedCommands": None,
            "autoAllowBashIfSandboxed": None,
            "filesystem": {"denyRead": None, "allowRead": None, "denyWrite": None},
            "network": {"deniedDomains": None}}


def _core(glob):
    """`*/.aws/*` and `*/.aws` both give `.aws`; `*/gh/hosts.yml` gives `gh/hosts.yml`."""
    if glob.startswith("*/"):
        glob = glob[2:]
    return glob[:-2] if glob.endswith("/*") else glob


def _paths(globs):
    out = []
    for g in globs:
        for a in ANCHORS:
            if a + _core(g) not in out:
                out.append(a + _core(g))
    return out


def sandbox_block(policy):
    """The settings block for the first rule of each isolated id. Added rules never change it."""
    seen, deny, allow = set(), [], []
    for r in policy["rules"]:
        if r["id"] in ISOLATED_RULES and r["id"] not in seen:
            seen.add(r["id"])
            deny += [p for p in _paths(r["match"]) if p not in deny]
            allow += [p for p in _paths(r.get("except", [])) if p not in allow]
    sandbox = {k: v for k, v in _FLAGS}
    sandbox["filesystem"] = {"denyRead": deny, "allowRead": allow}
    return {"sandbox": sandbox}


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
        # An empty file adds no key. The sandbox makes a zero-byte placeholder for
        # .claude/settings.json while a command runs, so a parallel call's Pre can see one.
        obj = json.loads(text) if text.strip() else {}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        raise ValueError("%s cannot be read as JSON (%s)" % (path, e)) from None
    if not isinstance(obj, dict) or not isinstance(obj.get("sandbox", {}), dict):
        raise ValueError("%s: \"sandbox\" must be an object" % path)
    return obj


def _merge(base, over):
    """Claude Code's merge: a boolean from the local file wins, lists are joined."""
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        elif isinstance(v, list) and isinstance(out.get(k), list):
            out[k] = out[k] + [x for x in v if x not in out[k]]
        else:
            out[k] = v
    return out


def _unknown(obj, allowed, where="sandbox"):
    for k, v in obj.items():
        if k not in allowed:
            return "%s.%s is not a key the block allows" % (where, k)
        if isinstance(allowed[k], dict):
            if not isinstance(v, dict):
                return "%s.%s must be an object" % (where, k)
            bad = _unknown(v, allowed[k], where + "." + k)
            if bad:
                return bad
    return None


def _write_grants(perms):
    """The two permission settings that, per the Claude Code docs, add sandbox write paths."""
    if not isinstance(perms, dict):
        return False, "permissions must be an object"
    if "additionalDirectories" in perms:
        return False, ("permissions.additionalDirectories widens where a sandboxed command may "
                       "write")
    allow = perms.get("allow", [])
    if not isinstance(allow, list):
        return False, "permissions.allow must be a list"
    for entry in allow:
        # a permission rule's tool name is the text before "(": no path is matched here
        if isinstance(entry, str) and entry.split("(", 1)[0].strip() == "Edit":
            return False, ("permissions.allow holds %s, which widens where a sandboxed command "
                           "may write" % entry)
    return True, ""


def block_in_force(project_dir, policy):
    """(True, "") when the project's settings files hold the block, else (False, first failure).

    Reads `.claude/settings.json` and `.claude/settings.local.json` of project_dir and merges
    them. Under "sandbox" only the keys of `_ALLOWED` pass. Outside it, the settings that add
    sandbox write paths (`permissions.additionalDirectories`, `Edit` allow rules) fail. An
    unreadable file, bad JSON or any other trouble is a failure, never a pass.
    """
    try:
        merged = {}
        for name in rules.SETTINGS:  # shared first, so the local file wins
            merged = _merge(merged, _read(os.path.join(project_dir, ".claude", name)))
        sb = merged.get("sandbox", {})
        want = sandbox_block(policy)["sandbox"]
        for k, v in _FLAGS:
            if sb.get(k) is not v:
                return False, "sandbox.%s is not %s" % (k, json.dumps(v))
        bad = _unknown(sb, _ALLOWED)
        if bad:
            return False, bad
        fs = sb.get("filesystem", {})
        for key in ("denyRead", "allowRead"):
            if not isinstance(fs.get(key, []), list):
                return False, "sandbox.filesystem.%s must be a list" % key
        for entry in want["filesystem"]["denyRead"]:
            if entry not in fs.get("denyRead", []):
                return False, "sandbox.filesystem.denyRead lacks %s" % entry
        for entry in fs.get("allowRead", []):
            if entry not in want["filesystem"]["allowRead"]:
                return False, "sandbox.filesystem.allowRead holds %s, not in the block" % entry
        return _write_grants(merged.get("permissions", {}))
    except Exception as e:  # an unchecked shell call is the case this layer exists to stop
        return False, "%s: %s" % (type(e).__name__, e)


def not_active_reason(project_dir, root, why):
    # The merged settings do not say which file holds a key, so the reason names both files.
    shared = os.path.join(project_dir, ".claude", "settings.json")
    local = os.path.join(project_dir, ".claude", "settings.local.json")
    block = os.path.join(root, "isolation", "settings.local.json")
    return ("Isolation is on, but the sandbox block is not in force in %s or %s: %s. Fix that "
            "setting in the file that holds it: remove it if it is a setting the block does not "
            "allow; if a sandbox setting is missing, merge the \"sandbox\" key of %s into %s and "
            "keep your other settings." % (shared, local, why, block, local))


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as f:
        sys.stdout.write(json.dumps(sandbox_block(json.load(f)), indent=2) + "\n")
