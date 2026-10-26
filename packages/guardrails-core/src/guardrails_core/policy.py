"""Load and check policy.json.

Lookup order: GUARDRAILS_POLICY env var, then <data dir>/policy.json (your edits survive
plugin updates), then the policy.json shipped in the plugin root.
A broken policy raises PolicyError. The hook turns every error into "ask", never "allow".
"""
import json
import os
import re

KINDS = ("path", "command", "tool")
DECISIONS = ("deny", "ask")


class PolicyError(ValueError):
    pass


def find_policy_path(root, data):
    env = os.environ.get("GUARDRAILS_POLICY")
    candidates = [env] if env else []
    if data:
        candidates.append(os.path.join(data, "policy.json"))
    candidates.append(os.path.join(root, "policy.json"))
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    raise PolicyError("no policy.json found (looked in: %s)" % ", ".join(candidates))


def _need(cond, msg):
    if not cond:
        raise PolicyError(msg)


def _regex_ok(pattern, where):
    try:
        re.compile(pattern)
    except re.error as e:
        raise PolicyError("%s: bad regex %r (%s)" % (where, pattern, e)) from None


def validate(p):
    """Check the parts the engine relies on. The full contract is policy.schema.json."""
    _need(isinstance(p, dict) and p.get("version") == 1, "policy must be an object with version 1")
    rules = p.get("rules")
    _need(isinstance(rules, list) and rules, "rules must be a non-empty list")
    seen = set()
    for r in rules:
        _need(isinstance(r, dict), "each rule must be an object")
        rid = r.get("id")
        _need(isinstance(rid, str) and rid and rid not in seen, "rule ids must be unique strings")
        seen.add(rid)
        _need(r.get("decision") in DECISIONS, "rule %s: decision must be deny or ask" % rid)
        _need(r.get("kind") in KINDS, "rule %s: kind must be one of %s" % (rid, KINDS))
        m = r.get("match")
        _need(isinstance(m, list) and m and all(isinstance(x, str) for x in m),
              "rule %s: match must be a list of strings" % rid)
        _need(isinstance(r.get("reason"), str), "rule %s: reason must be a string" % rid)
        _need(all(isinstance(x, str) for x in r.get("except", [])),
              "rule %s: except must be a list of strings" % rid)
        if r["kind"] != "path":
            for x in m:
                _regex_ok(x, "rule " + rid)
    cap = p.get("step_cap", {}).get("max_calls", 1)
    _need(isinstance(cap, int) and not isinstance(cap, bool) and cap >= 1,
          "step_cap.max_calls must be an integer >= 1")
    for x in p.get("untrusted_tools", []):
        _regex_ok(x, "untrusted_tools")
    for mk in p.get("injection_markers", []):
        _need(isinstance(mk, dict) and "id" in mk and "pattern" in mk,
              "injection_markers need id and pattern")
        _regex_ok(mk["pattern"], "injection marker " + str(mk["id"]))
    return p


def load_policy(root, data):
    path = find_policy_path(root, data)
    try:
        with open(path, encoding="utf-8") as f:
            p = json.load(f)
    except (OSError, ValueError) as e:
        raise PolicyError("cannot read %s: %s" % (path, e)) from None
    return validate(p)
