"""Load and check policy.json.

The shipped policy (<plugin root>/policy.json) always loads first. Added policy files are merged
into it and can only add: the GUARDRAILS_POLICY file and <data dir>/policy.json. An added file
that is missing, unreadable or invalid is left out and reported; the shipped rules still apply.
Every file is checked against policy.schema.json in full.
A broken shipped policy raises PolicyError. The hook turns that into "ask", never "allow".
"""
import json
import os
import re

KINDS = ("path", "command", "tool")
DECISIONS = ("deny", "ask")

# The schema keywords the checker implements. Any other keyword in the schema is refused, so a
# later schema edit cannot add a check that does nothing.
_ANNOTATIONS = ("$schema", "title", "description")
_KEYWORDS = ("type", "required", "properties", "additionalProperties", "items", "enum", "const",
             "minItems", "minLength", "minimum")


class PolicyError(ValueError):
    pass


def _need(cond, msg):
    if not cond:
        raise PolicyError(msg)


def _regex_ok(pattern, where):
    try:
        re.compile(pattern)
    except re.error as e:
        raise PolicyError("%s: bad regex %r (%s)" % (where, pattern, e)) from None


def check_schema(schema, where="schema"):
    """Refuse a schema that uses a keyword this checker does not implement."""
    _need(isinstance(schema, dict), "%s: a schema must be an object" % where)
    for k, v in schema.items():
        _need(k in _ANNOTATIONS or k in _KEYWORDS, "%s: unknown schema keyword %r" % (where, k))
        if k == "type":
            _need(v in _TYPES, "%s: unknown schema type %r" % (where, v))
        elif k == "properties":
            for name, sub in v.items():
                check_schema(sub, "%s.%s" % (where, name))
        elif k == "items":
            check_schema(v, where + "[]")
        elif k == "additionalProperties":
            _need(v is False, "%s: only additionalProperties false is supported" % where)


_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),  # True is not 1
    "boolean": lambda v: isinstance(v, bool),
}


def _same(a, b):
    return type(a) is type(b) and a == b  # so True and 1.0 do not equal 1


def _walk(v, s, where):
    t = s.get("type")
    if t:
        _need(_TYPES[t](v), "%s: must be of type %s" % (where, t))
    if "const" in s:
        _need(_same(v, s["const"]), "%s: must be %r" % (where, s["const"]))
    if "enum" in s:
        _need(any(_same(v, e) for e in s["enum"]), "%s: must be one of %s" % (where, s["enum"]))
    if "minimum" in s:
        _need(v >= s["minimum"], "%s: must be at least %s" % (where, s["minimum"]))
    if "minLength" in s:
        _need(len(v) >= s["minLength"], "%s: must not be empty" % where)
    if "minItems" in s:
        _need(len(v) >= s["minItems"], "%s: needs at least %d item(s)" % (where, s["minItems"]))
    if isinstance(v, list) and "items" in s:
        for i, x in enumerate(v):
            _walk(x, s["items"], "%s[%d]" % (where, i))
    if isinstance(v, dict):
        props = s.get("properties", {})
        for k in s.get("required", []):
            _need(k in v, "%s: missing key %r" % (where, k))
        for k, x in v.items():
            if k in props:
                _walk(x, props[k], "%s.%s" % (where, k))
            else:
                _need(s.get("additionalProperties") is not False,
                      "%s: unknown key %r" % (where, k))


def validate(p, schema):
    """Check p against policy.schema.json in full, then the things a schema cannot say."""
    check_schema(schema)
    _walk(p, schema, "policy")
    seen = set()
    for r in p.get("rules", []):
        _need(r["id"] not in seen, "rule ids must be unique: %s" % r["id"])
        seen.add(r["id"])
        if r["kind"] != "path":
            for x in r["match"]:
                _regex_ok(x, "rule " + r["id"])
    for key in ("untrusted_tools", "trusted_tools"):
        for x in p.get(key, []):
            _regex_ok(x, key)
    for mk in p.get("injection_markers", []):
        _regex_ok(mk["pattern"], "injection marker " + mk["id"])
    return p


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise PolicyError("cannot read: %s" % e) from None


def _merge(base, extra):
    """Add the rules, markers and tool names of extra; take the lower step cap. Never remove.

    The one exception is trusted_tools: a name listed there is not scanned for injection (a log
    warning only, never a deny or an ask). "isolation" only goes one way: true in any file wins.
    """
    base["rules"] += [r for r in extra.get("rules", []) if r not in base["rules"]]
    base["isolation"] = bool(base.get("isolation")) or extra.get("isolation") is True
    for key in ("untrusted_tools", "trusted_tools", "injection_markers"):
        have = base.get(key, [])
        base[key] = have + [x for x in extra.get(key, []) if x not in have]
    cap = extra.get("step_cap", {}).get("max_calls")
    if cap is not None:
        base["step_cap"]["max_calls"] = min(base["step_cap"]["max_calls"], cap)
    # "audit" is ignored: a smaller value would weaken the log.


def _added_files(data):
    env = os.environ.get("GUARDRAILS_POLICY")
    files = [(env, True)] if env else []
    if data:
        files.append((os.path.join(data, "policy.json"), False))
    return files


def load_policy(root, data):
    """Return (policy, errors): shipped policy plus every added file that is valid.

    errors holds one line per added file that was left out. Raises PolicyError if the shipped
    policy or the schema is broken.
    """
    where = os.path.join(root, "policy.json")
    schema = _read(os.path.join(root, "policy.schema.json"))
    try:
        pol = validate(_read(where), schema)
        _need("rules" in pol, "missing key 'rules'")
        _need("max_calls" in pol.get("step_cap", {}), "step_cap.max_calls is required")
    except PolicyError as e:
        raise PolicyError("%s: %s" % (where, e)) from None
    errors = []
    for path, must_exist in _added_files(data):
        try:
            if not os.path.lexists(path):
                _need(not must_exist, "does not exist")
                continue  # no <data>/policy.json is the normal case
            _need(os.path.isfile(path), "not a regular file")
            _merge(pol, validate(_read(path), schema))
        except PolicyError as e:
            errors.append("%s: %s" % (path, e))
    return pol, errors
