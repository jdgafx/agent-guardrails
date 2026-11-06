"""Secret redaction. Runs before anything is written to the audit log."""
import re

# Order matters: the specific key formats run before the generic ones.
PATTERNS = [
    ("private-key", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)")),
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}")),
    ("openai-key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws-secret-key", re.compile(
        r"(?i)(aws_secret_access_key\s*[=:]\s*)[\"']?[A-Za-z0-9/+=]{30,}[\"']?")),
    ("github-token", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("bearer-token", re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=\-]{8,}")),
]


def redact_text(text):
    """Return text with every known secret format replaced by [REDACTED:<kind>]."""
    for kind, pat in PATTERNS:
        if pat.groups:
            text = pat.sub(lambda m, k=kind: m.group(1) + "[REDACTED:" + k + "]", text)
        else:
            text = pat.sub("[REDACTED:" + kind + "]", text)
    return text


def redact(obj):
    """Redact every string inside a JSON-like structure. Returns a new object."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {redact_text(str(k)): redact(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    return obj


def redact_fields(obj, keys):
    """Redact the string values of the named keys of a dict. Returns a copy; adds no key.

    Anything that is not a dict, and any value that is not a string, is left as it is.
    """
    if not isinstance(obj, dict):
        return obj
    return {k: redact_text(v) if k in keys and isinstance(v, str) else v for k, v in obj.items()}
