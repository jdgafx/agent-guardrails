"""Untrusted-input scan: finds prompt-injection markers in tool results, never edits them."""
import json
import re

from .redact import redact_text

MAX_SCAN_CHARS = 200000


def is_untrusted_tool(policy, tool_name):
    return any(re.search(p, tool_name) for p in policy.get("untrusted_tools", []))


def result_text(tool_response):
    if isinstance(tool_response, str):
        return tool_response
    try:
        return json.dumps(tool_response, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(tool_response)


def scan(policy, tool_response):
    """Return one warning per marker that matched. Excerpts are redacted and short."""
    text = result_text(tool_response)[:MAX_SCAN_CHARS]
    found = []
    for mk in policy.get("injection_markers", []):
        m = re.search(mk["pattern"], text, re.I)
        if m:
            found.append({"warning": "prompt-injection-suspected", "marker": mk["id"],
                          "excerpt": redact_text(m.group(0))[:80]})
    return found
