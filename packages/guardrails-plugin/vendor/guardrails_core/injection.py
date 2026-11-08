"""Injection scan: finds prompt-injection markers in tool results and reports them, no edits.

It is a signal, not a shield: hooks.py tells Claude and the person, and marks the session. Every
tool is scanned unless a trusted_tools pattern names it. The scan reads the text values of the
response, normalizes them, and runs the markers under one time limit.
"""
import json
import re
import signal
import threading
import unicodedata

from .redact import redact_text

MAX_SCAN_CHARS = 200000
SCAN_SECONDS = 3

# A long run with no whitespace in the base64 alphabet (or a base64 data URL) is image or file
# data. Every marker needs whitespace, so it cannot hold a match, and it would fill the cap.
_BASE64 = re.compile(r"(?:data:[^,\s]{0,100};base64,)?[A-Za-z0-9+/=_-]{1000,}")
# Whitespace, and the two-character escapes MCP servers leave when they put JSON inside text.
_GAPS = re.compile(r"(?:\s|\\[nrt])+")


class ScanTimeout(BaseException):
    """Raised by the timer; a BaseException so a marker's own error handling cannot hide it."""


def named_untrusted(policy, tool_name):
    """True when an untrusted_tools pattern names the tool: its hits mark the session."""
    return any(re.search(p, tool_name) for p in policy.get("untrusted_tools", []))


def is_scanned(policy, tool_name):
    """True unless a trusted_tools pattern names the tool and no untrusted_tools pattern does."""
    if named_untrusted(policy, tool_name):
        return True
    return not any(re.search(p, tool_name) for p in policy.get("trusted_tools", []))


# A character json.dumps writes as more than itself: a quote, a backslash or a control character.
_ESCAPED = re.compile(r'[\x00-\x1f"\\]')
_SHORT = "\b\t\n\f\r"  # controls written as 2 bytes; the other controls take 6


def _quoted_size(s):
    """UTF-8 size of json.dumps(s, ensure_ascii=False), without building that text."""
    m = _ESCAPED.findall(s)  # a plain string has none: no per-character work
    n = (len(s) if s.isascii() else len(s.encode("utf-8", "surrogatepass"))) + 2 + len(m)
    return n + 4 * sum(1 for c in m if c < " " and c not in _SHORT)


def result_bytes(resp):
    """UTF-8 size of the response as JSON text (a plain string counts as itself).

    Counted by walking the response, so a big page is not copied whole as a second text.
    """
    if isinstance(resp, str):
        return len(resp.encode("utf-8", "surrogatepass"))
    total, stack = 0, [resp]
    try:
        while stack:
            v = stack.pop()
            if isinstance(v, str):
                total += _quoted_size(v)
            elif isinstance(v, dict):
                total += 2 + 2 * len(v) + 2 * max(len(v) - 1, 0)  # braces, ": ", ", "
                for k, x in v.items():
                    total += _quoted_size(k if isinstance(k, str) else json.dumps(k))
                    stack.append(x)
            elif isinstance(v, (list, tuple)):
                total += 2 + 2 * max(len(v) - 1, 0)
                stack.extend(v)
            else:
                total += len(json.dumps(v, ensure_ascii=False))  # numbers, true, false, null
        return total
    except (TypeError, ValueError):
        return len(str(resp).encode("utf-8", "surrogatepass"))


def _clean(s):
    if not s.isascii():
        s = unicodedata.normalize("NFKC", s)
        s = "".join(c for c in s if unicodedata.category(c) != "Cf")
    return _GAPS.sub(" ", s)


def scan_text(resp):
    """Return (text, cut): one string of the text values of resp, and whether the cap cut text.

    Walks with a stack (no recursion), skips dict keys, numbers and base64 data, applies NFKC,
    drops format characters (zero-width, soft hyphen) and collapses whitespace.
    """
    parts, size, cut = [], 0, False
    stack = [resp]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            if len(v) >= 1000 and _BASE64.fullmatch(v):
                continue
            if len(v) > MAX_SCAN_CHARS:
                v, cut = v[:MAX_SCAN_CHARS], True
            v = _clean(v)
            parts.append(v)
            size += len(v) + 1
            if size >= MAX_SCAN_CHARS:
                cut = cut or bool(stack)
                break
        elif isinstance(v, dict):
            stack.extend(reversed(list(v.values())))
        elif isinstance(v, (list, tuple)):
            stack.extend(reversed(v))
    text = _GAPS.sub(" ", " ".join(parts))
    return text[:MAX_SCAN_CHARS], cut or len(text) > MAX_SCAN_CHARS


def _alarm(signum, frame):
    raise ScanTimeout()


def scan(policy, resp):
    """Return (warnings, cut): one warning per marker that matched, and whether the cap cut text.

    Excerpts are redacted and short. The whole scan has a SCAN_SECONDS timer where Python has one
    (main thread, not Windows); when it fires the warnings found so far stay and one scan-timeout
    warning names the marker that was running.
    """
    found, cut, running = [], False, [None]
    timer = hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread()
    if timer:
        old = signal.signal(signal.SIGALRM, _alarm)
        signal.setitimer(signal.ITIMER_REAL, SCAN_SECONDS)
    try:
        try:
            text, cut = scan_text(resp)
            for mk in policy.get("injection_markers", []):
                running[0] = mk["id"]
                m = re.search(mk["pattern"], text, re.I)
                if m:
                    found.append({"warning": "prompt-injection-suspected", "marker": mk["id"],
                                  "excerpt": redact_text(m.group(0))[:80]})
            running[0] = None
        finally:
            if timer:
                signal.setitimer(signal.ITIMER_REAL, 0)
    except ScanTimeout:  # outside the inner try too, so an alarm in the clean-up cannot escape
        found.append({"warning": "scan-timeout", "marker": running[0]})
    finally:
        if timer:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old)
    return found, cut
