"""Injection scan: finds prompt-injection markers in tool results and logs them, never edits them.

It is a record of what came in, not a shield. Every tool is scanned unless a trusted_tools
pattern names it. The scan reads the text values of the response, normalizes them, and runs the
markers under one time limit.
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


def is_scanned(policy, tool_name):
    """True unless a trusted_tools pattern names the tool and no untrusted_tools pattern does."""
    if any(re.search(p, tool_name) for p in policy.get("untrusted_tools", [])):
        return True
    return not any(re.search(p, tool_name) for p in policy.get("trusted_tools", []))


def _quoted_size(s):
    """UTF-8 size of json.dumps(s, ensure_ascii=False), without building that text."""
    b = s.encode("utf-8", "surrogatepass")
    n = len(b) + 2 + b.count(b'"') + b.count(b"\\")
    for c in range(32):  # control characters: \b \t \n \f \r take 2 bytes, the rest 6
        n += b.count(bytes([c])) * (1 if c in (8, 9, 10, 12, 13) else 5)
    return n


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
        text, cut = scan_text(resp)
        for mk in policy.get("injection_markers", []):
            running[0] = mk["id"]
            m = re.search(mk["pattern"], text, re.I)
            if m:
                found.append({"warning": "prompt-injection-suspected", "marker": mk["id"],
                              "excerpt": redact_text(m.group(0))[:80]})
        running[0] = None
    except ScanTimeout:
        found.append({"warning": "scan-timeout", "marker": running[0]})
    finally:
        if timer:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old)
    return found, cut
