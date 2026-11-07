"""A local, read-only server for index.html: the page, /api/status, /api/policy, /api/events.

Standard library only. It binds 127.0.0.1, answers GET only, refuses any Host header that is not
this computer's, and refuses every route without the one-time key it makes at start. No part of a
URL is ever joined into a file path, and nothing it serves is ever written.
"""
import argparse
import glob
import hmac
import json
import os
import re
import secrets
import signal
import stat
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from guardrails_core.policy import load_policy

PORT = 8765
WINDOW = 4 * 1024 * 1024  # most bytes one /api/events request reads, whatever the log size
LIMIT = 500  # most lines one /api/events request returns (the page keeps 500)
DAY_FILE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.jsonl$")
CURSOR = re.compile(r"^(\d{4}-\d{2}-\d{2}):(\d{1,15})$")
FOLDERS = "agent-guardrails-*"
REPO = Path(__file__).resolve().parents[4]


def _day_files(data):
    try:
        return sorted(n for n in os.listdir(os.path.join(data, "audit")) if DAY_FILE.match(n))
    except OSError:
        return []


def _newest_change(data):
    """Change time of the newest day file, or None."""
    for name in reversed(_day_files(data)):
        try:
            return os.stat(os.path.join(data, "audit", name)).st_mtime
        except OSError:
            continue
    return None


def find_data(arg, env, home):
    """Return (folder or None, other folders found, places looked in)."""
    if arg:
        return arg, [], []
    if env.get("CLAUDE_PLUGIN_DATA"):
        return env["CLAUDE_PLUGIN_DATA"], [], []
    looked = []
    if env.get("CLAUDE_CONFIG_DIR"):
        looked.append(os.path.join(env["CLAUDE_CONFIG_DIR"], "plugins", "data", FOLDERS))
    looked.append(os.path.join(home, ".claude*", "plugins", "data", FOLDERS))
    seen, found = set(), []
    for pattern in looked:
        for folder in sorted(glob.glob(pattern)):
            real = os.path.realpath(folder)
            has_logs = os.path.isdir(os.path.join(real, "audit"))
            if real in seen or not (has_logs or os.path.isdir(os.path.join(real, "state"))):
                continue
            seen.add(real)
            found.append(folder)
    found.sort(key=lambda f: _newest_change(f) or 0, reverse=True)
    return (found[0] if found else None), found[1:], looked


def _age(seconds):
    seconds = max(0, int(seconds))
    for size, unit in ((86400, "d"), (3600, "h"), (60, "m")):
        if seconds >= size:
            return "%d%s ago" % (seconds // size, unit)
    return "%ds ago" % seconds


def _load(plugin_root, data):
    """Return (policy or None, error text or None)."""
    try:
        pol, errors = load_policy(plugin_root, data)
    except Exception as e:  # any failure is shown on the page as the policy error, never a 500
        return None, str(e)
    return pol, "; ".join(errors) or None


def status(plugin_root, data):
    pol, error = _load(plugin_root, data)
    changed = _newest_change(data)
    if changed is None:
        detail = "No audit log yet in %s" % data
    else:
        detail = "Hooks last wrote to the log %s (%s)" % (_age(time.time() - changed), data)
    return {
        "plugin_loaded": any(os.path.isdir(os.path.join(data, d)) for d in ("audit", "state")),
        "plugin_detail": detail,
        "policy_ok": error is None,
        "policy_error": error,
        "isolation": bool(pol and pol.get("isolation") is True),
        "log_found": changed is not None,
    }


def policy(plugin_root, data):
    pol, _ = _load(plugin_root, data)
    return pol if pol is not None else {"rules": []}


def _read_window(path, lower, budget):
    """Read a day file from max(lower, size - budget).

    Returns (start, bytes, mid_line): mid_line is true when start is inside a line. The file is
    opened with O_NOFOLLOW, so a symbolic link named like a day file is never read.
    """
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return 0, b"", False
    try:
        size = os.fstat(fd).st_size
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return 0, b"", False
        if lower > size:  # the file was replaced by a shorter one: read it from its start
            lower = 0
        start = max(lower, size - budget)
        if start >= size:
            return start, b"", False
        mid = False
        if start > lower:  # the byte before the window tells whether it begins on a line
            os.lseek(fd, start - 1, os.SEEK_SET)
            mid = os.read(fd, 1) != b"\n"
        else:
            os.lseek(fd, start, os.SEEK_SET)
        chunks, want = [], size - start
        while want > 0:
            chunk = os.read(fd, min(want, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            want -= len(chunk)
        return start, b"".join(chunks), mid
    except OSError:
        return 0, b"", False
    finally:
        os.close(fd)


def _lines(start, data, day, mid):
    """The complete lines of data (which begins at file offset start) as parsed objects."""
    out, pos = [], 0
    if mid:  # the window began inside a line: drop that partial first line
        cut = data.find(b"\n")
        pos = len(data) if cut < 0 else cut + 1
    while True:
        end = data.find(b"\n", pos)
        if end < 0:  # an unfinished last line comes back on a later poll
            return out
        raw, pos = data[pos:end], end + 1
        try:
            obj = json.loads(raw)
        except ValueError:
            continue
        if isinstance(obj, dict):
            obj["cursor"] = "%s:%d" % (day, start + pos)
            out.append(obj)


def read_events(audit_dir, after, limit=LIMIT, window=WINDOW):
    """Lines after the cursor, oldest first. Raises ValueError for a bad cursor."""
    after_day, after_off = "", 0
    if after:
        m = CURSOR.match(after)
        if not m:
            raise ValueError("bad cursor")
        after_day, after_off = m.group(1), int(m.group(2))
    try:
        names = sorted(n for n in os.listdir(audit_dir) if DAY_FILE.match(n))
    except OSError:
        return []
    budget, newest_first = window, []
    for name in reversed(names):
        day = name[:-6]
        if (after_day and day < after_day) or budget <= 0:
            break
        lower = after_off if day == after_day else 0
        start, data, mid = _read_window(os.path.join(audit_dir, name), lower, budget)
        budget -= len(data)
        newest_first.append(_lines(start, data, day, mid))
    events = [e for lines in reversed(newest_first) for e in lines]
    return events[-limit:]


def _json(code, obj):
    return code, "application/json", json.dumps(obj).encode("ascii")


def _route_page(srv, q):
    with open(srv.page, "rb") as f:
        return 200, "text/html; charset=utf-8", f.read()


def _route_status(srv, q):
    return _json(200, status(srv.plugin_root, srv.data))


def _route_policy(srv, q):
    return _json(200, policy(srv.plugin_root, srv.data))


def _route_events(srv, q):
    try:
        return _json(200, read_events(os.path.join(srv.data, "audit"), q.get("after", [""])[0]))
    except ValueError:
        return _json(400, {"error": "bad cursor"})


ROUTES = {"/": _route_page, "/index.html": _route_page, "/api/status": _route_status,
          "/api/policy": _route_policy, "/api/events": _route_events}


class Handler(BaseHTTPRequestHandler):
    """GET only: the standard library answers every other method with 501."""

    def end_headers(self):  # also runs for the standard library's error pages
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def log_message(self, *args):  # the page polls every 2 s: printed lines would bury the link
        pass

    def do_GET(self):
        srv = self.server
        if (self.headers.get("Host") or "").lower() not in srv.hosts:  # DNS rebinding
            return self.send_error(403)
        path, _, query = self.path.partition("?")  # the path is matched as written, never decoded
        q = parse_qs(query, keep_blank_values=True)
        given = q.get("key", [""])[0].encode("utf-8", "replace")
        if not hmac.compare_digest(given, srv.key.encode("ascii")):
            return self.send_error(403)
        route = ROUTES.get(path)
        if route is None:
            return self.send_error(404)
        try:
            code, ctype, body = route(srv, q)
        except Exception:
            return self.send_error(500)  # the page then shows "offline", not old data
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def make_server(plugin_root, page, data, port, key=None):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    bound = httpd.server_address[1]
    httpd.plugin_root, httpd.page, httpd.data = str(plugin_root), str(page), str(data)
    httpd.key = key or secrets.token_urlsafe(24)
    httpd.hosts = {"127.0.0.1:%d" % bound, "localhost:%d" % bound}
    return httpd


def _say(*lines):
    print("\n".join(lines), flush=True)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="guardrails_dashboard",
                                 description="Local read-only server for the dashboard page.")
    ap.add_argument("--port", type=int, default=PORT, help="port on 127.0.0.1 (0 picks a free one)")
    ap.add_argument("--data", help="the plugin data folder to read (default: search for it)")
    args = ap.parse_args(argv)
    plugin_root, page = REPO / "packages" / "guardrails-plugin", REPO / "index.html"
    for need in (plugin_root / "policy.json", page):
        if not need.is_file():
            _say("cannot find %s: run this from a clone of the agent-guardrails repo." % need)
            return 2
    folder, others, looked = find_data(args.data, os.environ, os.path.expanduser("~"))
    if folder is None:
        _say("No agent-guardrails data folder found. Looked in:", *("  " + p for p in looked),
             "Start Claude Code with the plugin first, or pass --data FOLDER.")
        return 2
    try:
        httpd = make_server(plugin_root, page, folder, args.port)
    except (OSError, OverflowError) as e:
        _say("cannot listen on 127.0.0.1:%s (%s). Pick another with --port N." % (args.port, e))
        return 2
    port = httpd.server_address[1]
    env_policy = os.environ.get("GUARDRAILS_POLICY")
    _say("agent-guardrails dashboard: http://127.0.0.1:%d/?key=%s" % (port, httpd.key),
         "  Open that exact link. The key is new at every start; any other login account on this "
         "computer is refused without it.",
         "  data folder: %s%s" % (folder, " (newest of %d found; --data picks another)"
                                  % (len(others) + 1) if others else ""),
         *("  also found:  " + o for o in others),
         "  shipped policy: %s" % (plugin_root / "policy.json"),
         "  GUARDRAILS_POLICY: %s" % (env_policy or "not set in this shell (if your Claude Code "
                                      "sessions set it, set it here too)"),
         "  Read-only. Only this computer can connect. Ctrl-C stops it.")
    signal.signal(signal.SIGINT, signal.default_int_handler)  # also when a parent set it to ignore
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    _say("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
