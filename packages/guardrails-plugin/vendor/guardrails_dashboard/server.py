"""A local server for index.html: the page, /api/status, /api/policy, /api/events, /api/inventory.

Standard library only. It binds 127.0.0.1, refuses any Host header that is not this computer's,
and refuses every route without the one-time key it makes at start. No part of a URL is ever
joined into a file path. Every GET only reads. The one POST, /api/taint/clear, deletes the mark
file of one session (the name is cleaned first) and writes one log line that says so.

Two options do their work and exit without serving: --scan prints the NHI and agent inventory,
--install wires the guard into an agent (see guardrails_core/install.py).
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
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from guardrails_core import audit, discovery, install
from guardrails_core.policy import load_policy

PORT = 8765
WINDOW = 4 * 1024 * 1024  # most bytes one /api/events request reads, whatever the log size
LIMIT = 500  # most lines one /api/events request returns (the page keeps 500)
DAY_FILE = re.compile(r"^(\d{4}-\d{2}-\d{2})\.jsonl$")
CURSOR = re.compile(r"^(\d{4}-\d{2}-\d{2}):(\d{1,15})$")
FOLDERS = "agent-guardrails-*"
PLUGIN_KEY = "agent-guardrails@agent-guardrails"  # plugin@marketplace, as in installed_plugins.json
HANDOVER = "GUARDRAILS_DASHBOARD_HANDOVER"
OWN_DATA = ".agent-guardrails"


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
    looked.append(os.path.join(home, OWN_DATA))  # where the other agents log with no plugin folder
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
        "marked": marked_sessions(data),
    }


def marked_sessions(data):
    """The sessions that are marked now: the names of the mark files that are not empty."""
    out = []
    for path in sorted(glob.glob(os.path.join(glob.escape(data), "state", "*.taint"))):
        try:
            if os.path.getsize(path) > 0:
                out.append(os.path.basename(path)[:-len(".taint")])
        except OSError:
            continue
    return out


def clear_mark(data, session):
    """Delete one session's mark file and log it. Returns the cleaned name and whether a mark
    was there. safe_name keeps the name inside <data>/state whatever the request sent."""
    name = audit.safe_name(session)
    try:
        os.unlink(audit.mark_path(data, name))
    except FileNotFoundError:
        return name, False
    audit.write_audit(data, {"session_id": name, "tool_name": "dashboard", "event": "mark-cleared",
                             "decision": "allow", "rule": "ask-after-injection", "input": {},
                             "reason": "A person cleared the session mark from the dashboard.",
                             "agent": "dashboard"}, {})
    return name, True


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


def _route_inventory(srv, q):
    return _json(200, discovery.scan(project=srv.project))


def _route_clear(srv, q):
    session = q.get("session", [""])[0]
    if not session:
        return _json(400, {"error": "no session"})
    name, cleared = clear_mark(srv.data, session)
    return _json(200, {"session": name, "cleared": cleared})


ROUTES = {"/": _route_page, "/index.html": _route_page, "/api/status": _route_status,
          "/api/policy": _route_policy, "/api/events": _route_events,
          "/api/inventory": _route_inventory}
POST_ROUTES = {"/api/taint/clear": _route_clear}


class Handler(BaseHTTPRequestHandler):
    """GET and one POST route: the standard library answers every other method with 501."""

    def end_headers(self):  # also runs for the standard library's error pages
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def log_message(self, *args):  # the page polls every 2 s: printed lines would bury the link
        pass

    def do_GET(self):
        self._answer(ROUTES)

    def do_POST(self):
        # A page of another site cannot read the key, and is refused here even if it had it.
        origin = self.headers.get("Origin")
        if origin is not None and origin not in {"http://" + h for h in self.server.hosts}:
            return self.send_error(403)
        self._answer(POST_ROUTES)

    def _answer(self, routes):
        srv = self.server
        if (self.headers.get("Host") or "").lower() not in srv.hosts:  # DNS rebinding
            return self.send_error(403)
        path, _, query = self.path.partition("?")  # the path is matched as written, never decoded
        q = parse_qs(query, keep_blank_values=True)
        given = q.get("key", [""])[0].encode("utf-8", "replace")
        if not hmac.compare_digest(given, srv.key.encode("ascii")):
            return self.send_error(403)
        route = routes.get(path)
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
    httpd.project = os.getcwd()  # the project the inventory looks at: where the server started
    httpd.key = key or secrets.token_urlsafe(24)
    httpd.hosts = {"127.0.0.1:%d" % bound, "localhost:%d" % bound}
    return httpd


def _say(*lines):
    print("\n".join(lines), flush=True)


def _plugin_version(plugin_root):
    try:
        meta = os.path.join(str(plugin_root), ".claude-plugin", "plugin.json")
        with open(meta, encoding="utf-8") as f:
            return str(json.load(f).get("version") or "unknown")
    except (OSError, ValueError, AttributeError):
        return "unknown"


def main(argv, plugin_root, page, data=None, notes=()):
    """Serve plugin_root's policy and the page. data is the default for --data; notes are extra
    start-up lines, printed after the link, the data folder and the policy lines."""
    ap = argparse.ArgumentParser(prog="guardrails_dashboard",
                                 description="Local server for the dashboard page.")
    ap.add_argument("--port", type=int, default=PORT, help="port on 127.0.0.1 (0 picks a free one)")
    ap.add_argument("--data", default=data,
                    help="the plugin data folder to read (default: search for it)")
    ap.add_argument("--scan", action="store_true",
                    help="print the NHI and agent inventory of this computer, then exit")
    ap.add_argument("--open", action="store_true",
                    help="open the dashboard in the default browser once it is up")
    ap.add_argument("--install", choices=install.TARGETS,
                    help="wire the guard into that agent (hooks, no JSON to copy), then exit")
    args = ap.parse_args(argv)
    plugin_root, page = Path(plugin_root), Path(page)
    if args.scan:
        _say(discovery.report(discovery.scan()))
        return 0
    home = os.path.expanduser("~")
    folder, others, looked = find_data(args.data, os.environ, home)
    if args.install:  # the agent logs where this dashboard reads, so one page shows every agent
        code, lines = install.install(args.install, plugin_root,
                                      folder or os.path.join(home, OWN_DATA))
        _say(*lines)
        return code
    if folder is None:
        _say("No agent-guardrails data folder found. Looked in:", *("  " + p for p in looked),
             "Start Claude Code with the plugin first (or wire another agent with --install), "
             "or pass --data FOLDER.")
        return 2
    try:
        httpd = make_server(plugin_root, page, folder, args.port)
    except (OSError, OverflowError) as e:
        _say("cannot listen on 127.0.0.1:%s (%s). Pick another with --port N." % (args.port, e))
        return 2
    port = httpd.server_address[1]
    env_policy = os.environ.get("GUARDRAILS_POLICY")
    if data and args.data == data:
        where = " (this install's folder; --data picks another)"
    elif others:
        where = " (newest of %d found; --data picks another)" % (len(others) + 1)
    else:
        where = ""
    link = "http://127.0.0.1:%d/?key=%s" % (port, httpd.key)
    _say("agent-guardrails dashboard: " + link,
         "  Open that exact link. The key is new at every start; any other login account on this "
         "computer is refused without it.",
         "  data folder: %s%s" % (folder, where),
         *("  also found:  " + o for o in others),
         "  plugin: %s (version %s from .claude-plugin/plugin.json)"
         % (plugin_root, _plugin_version(plugin_root)),
         "  shipped policy: %s" % (plugin_root / "policy.json"),
         "  GUARDRAILS_POLICY: %s" % (env_policy or "not set in this shell (if your Claude Code "
                                      "sessions set it, set it here too)"),
         *notes,  # before the last line, so a reader that stops at "Ctrl-C stops it" sees them
         "  It reads; its one write clears a session mark when you press that button. Only "
         "this computer can connect. Ctrl-C stops it.")
    if args.open:  # no browser to start is not an error: the link is printed above
        webbrowser.open(link)
    signal.signal(signal.SIGINT, signal.default_int_handler)  # also when a parent set it to ignore
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    _say("stopped")
    return 0


def _records(config):
    """Claude Code's records for this plugin, or None when the file is not in the known shape."""
    try:
        path = os.path.join(config, "plugins", "installed_plugins.json")
        with open(path, encoding="utf-8") as f:
            recs = json.load(f)["plugins"][PLUGIN_KEY]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    ok = isinstance(recs, list) and recs and all(
        isinstance(r, dict) and isinstance(r.get("installPath"), str) for r in recs)
    return recs if ok else None


def _also(rec):
    project = ", project %s" % rec["projectPath"] if rec.get("projectPath") else ""
    return "  also installed: %s (scope %s%s)" % (rec["installPath"], rec.get("scope"), project)


def run_installed(own, argv):
    """Start the dashboard from a plugin folder (dashboard.py calls this).

    The copy that serves is the one Claude Code's install record names, so the policy on the page
    is the policy in force. Another copy hands over to it. This code runs from whichever copy the
    start command reached first, maybe an old one: keep it small and its interface fixed.
    """
    own = Path(own).resolve()
    notes, data = [], None
    if own.parents[2].name == "cache" and own.parents[3].name == "plugins":
        config = own.parents[4]
        data = str(config / "plugins" / "data" / re.sub(r"[^A-Za-z0-9_-]", "-", PLUGIN_KEY))
        recs = _records(str(config))
        unchecked = ("  warning: %s %s: the policy shown is this copy's and could not be checked "
                     "against Claude Code's record.")
        record_file = config / "plugins" / "installed_plugins.json"
        if recs is None:
            notes.append(unchecked % (record_file, "is not in the shape this dashboard knows, or "
                                      "has no record for " + PLUGIN_KEY))
        else:
            picked = next((r for r in recs if r.get("scope") == "user"),
                          max(recs, key=lambda r: str(r.get("lastUpdated") or "")))
            notes += [_also(r) for r in recs if r is not picked]
            target = Path(picked["installPath"]).resolve()
            if target == own:
                pass
            elif target.parent != own.parent:  # never run code from outside this plugin's cache
                why = "names %s, which is not a version folder of this plugin" % target
                notes = [unchecked % (record_file, why)]
            elif os.environ.get(HANDOVER):
                _say("Claude Code's plugin record changed while the dashboard was starting; "
                     "run the command again.")
                return 2
            elif (target / "dashboard.py").is_file():
                os.environ[HANDOVER] = "1"
                os.execv(sys.executable, [sys.executable, str(target / "dashboard.py"), *argv])
            else:
                _say("The agent-guardrails version in force (%s, version %s) has no dashboard. "
                     "Run: claude plugin update %s" % (target, _plugin_version(target), PLUGIN_KEY))
                return 2
    for need in (own / "policy.json", own / "vendor" / "index.html"):
        if not need.is_file():
            _say("cannot find %s: reinstall the plugin with claude plugin install %s"
                 % (need, PLUGIN_KEY))
            return 2
    return main(argv, own, own / "vendor" / "index.html", data, notes)
