"""T-050: the dashboard's 'Tools used' table, from the audit log the real hooks write.

The log lines come from the real hook scripts (packages/guardrails-plugin/hooks). The table is read
two ways: /api/tools of the real server, and the rendered table in Chromium (the page as the viewer
sees it; skipped only when node or playwright is missing, as in tests/e2e/test_t031_dashboard.py).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "packages" / "guardrails-plugin"
SRC = ":".join(str(ROOT / "packages" / p / "src")
                for p in ("guardrails-core", "guardrails-dashboard"))
ENV = dict(os.environ, PYTHONPATH=SRC, PYTHONDONTWRITEBYTECODE="1")
TZ = "Pacific/Auckland"  # far from UTC, so a table that shows the raw UTC time fails

# Bash x3 ran (one `git push` was asked and approved) and one asked `git push` was refused; Read x2
# ran and one .env read was denied; fetch server: 2 + 1 calls; plugin_x_y server: 1 call.
CALLS = [
    ("Bash", {"command": "ls"}, True),
    ("Bash", {"command": "pwd"}, True),
    ("Bash", {"command": "git push origin main"}, True),    # ask, approved: ran
    ("Bash", {"command": "git push origin dev"}, False),    # ask, refused: did not run
    ("Read", {"file_path": "README.md"}, True),
    ("Read", {"file_path": "LICENSE"}, True),
    ("Read", {"file_path": ".env"}, False),                 # deny
    ("mcp__fetch__fetch", {"url": "https://example.com"}, True),
    ("mcp__fetch__fetch", {"url": "https://example.org"}, True),
    ("mcp__fetch__head", {"url": "https://example.org"}, True),
    ("mcp__plugin_x_y__ping", {}, True),
]


def run_hook(event, payload, data):
    cfg = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())
    cmd = cfg["hooks"][event][0]["hooks"][0]["command"]
    cmd = cmd.replace("${CLAUDE_PLUGIN_ROOT}", str(PLUGIN))
    env = {"PATH": "/usr/bin:/bin", "HOME": str(data), "CLAUDE_PLUGIN_ROOT": str(PLUGIN),
           "CLAUDE_PLUGIN_DATA": str(data)}
    out = subprocess.run(["/bin/bash", "-c", cmd], input=json.dumps(payload), capture_output=True,
                         text=True, env=env, timeout=60)
    assert out.returncode == 0, out.stderr


def session(data, calls):
    """Run calls through the real hooks the way Claude Code does: Pre, then Post when it ran."""
    for i, (tool, tin, ran) in enumerate(calls):
        p = {"session_id": "s1", "tool_use_id": "toolu_%d" % i, "tool_name": tool,
             "tool_input": tin}
        run_hook("PreToolUse", p, data)
        if ran:
            run_hook("PostToolUse", dict(p, tool_response={"stdout": "ok"}), data)


def raw_lines(data):
    return [json.loads(x) for f in sorted((Path(data) / "audit").glob("*.jsonl"))
            for x in f.read_text().splitlines()]


def last_ts(data, *tools):
    return max(r["ts"] for r in raw_lines(data)
               if r["tool_name"] in tools and r["event"] == "result")


def by_name(rows, key):
    return {r[key]: r for r in rows}


def serve(data):
    proc = subprocess.Popen([sys.executable, "-m", "guardrails_dashboard", "--port", "0", "--data",
                             str(data)], cwd=str(ROOT), env=ENV, stdout=subprocess.PIPE, text=True)
    buf = ""
    while "Ctrl-C stops it" not in buf:
        line = proc.stdout.readline()
        assert line, "server exited: " + buf
        buf += line
    return proc, re.search(r"http://127\.0\.0\.1:\d+/\?key=\S+", buf).group(0)


def stop(proc):
    proc.terminate()
    proc.wait(timeout=10)


def api_tools(link):
    with urllib.request.urlopen(link.replace("/?key=", "/api/tools?key="), timeout=10) as r:
        return json.loads(r.read())


def tools_used(audit):
    sys.path[:0] = SRC.split(":")
    from guardrails_dashboard import server
    return server.tools_used(str(audit))


@pytest.fixture
def real_log(tmp_path):
    data = tmp_path / "data"
    session(data, CALLS)
    return data


def test_api_counts_match_the_audit_log_line_for_line(real_log):
    log = raw_lines(real_log)
    # the log itself: the denied read and the refused push have one line each, the approved push two
    assert [r["decision"] for r in log if r["event"] == "decision"] == ["ask", "ask", "deny"]
    assert len([r for r in log if r["event"] == "result"]) == 9
    proc, link = serve(real_log)
    try:
        got = api_tools(link)
    finally:
        stop(proc)
    tools = by_name(got["tools"], "tool")
    assert sorted(tools) == ["Bash", "Read"]
    # used = calls that ran; denied and asked count each call once, however many lines it left
    assert [tools["Bash"][k] for k in ("used", "denied", "asked")] == [3, 0, 2]
    assert [tools["Read"][k] for k in ("used", "denied", "asked")] == [2, 1, 0]
    assert tools["Bash"]["last"] == last_ts(real_log, "Bash")
    assert tools["Read"]["last"] == last_ts(real_log, "Read")
    servers = by_name(got["servers"], "server")
    assert sorted(servers) == ["fetch", "plugin_x_y"]
    fetch = servers["fetch"]
    assert [fetch[k] for k in ("used", "denied", "asked")] == [3, 0, 0]
    assert fetch["last"] == last_ts(real_log, "mcp__fetch__fetch", "mcp__fetch__head")
    inner = by_name(fetch["tools"], "tool")
    assert sorted(inner) == ["fetch", "head"]
    assert (inner["fetch"]["used"], inner["head"]["used"]) == (2, 1)
    assert servers["plugin_x_y"]["tools"][0]["tool"] == "ping"
    assert got["calls"] == len(CALLS) and got["skipped"] == 0 and got["truncated"] is False


def test_api_skips_and_counts_malformed_lines_and_joins_a_call_across_two_days(tmp_path):
    audit = tmp_path / "audit"
    audit.mkdir()

    def line(ts, tid, ev, dec):
        return json.dumps({"ts": ts, "tool_name": "Bash", "tool_use_id": tid, "event": ev,
                           "decision": dec})
    (audit / "2026-11-07.jsonl").write_text("\n".join([
        "{not json", '"a string"', "[1,2]", '{"event": "result"}',        # 4 unusable lines
        '{"tool_name": 5, "event": "result"}',                            # 5th: tool name not text
        line("2026-11-07T23:59:59Z", "a", "decision", "ask"),
        "{half a line"]))  # unfinished last line: still being written, not counted
    (audit / "2026-11-08.jsonl").write_text(
        line("2026-11-08T00:00:02Z", "a", "result", "ask") + "\n")
    got = tools_used(audit)
    assert got["skipped"] == 5 and got["calls"] == 1
    assert got["tools"] == [{"tool": "Bash", "used": 1, "last": "2026-11-08T00:00:02Z",
                             "denied": 0, "asked": 1}]


def test_api_empty_and_missing_log(tmp_path):
    for folder in (tmp_path / "nothing", tmp_path):
        assert tools_used(folder) == {"tools": [], "servers": [], "calls": 0, "skipped": 0,
                                      "truncated": False}


# ---- the table as rendered in Chromium

def node_modules():
    here = ROOT / "node_modules"
    if here.is_dir():
        return here
    common = subprocess.run(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
                            capture_output=True, text=True, cwd=str(ROOT)).stdout.strip()
    other = Path(common).parent / "node_modules"
    return other if other.is_dir() else None


SHOT = textwrap.dedent("""
    const { chromium } = require("playwright");
    (async () => {
      const b = await chromium.launch();
      const ctx = await b.newContext({ locale: "en-GB", timezoneId: process.argv[3] });
      const p = await ctx.newPage();
      await p.goto(process.argv[2]);
      await p.waitForSelector("#tools-section[data-loaded]", { timeout: 15000 });
      const out = await p.evaluate(() => ({
        heading: document.querySelector("#tools-heading").innerText,
        empty: document.querySelector("#tools-empty").hidden ? null
          : document.querySelector("#tools-empty").innerText,
        note: document.querySelector("#tools-note").innerText,
        header: [...document.querySelectorAll("#tools-table thead th")].map((x) => x.innerText),
        rows: [...document.querySelectorAll("#tools-table tbody tr")].map(
          (r) => ({ cls: r.className, cells: [...r.children].map((c) => c.innerText.trim()) })),
        injected: document.querySelectorAll("#tools-section img").length,
      }));
      console.log(JSON.stringify(out));
      await b.close();
    })();
""")


def rendered(link, tmp_path):
    mods = node_modules()
    if shutil.which("node") is None or mods is None or not (mods / "playwright").is_dir():
        pytest.skip("needs node and playwright (npm ci); CI has no Node step")
    script = tmp_path / "shot.cjs"
    script.write_text(SHOT)
    out = subprocess.run(["node", str(script), link, TZ], capture_output=True, text=True,
                         env=dict(ENV, NODE_PATH=str(mods)), timeout=120)
    assert out.returncode == 0, out.stdout[-3000:] + out.stderr[-3000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def local(ts):
    t = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return t.astimezone(ZoneInfo(TZ)).strftime("%d/%m/%Y, %H:%M:%S")


def test_page_shows_the_table_a_viewer_sees(real_log, tmp_path):
    proc, link = serve(real_log)
    try:
        page = rendered(link, tmp_path)
    finally:
        stop(proc)
    assert "tools used" in page["heading"].lower() and page["empty"] is None
    assert [h.lower() for h in page["header"]] == [
        "tool", "times used", "last used", "times denied", "times asked"]
    rows = [(r["cls"].split()[-1], r["cells"]) for r in page["rows"]]
    # a built-in tool is one row; a server is one row (mcp__<server>__*) with its tools under it
    assert ("tools-builtin", ["Bash", "3", local(last_ts(real_log, "Bash")), "0", "2"]) in rows
    assert ("tools-builtin", ["Read", "2", local(last_ts(real_log, "Read")), "1", "0"]) in rows
    fetch_last = last_ts(real_log, "mcp__fetch__fetch", "mcp__fetch__head")
    assert ("tools-server", ["mcp__fetch__*", "3", local(fetch_last), "0", "0"]) in rows
    one = last_ts(real_log, "mcp__fetch__fetch")
    two = last_ts(real_log, "mcp__fetch__head")
    ping = last_ts(real_log, "mcp__plugin_x_y__ping")
    assert ("tools-sub", ["fetch", "2", local(one), "0", "0"]) in rows
    assert ("tools-sub", ["head", "1", local(two), "0", "0"]) in rows
    assert ("tools-server", ["mcp__plugin_x_y__*", "1", local(ping), "0", "0"]) in rows
    names = [c[0] for _, c in rows]
    # the server's tools sit right under its row
    assert names.index("mcp__fetch__*") < names.index("fetch") < names.index("head")
    assert len(rows) == 7


def test_page_empty_log_says_no_tool_calls_recorded_yet(tmp_path):
    data = tmp_path / "data"
    (data / "audit").mkdir(parents=True)
    proc, link = serve(data)
    try:
        page = rendered(link, tmp_path)
    finally:
        stop(proc)
    assert page["empty"] == "No tool calls recorded yet" and page["rows"] == []


def test_page_survives_malformed_lines_and_a_hostile_tool_name(tmp_path):
    data = tmp_path / "data"
    (data / "audit").mkdir(parents=True)
    hostile = "<img src=x onerror=alert(1)>"
    (data / "audit" / "2026-11-08.jsonl").write_text("\n".join([
        "{broken", "42",
        json.dumps({"ts": "2026-11-08T01:02:03Z", "tool_name": hostile, "tool_use_id": "h",
                    "event": "result", "decision": "allow"}), ""]))
    proc, link = serve(data)
    try:
        page = rendered(link, tmp_path)
    finally:
        stop(proc)
    assert [r["cells"][0] for r in page["rows"]] == [hostile] and page["injected"] == 0
    assert "2 lines skipped" in page["note"]
