"""The log chain, the session pass, the waiting approval, two more redaction formats, Windows
paths and the MCP wrap. Every test runs the real engine on a scratch data folder."""
import json
import threading
import time
from pathlib import Path

from guardrails_core import adapters, approval, audit, hooks, install, redact, rules

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "packages" / "guardrails-plugin"
POLICY = json.loads((PLUGIN / "policy.json").read_text())
PUSH = {"session_id": "sess-1", "tool_use_id": "t1", "tool_name": "Bash",
        "tool_input": {"command": "git push origin main"}}


def pre(data, **change):
    return hooks.run_pre(json.dumps(dict(PUSH, **change)), str(PLUGIN), str(data))


def log(data):
    return [json.loads(x) for f in sorted((Path(data) / "audit").glob("*.jsonl"))
            for x in f.read_text().splitlines()]


def write(data, n):
    audit.write_audit(str(data), {"session_id": "s", "tool_name": "Read", "event": "decision",
                                  "decision": "deny", "rule": "r", "input": {"n": n}}, POLICY)


# ---- the log chain

def test_chain_matches_until_a_line_is_edited_removed_or_added(tmp_path):
    for n in range(3):
        write(tmp_path, n)
    assert audit.verify_chain(str(tmp_path)) == {
        "ok": True, "verified_lines": 3, "unchained_lines": 0, "tampered_file": None,
        "detail": "3 line(s) match their chain; 0 line(s) written before the chain began"}
    day = next((tmp_path / "audit").glob("*.jsonl"))
    good = day.read_text()
    for bad in (good.replace('"n": 1', '"n": 7'),              # a line edited
                "".join(good.splitlines(True)[:2]),            # the last line removed
                "".join(good.splitlines(True)[1:]),            # the first line removed
                good + good.splitlines(True)[0]):              # a line added without a record
        day.write_text(bad)
        res = audit.verify_chain(str(tmp_path))
        assert res["ok"] is False and res["tampered_file"] == day.name, bad
    day.write_text(good)
    assert audit.verify_chain(str(tmp_path))["ok"] is True


def test_lines_written_before_the_chain_began_are_not_called_tampering(tmp_path):
    (tmp_path / "audit").mkdir()
    day = tmp_path / "audit" / (time.strftime("%Y-%m-%d", time.gmtime()) + ".jsonl")
    day.write_text('{"old": 1}\n{"old": 2}\n')  # an older hook wrote these, with no chain
    (tmp_path / "audit" / "2020-01-01.jsonl").write_text('{"old": 0}\n')  # a whole day without one
    write(tmp_path, 1)
    write(tmp_path, 2)
    res = audit.verify_chain(str(tmp_path))
    assert (res["ok"], res["verified_lines"], res["unchained_lines"]) == (True, 2, 3)
    assert audit.verify_chain(str(tmp_path / "nothing-here"))["detail"] == "No audit log yet"


def test_hooks_writing_at_the_same_moment_keep_one_valid_chain(tmp_path):
    threads = [threading.Thread(target=lambda k=k: [write(tmp_path, (k, n)) for n in range(25)])
               for k in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    res = audit.verify_chain(str(tmp_path))
    assert res["ok"] is True and res["verified_lines"] == 200, res


# ---- the session pass

def test_a_pass_allows_that_rule_and_tool_in_that_session_only(tmp_path):
    assert "ask-git-push" in pre(tmp_path)
    row = approval.allow_for_session(str(tmp_path), "sess-1", "ask-git-push", "Bash")
    assert row["session_id"] == "sess-1" and approval.list_session_allows(str(tmp_path)) == [row]
    assert pre(tmp_path, tool_use_id="t2") == ""  # allowed
    hooks.run_post(json.dumps(dict(PUSH, tool_use_id="t2", tool_response="ok")), str(PLUGIN),
                   str(tmp_path))
    last = log(tmp_path)[-1]  # the call that ran is logged as allowed, under the rule it passed
    assert (last["decision"], last["rule"], last["event"]) == ("allow", "ask-git-push", "result")
    assert "ask-git-push" in pre(tmp_path, session_id="sess-2")  # another session still asks
    rm = {"tool_use_id": "t3", "tool_input": {"command": "rm -rf build"}}
    assert "ask-rm-recursive" in pre(tmp_path, **rm)  # another rule still asks
    assert approval.clear_session_allows(str(tmp_path), "sess-1") == ("sess-1", True)
    assert "ask-git-push" in pre(tmp_path, tool_use_id="t4")  # taken back: it asks again
    events = [x["event"] for x in log(tmp_path) if x["agent"] == "dashboard"]
    assert events == ["session-allow", "session-allow-cleared"]


def test_a_pass_never_waves_through_a_marked_session_or_a_built_in_ask(tmp_path):
    data = str(tmp_path)
    approval.allow_for_session(data, "sess-1", "ask-git-push", "Bash")
    audit.mark_session(data, "sess-1", {"id": "f1", "tool": "WebFetch", "markers": ["x"]})
    assert '"permissionDecision": "ask"' in pre(tmp_path)  # marked: the pass does not count
    # a pass someone wrote for a built-in ask is not honoured: only rules of the policy file are
    for rule in ("ask-after-injection", "step-cap", "ask-guard-paths"):
        approval.allow_for_session(data, "sess-1", rule, "Bash")
    assert '"permissionDecision": "ask"' in pre(tmp_path, tool_use_id="t9")
    key = {"session_id": "sess-4", "tool_use_id": "k1",
           "tool_input": {"command": "cat ~/.ssh/id_rsa"}}
    approval.allow_for_session(data, "sess-4", "deny-key-files", "Bash")
    assert "deny-key-files" in pre(tmp_path, **key)  # a deny rule that asks on a shell: no pass
    guard = {"session_id": "sess-3", "tool_use_id": "g1",
             "tool_input": {"command": "cat %s" % (tmp_path / "state" / "sess-3.allow")}}
    approval.allow_for_session(data, "sess-3", "ask-guard-paths", "Bash")
    assert "ask-guard-paths" in pre(tmp_path, **guard)  # the guard's own files still ask


# ---- the waiting approval (an agent that cannot ask)

def waiting_call(tmp_path, monkeypatch, answer, wait="5"):
    monkeypatch.setenv("GUARDRAILS_WEB_APPROVAL", "1")
    monkeypatch.setenv("GUARDRAILS_APPROVAL_TIMEOUT", wait)
    data, result = str(tmp_path), []
    payload = {"hook_event_name": "PreToolUse", "session_id": "cx-1", "tool_use_id": "1",
               "tool_name": "Bash", "tool_input": {"command": "git push origin main"}}
    t = threading.Thread(
        target=lambda: result.append(adapters.check("codex", payload, str(PLUGIN), data)))
    t.start()
    seen = None
    for _ in range(50):
        pending = approval.list_pending(data)
        if pending:
            seen = pending[0]
            if answer:
                assert approval.resolve_pending(data, seen["id"], answer, passable=True)
            break
        time.sleep(0.1)
    t.join(timeout=10)
    return seen, result[0]


def test_a_waiting_call_is_allowed_once_from_the_dashboard(tmp_path, monkeypatch):
    seen, result = waiting_call(tmp_path, monkeypatch, "allow")
    assert (seen["agent"], seen["tool_name"], seen["rule"]) == ("codex", "Bash", "ask-git-push")
    assert seen["input"] == {"command": "git push origin main"} and seen["status"] == "pending"
    assert result == (False, "allow", "")
    assert approval.list_pending(str(tmp_path)) == []  # the request file is gone
    assert not approval.is_session_allowed(str(tmp_path), "cx-1", "ask-git-push", "Bash")
    events = [(x["event"], x["decision"], x["agent"]) for x in log(tmp_path)]
    assert events == [("decision", "ask", "codex"), ("approval-resolved", "allow", "dashboard")]
    assert approval.resolve_pending(str(tmp_path), seen["id"], "allow") is None  # only once


def test_allow_for_the_session_also_leaves_a_pass(tmp_path, monkeypatch):
    _, result = waiting_call(tmp_path, monkeypatch, "allow-session")
    assert result == (False, "allow", "")
    assert approval.is_session_allowed(str(tmp_path), "cx-1", "ask-git-push", "Bash")


def test_a_denied_or_unanswered_waiting_call_is_refused(tmp_path, monkeypatch):
    _, denied = waiting_call(tmp_path / "a", monkeypatch, "deny")
    assert denied[1] == "deny" and "Denied in the dashboard" in denied[2]
    _, late = waiting_call(tmp_path / "b", monkeypatch, None, wait="1")
    assert late[1] == "deny" and "Nobody answered" in late[2]
    assert log(tmp_path / "b")[-1]["event"] == "approval-timeout"
    assert approval.list_pending(str(tmp_path / "b")) == []


def test_without_the_opt_in_an_ask_stays_an_ask(tmp_path, monkeypatch):
    monkeypatch.delenv("GUARDRAILS_WEB_APPROVAL", raising=False)
    payload = {"hook_event_name": "PreToolUse", "session_id": "cx-1", "tool_use_id": "1",
               "tool_name": "Bash", "tool_input": {"command": "git push origin main"}}
    assert adapters.check("codex", payload, str(PLUGIN), str(tmp_path))[1] == "ask"
    assert approval.list_pending(str(tmp_path)) == []


# ---- redaction, Windows paths, the MCP wrap

def test_a_jwt_and_a_database_password_are_redacted():
    jwt = ".".join(("eyJ" + "hbGciOiJIUzI1NiJ9", "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0",
                    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"))  # joined here, not in the repo
    conn = "postgresql://admin:" + "SuperSecretPass123" + "@db.internal.example.com:5432/prod"
    out = redact.redact_text("token=%s db=%s" % (jwt, conn))
    assert "[REDACTED:jwt-token]" in out and "dozjgNry" not in out
    assert "postgresql://admin:[REDACTED:connection-string]@db.internal.example.com:5432" in out
    assert "SuperSecretPass123" not in out
    assert redact.redact_text("https://example.com/a:b@c") == "https://example.com/a:b@c"


def test_windows_paths_match_the_same_rules():
    d = rules.evaluate(POLICY, "Read", {"file_path": r"C:\Users\alice\.ssh\id_rsa"}, 1)
    assert d.decision == "deny"
    d2 = rules.evaluate(POLICY, "Read", {"file_path": r"C:\srv\production\db.yaml"}, 1)
    assert (d2.decision, d2.rule) == ("deny", "deny-prod-config")
    assert rules.evaluate(POLICY, "Read", {"file_path": r"C:\src\readme.md"}, 1).decision == "allow"


def test_install_mcp_wraps_stdio_servers_once_and_keeps_the_original(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    before = {"mcpServers": {"github": {"command": "npx", "args": ["-y", "server-github"],
                                        "env": {"GITHUB_TOKEN": "x"}},
                             "remote": {"url": "https://mcp.example.com"}}}
    mcp_file = tmp_path / ".mcp.json"
    mcp_file.write_text(json.dumps(before))
    code, lines = install.install("mcp", PLUGIN, tmp_path / "data", home=str(tmp_path))
    assert code == 0 and "1 stdio MCP server(s)" in lines[0]
    cfg = json.loads(mcp_file.read_text())["mcpServers"]
    assert cfg["github"]["command"] == "python3" and cfg["github"]["env"] == {"GITHUB_TOKEN": "x"}
    assert cfg["github"]["args"] == [str(PLUGIN / "guard.py"), "mcp", "--name", "github", "--",
                                     "npx", "-y", "server-github"]
    assert cfg["remote"] == {"url": "https://mcp.example.com"}  # a server reached by URL is left
    assert json.loads((tmp_path / ".mcp.json.guardrails-bak").read_text()) == before
    code2, lines2 = install.install("mcp", PLUGIN, tmp_path / "data", home=str(tmp_path))
    assert code2 == 0 and "No stdio MCP server to wrap" in lines2[0]
    assert json.loads(mcp_file.read_text())["mcpServers"] == cfg  # a second run changes nothing
    mcp_file.write_text("{not json")
    assert install.install("mcp", PLUGIN, tmp_path / "data", home=str(tmp_path))[0] == 0
    assert mcp_file.read_text() == "{not json"  # a broken file is left alone
