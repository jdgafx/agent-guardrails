"""discovery.py (the NHI and agent inventory) and install.py (wiring the guard into an agent), on
a made-up home folder. The main property: no secret VALUE ever reaches the inventory.
"""
import json
import os
import stat
import sys
from pathlib import Path

import pytest
from guardrails_core import discovery, install, rules

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "packages" / "guardrails-plugin"
SECRETS = ["ghp_valueOfTheGithubToken", "tok-in-an-argument", "tok-in-a-url", "bearer-in-a-header",
           "value-of-the-env-var", "PRIVATE-KEY-BODY", "aws-secret-body", "npm-token-body",
           "dotenv-body", "fal-key-value"]
needs_toml = pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib is Python 3.11+")


@pytest.fixture
def world(tmp_path):
    """(home, project, env): Claude Code and Codex set up, Cursor not, secrets in the usual
    places."""
    home, project = tmp_path / "home", tmp_path / "proj"
    for d in (home / ".claude", home / ".codex", home / ".ssh", home / ".aws", project):
        d.mkdir(parents=True)
    (home / ".claude.json").write_text(json.dumps({
        "mcpServers": {
            "github": {"type": "http", "url": "https://mcp.example.com/v1?token=tok-in-a-url",
                       "headers": {"Authorization": "Bearer bearer-in-a-header"}},
            "notes": {"command": "/opt/tools/notes-server", "args": ["--quiet"], "env": {}}},
        "projects": {str(project): {"mcpServers": {
            "shell-runner": {"command": "npx", "args": ["run", "--key=tok-in-an-argument"],
                             "env": {"GITHUB_TOKEN": "ghp_valueOfTheGithubToken",
                                     "LOG_LEVEL": "debug"}}}}}}))
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "stripe": {"command": "npx", "args": ["-y", "stripe-mcp"]}}}))
    (home / ".codex" / "config.toml").write_text(
        '[mcp_servers.fal]\ncommand = "npx"\nargs = ["fal-mcp"]\n\n'
        '[mcp_servers.fal.env]\nFAL_KEY = "fal-key-value"\n')
    (home / ".ssh" / "id_ed25519").write_text("PRIVATE-KEY-BODY")
    os.chmod(home / ".ssh", 0o700)
    (home / ".aws" / "credentials").write_text("aws-secret-body")
    os.chmod(home / ".aws", 0o755)
    (home / ".npmrc").write_text("npm-token-body")
    os.chmod(home / ".npmrc", 0)  # the scan must not need to open it
    (project / ".env").write_text("dotenv-body")
    os.chmod(project / ".env", 0o644)
    (project / ".env.example").write_text("EXAMPLE=1")
    env = {"OPENAI_API_KEY": "value-of-the-env-var", "DEPLOY_TOKEN": "value-of-the-env-var",
           "PATH": "/usr/bin", "KEYBOARD": "us"}
    return home, project, env


def scan(world):
    home, project, env = world
    return discovery.scan(home=str(home), project=str(project), env=env)


def agent(inv, agent_id):
    return next(a for a in inv["agents"] if a["id"] == agent_id)


def test_no_secret_value_reaches_the_inventory_or_the_report(world):
    inv = scan(world)
    text = json.dumps(inv) + discovery.report(inv)
    assert [s for s in SECRETS if s in text] == []
    assert "debug" not in text and "--quiet" not in text  # no value and no argument at all


def test_the_scan_changes_nothing_and_opens_no_credential_file(world):
    home, project, _ = world

    def snapshot():
        return {str(p): (p.lstat().st_mode, p.lstat().st_mtime_ns, p.lstat().st_size)
                for root in (home, project) for p in sorted(root.rglob("*"))}
    before = snapshot()
    inv = scan(world)
    assert snapshot() == before
    npmrc = next(n for n in inv["nhis"] if n["name"] == "~/.npmrc")
    assert npmrc["mode"] == "0000"  # listed although nobody can read it


def test_nhis_are_paths_modes_and_names(world):
    home, project, _ = world
    nhis = {n["name"]: n for n in scan(world)["nhis"]}
    assert set(nhis) == {"~/.ssh", "~/.aws", "~/.npmrc", str(project / ".env"),
                         "DEPLOY_TOKEN", "OPENAI_API_KEY"}  # no .env.example, no KEYBOARD
    assert nhis["~/.ssh"] == {"kind": "dir", "name": "~/.ssh", "mode": "0700", "loose": False,
                              "entries": 1}
    assert nhis["~/.aws"]["loose"] is True and nhis[str(project / ".env")]["loose"] is True
    assert nhis["OPENAI_API_KEY"] == {"kind": "env", "name": "OPENAI_API_KEY"}


def test_claude_code_servers_from_the_user_the_local_and_the_project_config(world):
    claude = agent(scan(world), "claude-code")
    servers = {s["name"]: s for s in claude["mcp_servers"]}
    assert {n: s["scope"] for n, s in servers.items()} == {
        "github": "user", "notes": "user", "shell-runner": "local", "stripe": "project"}
    assert servers["github"]["transport"] == "http"
    assert servers["github"]["host"] == "mcp.example.com"
    assert servers["github"]["credential_names"] == ["Authorization"]
    assert servers["shell-runner"]["command"] == "npx"
    assert servers["shell-runner"]["credential_names"] == ["GITHUB_TOKEN"]  # LOG_LEVEL is no secret
    assert servers["notes"]["command"] == "notes-server"  # the file name, not the folder
    assert "exec" in servers["shell-runner"]["classes"]
    assert "financial" in servers["stripe"]["classes"]
    assert {"network", "write"} <= set(servers["github"]["classes"])
    assert servers["notes"]["classes"] == ["read"]


@needs_toml
def test_codex_servers_come_from_its_toml_file(world):
    codex = agent(scan(world), "codex")
    assert [(s["name"], s["command"], s["credential_names"]) for s in codex["mcp_servers"]] == [
        ("fal", "npx", ["FAL_KEY"])]


def test_the_lethal_trifecta_levels(world):
    home, project, env = world
    inv = scan(world)
    claude, cursor = agent(inv, "claude-code"), agent(inv, "cursor")
    assert claude["risk"]["level"] == "CRITICAL"
    assert claude["risk"]["untrusted_read"][:2] == ["WebFetch", "WebSearch"]
    assert "shell-runner: GITHUB_TOKEN" in claude["risk"]["secrets"]
    assert claude["risk"]["external_write"][0] == "Bash"
    assert cursor["found"] is False and cursor["risk"] is None
    # the project alone: a .env file and a server that can pay, but nothing that reads the web
    assert inv["project"]["risk"]["level"] == "HIGH"
    assert inv["project"]["risk"]["untrusted_read"] == []
    # an agent with a shell and nothing else: one leg
    for path in (".ssh/id_ed25519", ".aws/credentials", ".npmrc"):
        (home / path).unlink()
    for folder in (".ssh", ".aws"):
        (home / folder).rmdir()
    (home / ".codex" / "config.toml").unlink()
    bare = discovery.scan(home=str(home), project=str(home / "nowhere"), env={})
    assert agent(bare, "codex")["risk"] == {
        "untrusted_read": [], "secrets": [], "external_write": ["shell"], "level": "OK"}


def test_classify_reads_a_tool_name_too():
    assert discovery.classify("mcp__files__read_file") == ["read", "write"]
    assert "financial" in discovery.classify("create_payment_link")
    assert discovery.classify("plain", remote=True) == ["read", "network"]


def test_the_report_names_each_level_and_each_loose_folder(world):
    text = discovery.report(scan(world))
    assert "Claude Code  CRITICAL not guarded" in text and "Cursor       not found" in text
    assert "~/.aws  mode 0755, 1 entries  <- group or others can get in" in text
    assert "env   OPENAI_API_KEY" in text


# ---- install.py

def hooks_file(home, agent_id):
    return json.loads((home / ("." + agent_id) / "hooks.json").read_text())


def test_install_codex_adds_its_entries_once_and_keeps_the_others(world, tmp_path):
    home = world[0]
    theirs = {"hooks": {"PreToolUse": [{"matcher": "^mcp__x__", "hooks": [
        {"type": "command", "command": "node other.js"}]}], "Stop": []}}
    (home / ".codex" / "hooks.json").write_text(json.dumps(theirs))
    code, lines = install.install("codex", PLUGIN, tmp_path / "data", home=str(home))
    assert code == 0 and "guard hooks added" in lines[0] and any("/hooks" in x for x in lines)
    cfg = hooks_file(home, "codex")
    assert cfg["hooks"]["PreToolUse"][0] == theirs["hooks"]["PreToolUse"][0]
    mine = cfg["hooks"]["PreToolUse"][1]["hooks"][0]
    assert mine["command"] == "python3 %s/guard.py hook codex --data %s" % (
        PLUGIN, tmp_path / "data")
    assert cfg["hooks"]["PostToolUse"][0]["hooks"][0]["command"] == mine["command"]
    assert json.loads((home / ".codex" / "hooks.json.guardrails-bak").read_text()) == theirs
    assert agent(scan(world), "codex")["guarded"] is True
    # again: nothing changes; from another copy of the plugin: the path is updated, not doubled
    before = (home / ".codex" / "hooks.json").read_text()
    code, lines = install.install("codex", PLUGIN, tmp_path / "data", home=str(home))
    assert code == 0 and "already wired" in lines[0]
    assert (home / ".codex" / "hooks.json").read_text() == before
    install.install("codex", tmp_path / "newer", tmp_path / "data", home=str(home))
    cfg = hooks_file(home, "codex")
    assert len(cfg["hooks"]["PreToolUse"]) == 2
    assert str(tmp_path / "newer") in cfg["hooks"]["PreToolUse"][1]["hooks"][0]["command"]


def test_install_cursor_blocks_on_a_failed_before_hook(world, tmp_path):
    home = world[0]
    (home / ".cursor").mkdir()
    code, _ = install.install("cursor", PLUGIN, tmp_path / "data", home=str(home))
    cfg = hooks_file(home, "cursor")
    assert code == 0 and cfg["version"] == 1
    assert {e: cfg["hooks"][e][0].get("failClosed") for e in cfg["hooks"]} == {
        "beforeShellExecution": True, "beforeMCPExecution": True, "beforeReadFile": True,
        "afterShellExecution": None, "afterMCPExecution": None}
    assert not (home / ".cursor" / "hooks.json.guardrails-bak").exists()  # there was no file


def test_install_leaves_a_broken_file_and_a_missing_agent_alone(world, tmp_path):
    home = world[0]
    code, lines = install.install("cursor", PLUGIN, tmp_path / "data", home=str(home))
    assert code == 2 and "not set up" in lines[0] and not (home / ".cursor").exists()
    (home / ".codex" / "hooks.json").write_text("{broken")
    code, lines = install.install("codex", PLUGIN, tmp_path / "data", home=str(home))
    assert code == 2 and "left as it is" in lines[0]
    assert (home / ".codex" / "hooks.json").read_text() == "{broken"


def test_install_claude_runs_claude_codes_own_commands(tmp_path, monkeypatch):
    fake = tmp_path / "bin" / "claude"
    fake.parent.mkdir()
    fake.write_text('#!/bin/sh\necho "$@" >> "%s"\necho done\n' % (tmp_path / "calls"))
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(fake.parent))
    code, lines = install.install("claude", PLUGIN, tmp_path / "data")
    assert code == 0 and lines[-1] == "Restart Claude Code to load the hooks."
    assert (tmp_path / "calls").read_text().splitlines() == [
        "plugin marketplace add %s" % ROOT, "plugin install agent-guardrails@agent-guardrails"]
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert install.install("claude", PLUGIN, tmp_path / "data")[0] == 2


# ---- the rules guard the files the install wires

def test_a_write_to_an_agents_hooks_file_asks(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    guard = rules.guard_paths("/opt/plugin", "/opt/data", None)
    for folder in (".codex", ".cursor"):
        d = rules.guard_check("Edit", {"file_path": "~/%s/hooks.json" % folder}, guard, "/tmp/p")
        assert (d.decision, d.rule) == ("ask", "ask-claude-settings") and "hooks file" in d.reason
    d = rules.guard_check("Edit", {"file_path": "/tmp/p/.claude/settings.json"}, guard, "/tmp/p")
    assert "Claude Code settings file" in d.reason
    assert rules.guard_check("Edit", {"file_path": "~/notes/hooks.json"}, guard, "/tmp/p") is None


def test_every_file_of_a_multi_file_edit_is_guard_checked():
    guard = rules.guard_paths("/opt/plugin", "/opt/data", None)
    tin = {"file_path": "src/a.py", "file_paths": ["src/a.py", "/opt/plugin/policy.json"]}
    assert rules.guard_check("Edit", tin, guard, "/tmp/p").rule == "deny-guard-files"
