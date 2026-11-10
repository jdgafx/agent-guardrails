"""The one-command install (scripts/install.sh) and the one-word command (guardrails).

Both run for real, in a scratch home folder. Claude Code and the browser are stand-in scripts
that write down how they were called, so the test wires and opens nothing on this computer.
"""
import json
import os
import re
import signal
import stat
import subprocess
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LINK = re.compile(r"http://127\.0\.0\.1:\d+/\?key=\S+")


def script(path, body):
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(0o755)
    return path


def run_install(tmp_path, claude=True):
    home, stubs = tmp_path / "home", tmp_path / "stubs"
    home.mkdir(exist_ok=True)
    stubs.mkdir(exist_ok=True)
    if claude:
        script(stubs / "claude", 'echo "$@" >> "%s"' % (tmp_path / "claude.log"))
    env = {"HOME": str(home), "PATH": "%s:/usr/bin:/bin" % stubs}
    done = subprocess.run(["sh", str(ROOT / "scripts" / "install.sh")], env=env,
                          capture_output=True, text=True, timeout=120)
    return home, env, done


def test_one_command_installs_the_word_and_wires_claude_code(tmp_path):
    home, env, done = run_install(tmp_path)
    assert done.returncode == 0, done.stdout + done.stderr
    word = home / ".local" / "bin" / "guardrails"
    assert word.is_file() and word.stat().st_mode & stat.S_IXUSR
    assert str(ROOT) in word.read_text()  # run from a clone, it installs that clone
    calls = (tmp_path / "claude.log").read_text().splitlines()
    assert calls == ["plugin marketplace add %s" % ROOT,
                     "plugin install agent-guardrails@agent-guardrails"]
    assert done.stdout.strip().endswith("Done. To open the dashboard, type: guardrails")
    assert "is not on your PATH" in done.stdout  # the scratch PATH has no ~/.local/bin: it says so
    again = run_install(tmp_path)[2]  # a second run updates in place
    assert again.returncode == 0 and word.is_file()


def test_install_without_claude_code_still_installs_the_word(tmp_path):
    home, env, done = run_install(tmp_path, claude=False)
    assert done.returncode == 0, done.stdout + done.stderr
    assert (home / ".local" / "bin" / "guardrails").is_file()
    assert "Claude Code is not on PATH" in done.stdout
    assert "guardrails --install claude" in done.stdout


def test_the_word_starts_the_dashboard_and_opens_it(tmp_path):
    home, env, done = run_install(tmp_path)
    assert done.returncode == 0, done.stdout + done.stderr
    opened = tmp_path / "opened.txt"
    browser = script(tmp_path / "stubs" / "browser", 'printf "%%s" "$1" > "%s"' % opened)
    env = dict(env, BROWSER=str(browser))
    proc = subprocess.Popen([str(home / ".local" / "bin" / "guardrails")], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        seen = ""
        while "Ctrl-C stops it" not in seen:
            line = proc.stdout.readline()
            assert line, "the dashboard stopped early: " + seen
            seen += line
        link = LINK.search(seen).group(0)
        # a fresh install has no log yet: it opens on the fallback folder, not with an error
        assert "data folder: %s" % (home / ".agent-guardrails") in seen
        for _ in range(100):  # the browser is started just after the link is printed
            if opened.is_file() and opened.read_text():
                break
            time.sleep(0.1)
        assert opened.read_text() == link  # the browser was asked to open the exact printed link
        with urllib.request.urlopen(link.replace("/?key=", "/api/status?key="), timeout=10) as r:
            status = json.load(r)
        assert status["policy_ok"] is True and status["log_found"] is False
        with urllib.request.urlopen(link, timeout=10) as r:
            assert b"agent-guardrails" in r.read()
    finally:
        proc.send_signal(signal.SIGINT)
        rest = proc.communicate(timeout=20)[0]
    assert proc.returncode == 0 and "stopped" in rest


def test_options_after_the_word_still_work(tmp_path):
    home, env, done = run_install(tmp_path)
    word = str(home / ".local" / "bin" / "guardrails")
    scan = subprocess.run([word, "--scan"], env=env, capture_output=True, text=True, timeout=60)
    assert scan.returncode == 0 and "Claude Code" in scan.stdout  # the inventory report, no server
    assert not os.path.exists(tmp_path / "opened.txt")
