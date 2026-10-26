"""Run the fixture calls through the real hook scripts and print a decision table.

No API key, no network, no Claude session: the hooks are plain programs that read JSON.
"""
import glob
import json
import os
import re
import subprocess
import sys
import tempfile

from guardrails_core.redact import redact_text

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN = os.environ.get("GUARDRAILS_PLUGIN_DIR") or os.path.normpath(
    os.path.join(HERE, "..", "..", "..", "guardrails-plugin"))
DEMO_CAP = 3

# Fake secrets are built at run time so no key-shaped text sits in the repo.
FAKES = {
    "@@ANTHROPIC_KEY@@": "sk-ant-api03-" + "FAKE" * 12,
}


def fill(obj):
    text = json.dumps(obj)
    for k, v in FAKES.items():
        text = text.replace(k, v)
    return json.loads(text)


def run_hook(script, payload, data):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": data,
           "CLAUDE_PLUGIN_ROOT": PLUGIN, "CLAUDE_PLUGIN_DATA": data}
    return subprocess.run([sys.executable, os.path.join(PLUGIN, "hooks", script)],
                          input=json.dumps(payload), capture_output=True, text=True, env=env)


def last_audit_line(data):
    files = sorted(glob.glob(os.path.join(data, "audit", "*.jsonl")))
    if not files:
        return {}, ""
    with open(files[-1], encoding="utf-8") as f:
        raw = f.read().strip().splitlines()[-1]
    return json.loads(raw), raw


def decide(out):
    if not out.strip():
        return "allow", "default-allow"
    h = json.loads(out)["hookSpecificOutput"]
    rule = re.match(r"\[([^\]]+)\]", h["permissionDecisionReason"])
    return h["permissionDecision"], rule.group(1) if rule else "?"


def main():
    with open(os.path.join(HERE, "fixtures.json"), encoding="utf-8") as f:
        fixtures = json.load(f)
    with tempfile.TemporaryDirectory() as data:
        with open(os.path.join(PLUGIN, "policy.json"), encoding="utf-8") as f:
            pol = json.load(f)
        pol["step_cap"]["max_calls"] = DEMO_CAP  # data-dir policy overrides the plugin policy
        with open(os.path.join(data, "policy.json"), "w", encoding="utf-8") as f:
            json.dump(pol, f)

        rows, bad = [], 0
        for i, fx in enumerate(fixtures, 1):
            fx = fill(fx)
            base = {"session_id": fx.get("session", "demo-%d" % i), "tool_use_id": "t%d" % i,
                    "tool_name": fx["tool_name"], "tool_input": fx["tool_input"]}
            pre = run_hook("pre_tool_use.py", dict(base, hook_event_name="PreToolUse"), data)
            decision, rule = decide(pre.stdout)
            note = fx.get("note", "")
            if "tool_response" in fx:
                post = run_hook("post_tool_use.py", dict(
                    base, hook_event_name="PostToolUse", tool_response=fx["tool_response"]), data)
                rec, raw = last_audit_line(data)
                if post.returncode != 0:
                    note = "AUDIT FAILED: " + post.stderr.strip()
                elif rec.get("warnings"):
                    mk = rec["warnings"][0]["marker"]
                    note = "injection warning: %s (logged, not injected)" % mk
                elif "[REDACTED" in raw and not any(v in raw for v in FAKES.values()):
                    note = "secret redacted in log"
            shown = redact_text(json.dumps(fx["tool_input"], separators=(",", ":")))
            ok = decision == fx["expect"]
            bad += not ok
            rows.append((str(i), fx["tool_name"], shown[:46], decision + ("" if ok else " !"),
                         rule, note))

    head = ("#", "tool", "input", "decision", "rule", "note")
    widths = [max(len(r[c]) for r in rows + [head]) for c in range(6)]
    for r in [head, tuple("-" * w for w in widths)] + rows:
        print("  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip())
    counts = {d: sum(1 for r in rows if r[3].startswith(d)) for d in ("allow", "ask", "deny")}
    print("\n%d calls: %d allow, %d ask, %d deny. Step cap for this demo: %d."
          % (len(rows), counts["allow"], counts["ask"], counts["deny"], DEMO_CAP))
    if bad:
        print("%d call(s) did not match the expected decision (marked !)." % bad)
        return 1
    print("All decisions matched the fixtures.")
    return 0
