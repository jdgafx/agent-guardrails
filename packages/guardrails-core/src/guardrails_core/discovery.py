"""NHI and agent discovery: a read-only look at this computer for the agents that are set up, the
MCP servers they can call, and the non-human identities (NHIs: keys, tokens, credential files)
those agents could reach.

    python3 -m guardrails_core.discovery [--project DIR] [--text]     prints JSON (or the report)

It never opens a credential file and never reads the value of an environment variable: it reports
paths, permission bits and names. Agent config files are parsed for their MCP servers; of a server
it keeps the name, the program's file name, the host of a URL and the credential-like names of its
env vars and headers. Arguments, URL paths and every value are dropped (they can hold tokens).
It starts no server and opens no connection, so the classes of a server are a guess from its name.
"""
import argparse
import glob
import json
import os
import re
import stat
import sys
import time
from urllib.parse import urlsplit

try:
    import tomllib  # Python 3.11+; Codex keeps its servers in a TOML file
except ImportError:
    tomllib = None

HOOK_MARK = "guard.py hook"  # in a hooks file: install.py wired this agent to the guard
PLUGIN_MARK = "agent-guardrails@"  # in Claude Code's installed_plugins.json

# What each agent can do with no MCP server at all. Codex's web search is opt-in (--search).
AGENTS = (
    ("claude-code", "Claude Code", ".claude", ["WebFetch", "WebSearch"], ["Bash"]),
    ("cursor", "Cursor", ".cursor", ["web search"], ["terminal"]),
    ("codex", "Codex", ".codex", [], ["shell"]),
)
CRED_PATHS = ("~/.ssh", "~/.aws", "~/.kube/config", "~/.config/gcloud", "~/.npmrc", "~/.pypirc")
_ENV_NAME = re.compile(r"_(?:KEY|TOKEN|SECRET|PASSWORD)$")
_CRED_NAME = re.compile(r"KEY|TOKEN|SECRET|PASSWORD|AUTH|CREDENTIAL", re.I)
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,80}")  # a name; never "NAME=value" or a header line
_NOT_SECRET = (".example", ".sample", ".template")
# Guessed from the server's name, program and arguments. Every server also gets "read".
_CLASSES = (
    ("exec", r"shell|terminal|exec|command|ssh|docker|kube|k8s|sandbox|repl|interpreter|"
             r"run.?code|blender|computer.?use|desktop"),
    ("network", r"fetch|browser|playwright|puppeteer|chrome|web|search|scrap|crawl|http|slack|"
                r"git(?:hub|lab)|mail|notion|linear|jira|drive|zapier|cloud|supabase|vercel|"
                r"railway|memory|\bfal\b|api"),
    ("write", r"file|\bfs\b|git|slack|mail|notion|linear|jira|drive|docs|sheet|calendar|sql|"
              r"postgres|mongo|redis|database|\bdb\b|supabase|zapier|deploy|vercel|railway|"
              r"cloudflare|memory"),
    ("financial", r"stripe|paypal|pay|bank|plaid|wallet|crypto|coinbase|binance|trad(?:e|ing)|"
                  r"broker|alpaca|invoice|billing|quant|shopify"),
)
NOTES = (
    "The classes of an MCP server are guessed from its name and command; no server is started, "
    "so its real tool list is not read.",
    "Connectors that live in an account (claude.ai, ChatGPT) and servers shipped inside plugins "
    "are not in these files and are not listed.",
    "Every agent with a shell can also read the web and send data with it (curl); the first leg "
    "counts only web tools and MCP servers.",
)


def classify(text, remote=False):
    """The classes a server (or a tool name) looks like: read, write, exec, network, financial."""
    found = ["read"] + [c for c, pat in _CLASSES if re.search(pat, text, re.I)]
    if remote and "network" not in found:
        found.append("network")
    return found


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            obj = json.load(f)
    except (OSError, ValueError):
        return {}
    return obj if isinstance(obj, dict) else {}


def _read_toml(path):
    if tomllib is None or not os.path.isfile(path):
        return {}
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, ValueError):
        return {}


def _mentions(path, needle):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return needle in f.read()
    except OSError:
        return False


def _dict(v):
    return v if isinstance(v, dict) else {}


def _host(url):
    try:
        return urlsplit(str(url)).hostname
    except ValueError:
        return None


def _servers(table, source, scope):
    out = []
    for name, cfg in sorted(table.items()) if isinstance(table, dict) else ():
        if not isinstance(cfg, dict):
            continue
        cmd, url = cfg.get("command"), cfg.get("url")
        # Names only: the keys of the tables, and the two Codex fields that hold names of
        # environment variables. A table given as a list or a line of text is not read.
        env_vars = cfg.get("env_vars") if isinstance(cfg.get("env_vars"), list) else []
        names = [str(n) for k in ("env", "headers", "http_headers", "env_http_headers")
                 for n in _dict(cfg.get(k))]
        names += [n for n in env_vars + [cfg.get("bearer_token_env_var")] if isinstance(n, str)]
        args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
        text = " ".join([str(name), str(cmd or ""), " ".join(str(a) for a in args),
                         str(url or "")])
        # the program's file name only: a command given as one line can carry a token after it
        program = os.path.basename(cmd.split()[0]) if isinstance(cmd, str) and cmd.split() else None
        out.append({
            "name": str(name), "source": source, "scope": scope,
            "transport": "http" if url else "stdio", "command": program,
            "host": _host(url) if url else None,
            "credential_names": sorted({n for n in names
                                        if _NAME.fullmatch(n) and _CRED_NAME.search(n)}),
            "classes": classify(text, remote=bool(url))})
    return out


def _agent_servers(agent_id, home, project):
    """(config files found, MCP servers) of one agent: its user config and the project's."""
    j = os.path.join
    if agent_id == "claude-code":
        user = _read_json(j(home, ".claude.json"))
        local = _dict(_dict(user.get("projects")).get(project))
        parts = [(j(home, ".claude.json"), "user", user.get("mcpServers")),
                 (j(home, ".claude.json"), "local", local.get("mcpServers")),
                 (j(project, ".mcp.json"), "project",
                  _read_json(j(project, ".mcp.json")).get("mcpServers"))]
    elif agent_id == "cursor":
        parts = [(p, scope, _read_json(p).get("mcpServers")) for p, scope in (
            (j(home, ".cursor", "mcp.json"), "user"),
            (j(project, ".cursor", "mcp.json"), "project"))]
    else:
        parts = [(p, scope, _read_toml(p).get("mcp_servers")) for p, scope in (
            (j(home, ".codex", "config.toml"), "user"),
            (j(project, ".codex", "config.toml"), "project"))]
    servers = [s for path, scope, table in parts for s in _servers(table, path, scope)]
    return sorted({p for p, _, _ in parts if os.path.isfile(p)}), servers


def _guarded(agent_id, home):
    if agent_id == "claude-code":
        return _mentions(os.path.join(home, ".claude", "plugins", "installed_plugins.json"),
                         PLUGIN_MARK)
    return _mentions(os.path.join(home, "." + agent_id, "hooks.json"), HOOK_MARK)


def _path_nhi(path, shown):
    """Presence and permission bits of one path. The file is never opened."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    mode = stat.S_IMODE(st.st_mode)
    item = {"kind": "dir" if stat.S_ISDIR(st.st_mode) else "file", "name": shown,
            "mode": "%04o" % mode, "loose": bool(mode & 0o077)}  # loose: group or others get in
    if item["kind"] == "dir":
        try:
            item["entries"] = len(os.listdir(path))
        except OSError:
            item["entries"] = None
    return item


def _nhis(home, project, env):
    found = [_path_nhi(os.path.join(home, p[2:]), p) for p in CRED_PATHS]
    # shortcut: only .env files at the top of the project. Walk the tree if nested ones matter.
    for path in sorted(glob.glob(os.path.join(glob.escape(project), ".env*"))):
        if os.path.isfile(path) and not path.endswith(_NOT_SECRET):
            found.append(_path_nhi(path, os.path.join(project, os.path.basename(path))))
    found += [{"kind": "env", "name": k} for k in sorted(env) if _ENV_NAME.search(k)]
    return [n for n in found if n]


def _risk(web, shell, servers, nhis):
    """The lethal trifecta: outside content in, secrets within reach, a way to send data out.
    All three is CRITICAL, two is HIGH, fewer is OK. Each leg lists what was found for it."""
    out = {"network", "write", "exec", "financial"}
    legs = {
        "untrusted_read": web + [s["name"] for s in servers if "network" in s["classes"]],
        "secrets": [n["name"] for n in nhis] + ["%s: %s" % (s["name"], c) for s in servers
                                               for c in s["credential_names"]],
        "external_write": shell + [s["name"] for s in servers if out & set(s["classes"])],
    }
    n = sum(1 for v in legs.values() if v)
    return dict(legs, level="CRITICAL" if n == 3 else "HIGH" if n == 2 else "OK")


def scan(home=None, project=None, env=None):
    """The inventory, as plain JSON data. home, project and env are for tests."""
    home = home or os.path.expanduser("~")
    project = os.path.abspath(project or os.getcwd())
    nhis = _nhis(home, project, os.environ if env is None else env)
    agents, project_servers = [], []
    for agent_id, name, folder, web, shell in AGENTS:
        try:
            configs, servers = _agent_servers(agent_id, home, project)
        except Exception:  # a config in a shape nobody expected must not stop the whole scan
            configs, servers = [], []
        project_servers += [dict(s, agent=agent_id) for s in servers if s["scope"] != "user"]
        found = os.path.isdir(os.path.join(home, folder))
        agents.append({
            "id": agent_id, "name": name, "found": found, "config_files": configs,
            "guarded": _guarded(agent_id, home), "mcp_servers": servers,
            "risk": _risk(web, shell, servers, nhis) if found else None})
    if tomllib is None:
        agents[-1]["note"] = "Codex's config.toml needs Python 3.11 or newer to be read."
    mine = [n for n in nhis if n["name"].startswith(project + os.sep)]
    return {"scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "agents": agents,
            "project": {"path": project, "mcp_servers": project_servers,
                        "risk": _risk([], [], project_servers, mine)},
            "nhis": nhis, "notes": list(NOTES)}


def report(inv):
    """The inventory as terminal text."""
    def legs(risk):
        return ["      %-15s %s" % (leg.replace("_", " ") + ":", ", ".join(risk[leg]) or "none")
                for leg in ("untrusted_read", "secrets", "external_write")]

    def server(s):
        where = s["host"] or s["command"] or "?"
        creds = ", ".join(s["credential_names"])
        return "    - %s (%s, %s, %s) [%s]%s" % (
            s["name"], s["scope"], s["transport"], where, " ".join(s["classes"]),
            "  credentials: " + creds if creds else "")

    out = ["NHI & Agent Discovery (%s)" % inv["scanned_at"], "", "Agents"]
    for a in inv["agents"]:
        if not a["found"]:
            out.append("  %-12s not found" % a["name"])
            continue
        out.append("  %-12s %-8s %s, %d MCP server(s)" % (
            a["name"], a["risk"]["level"], "guarded" if a["guarded"] else "not guarded",
            len(a["mcp_servers"])))
        out += [server(s) for s in a["mcp_servers"]] + legs(a["risk"])
        out += ["      note: " + a["note"]] if a.get("note") else []
    p = inv["project"]
    out += ["", "Project %s" % p["path"], "  %-12s %s (its own MCP servers and .env files only)"
            % ("risk", p["risk"]["level"])] + legs(p["risk"])
    out += ["", "NHIs (credentials an agent on this account could reach)"]
    for n in inv["nhis"]:
        if n["kind"] == "env":
            out.append("  env   %s" % n["name"])
        else:
            loose = "  <- group or others can get in" if n["loose"] else ""
            count = ", %s entries" % n["entries"] if n["kind"] == "dir" else ""
            out.append("  %-5s %s  mode %s%s%s" % (n["kind"], n["name"], n["mode"], count, loose))
    if not inv["nhis"]:
        out.append("  none found")
    return "\n".join(out + [""] + ["Note: " + n for n in inv["notes"]])


def main(argv=None):
    ap = argparse.ArgumentParser(prog="guardrails_core.discovery",
                                 description="Read-only NHI and agent inventory of this computer.")
    ap.add_argument("--project", help="the project folder to look at (default: this folder)")
    ap.add_argument("--text", action="store_true", help="print the report, not JSON")
    args = ap.parse_args(argv)
    inv = scan(project=args.project)
    print(report(inv) if args.text else json.dumps(inv, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
