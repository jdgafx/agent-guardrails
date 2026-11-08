"""A minimal MCP server (stdio) with one tool, `fetch`: it returns the raw text of a real page."""
import json
import re
import sys
import urllib.request


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    msg = json.loads(line)
    mid, method = msg.get("id"), msg.get("method")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": msg["params"].get("protocolVersion", "2024-11-05"),
            "capabilities": {"tools": {}}, "serverInfo": {"name": "fetch", "version": "1"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [{
            "name": "fetch", "description": "Fetch a web page and return its text.",
            "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}},
                            "required": ["url"]}}]}})
    elif method == "tools/call":
        url = msg["params"]["arguments"]["url"]
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 t033"})
            html = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace")
            text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))[:30000]
        except Exception as e:
            text = "fetch failed: %s" % e
        send({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": text}]}})
    elif mid is not None:
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
