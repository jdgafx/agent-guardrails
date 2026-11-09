"""A guard in front of one MCP server, for any agent that speaks MCP over stdio:

    python3 -m guardrails_core.mcp_proxy [--name NAME] [--agent AGENT] -- <cmd> <args...>

Put it where the agent's config names the server's command. Every message is read as strict JSON
and written out again, so the server parses what was checked; a line that is not strict JSON (a
key given twice, bad UTF-8) is dropped. The content passes through unchanged, except:
- a tools/call request is checked first, as the tool mcp__<NAME>__<tool>. A deny is answered here
  and never reaches the server. An ask goes to the person through MCP elicitation when the client
  offers it, and is refused when it does not.
- a tools/call result has shaped secrets replaced, is scanned for injection text (a hit puts a
  note in front of the result and can mark the session) and is logged.
One proxy process is one session. It opens no port: stdin, stdout and the server's two pipes.
"""
import argparse
import itertools
import json
import os
import secrets
import subprocess
import sys
import threading

from . import adapters, redact


def _strict(pairs):
    """A JSON object with one value per key. Two "method" keys can mean one thing to this proxy
    and another to the server, so such a message is not JSON here."""
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("a key is given twice")
    return obj


def _parse(line):
    """The message, or None for a line that is not strict JSON (bad UTF-8, a key twice, too
    deep). Such a line is dropped: what was not read here is not passed on."""
    try:
        return json.loads(line, object_pairs_hook=_strict)
    except (ValueError, RecursionError):
        sys.stderr.write("guardrails proxy: dropped a line that is not JSON\n")
        return None


def _refusal(msg_id, text):
    """A tool result that says no. A result, not a protocol error, so the model reads the reason."""
    return {"jsonrpc": "2.0", "id": msg_id, "result": {
        "isError": True, "content": [{"type": "text", "text": "agent-guardrails: " + text}]}}


class Proxy:
    def __init__(self, name, agent, to_server, to_client, root, data):
        self.name, self.agent, self.root, self.data = name, agent, root, data
        self._server, self._client = to_server, to_client
        self.session = "mcp-%s-%d" % (name, os.getpid())
        self.calls = {}  # request id (as JSON text) -> the call, for a tools/call that went on
        self.held = {}  # our elicitation id -> (request, the call), not answered yet
        self.can_ask = False
        self._ids = itertools.count(1)
        self._ask_prefix = "guardrails-%s-" % secrets.token_hex(8)  # the server cannot guess it
        self._lock = threading.Lock()  # both threads write to the client

    def _to_server(self, msg):
        """Send the message as this proxy read it, written out again: the server parses the same
        thing that was checked, whatever its parser makes of an odd spelling."""
        try:
            self._server.write(json.dumps(msg).encode("ascii") + b"\n")
            self._server.flush()
        except (OSError, ValueError):  # the server is gone; the read loop ends the proxy
            pass

    def _to_client(self, msg):
        line = msg if isinstance(msg, bytes) else json.dumps(msg).encode("ascii")
        with self._lock:
            self._client.write(line if line.endswith(b"\n") else line + b"\n")
            self._client.flush()

    def _forward(self, held):
        msg, call = held
        self.calls[json.dumps(msg["id"])] = call
        self._to_server(msg)

    def from_client(self, line):
        msg = _parse(line)
        if msg is None:
            return
        if isinstance(msg, list):
            if all(isinstance(m, dict) and m.get("method") != "tools/call" for m in msg):
                return self._to_server(msg)
            # shortcut: a batch that holds a tools/call (or anything that is not a plain
            # message) is refused, not checked. MCP dropped batches in 2025-06-18; check each
            # call if a client still sends them.
            refused = [_refusal(m["id"], "send tools/call on its own, not in a batch.")
                       for m in msg if isinstance(m, dict) and "id" in m]
            return self._to_client(refused) if refused else None
        if not isinstance(msg, dict):
            return self._to_server(msg)
        method = msg.get("method")
        if method == "initialize":
            params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
            caps = params.get("capabilities")
            self.can_ask = isinstance(caps, dict) and "elicitation" in caps
        if method is None and isinstance(msg.get("id"), str) and msg["id"] in self.held:
            held = self.held.pop(msg["id"])  # the person's answer to our question
            result = msg.get("result") if isinstance(msg.get("result"), dict) else {}
            if result.get("action") == "accept":
                return self._forward(held)
            return self._to_client(_refusal(held[0]["id"], "the person did not approve this call."))
        if method != "tools/call":
            return self._to_server(msg)
        if "id" in msg:  # a tools/call with no id has no answer to check: it is dropped
            self._check(msg)

    def _check(self, msg):
        # The answer is found again by this id, so it must come back spelled the same: a text or
        # a whole number (what MCP allows), and not one that is already waiting for its answer.
        mid = msg["id"]
        plain = type(mid) is str or (type(mid) is int and abs(mid) < 2 ** 53)
        if not plain or json.dumps(mid) in self.calls:
            return self._to_client(_refusal(mid if plain else None, "the request id must be a "
                                            "text or a whole number that is not in use."))
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        tool = adapters.mcp_name(self.name, str(params.get("name")))
        # arguments in any shape go to the adapter: JSON text is read, anything else asks
        call = {"tool_name": tool, "tool_input": params.get("arguments"),
                "session_id": self.session, "tool_use_id": str(mid), "cwd": os.getcwd(),
                "agent": self.agent}
        try:
            _, decision, reason = adapters.check("generic", call, self.root, self.data)
        except Exception as e:
            decision, reason = "ask", "[guardrails-error] %s: %s" % (type(e).__name__, e)
        if decision == "allow":
            return self._forward((msg, call))
        if decision == "ask" and self.can_ask:
            ask_id = self._ask_prefix + str(next(self._ids))
            self.held[ask_id] = (msg, call)
            return self._to_client({
                "jsonrpc": "2.0", "id": ask_id, "method": "elicitation/create",
                "params": {"message": "agent-guardrails: allow %s? %s" % (tool, reason),
                           "requestedSchema": {"type": "object", "properties": {}}}})
        if decision == "ask":
            reason += adapters.NO_ASK % "This MCP client"
        self._to_client(_refusal(msg["id"], reason))

    def from_server(self, line):
        msg = _parse(line)
        if msg is None:
            return
        call = None
        if isinstance(msg, dict) and "method" not in msg:
            call = self.calls.pop(json.dumps(msg.get("id")), None)
        if call is None:
            return self._to_client(msg)
        try:
            if "result" in msg:
                msg["result"] = self._result(dict(call, tool_response=msg["result"]),
                                             msg["result"])
            else:
                self._result(dict(call, hook_event_name="PostToolUseFailure",
                                  error=json.dumps(msg.get("error"))), None)
        except Exception as e:  # a result that cannot be cleaned is held back, not passed on
            msg = _refusal(msg.get("id"), "the result could not be checked (%s), so it was held "
                                          "back." % type(e).__name__)
        self._to_client(msg)

    def _result(self, report, result):
        """Log and scan the result; return it with secrets replaced and the note in front."""
        note = None
        try:
            _, out, _ = adapters.check("generic", report, self.root, self.data)
            note = out.get("hookSpecificOutput", {}).get("additionalContext")
        except Exception as e:  # a log failure does not hide the result (as in PostToolUse)
            sys.stderr.write("guardrails audit failed: %s: %s\n" % (type(e).__name__, e))
        result = redact.redact(result)
        if note and isinstance(result, dict) and isinstance(result.get("content"), list):
            result["content"].insert(0, {"type": "text", "text": note})
        return result


def main(argv=None):
    ap = argparse.ArgumentParser(prog="guardrails_core.mcp_proxy",
                                 description="A guard in front of one MCP server (stdio).")
    ap.add_argument("--name", help="the server's name in tool names (default: the command's name)")
    ap.add_argument("--agent", default=os.environ.get("GUARDRAILS_AGENT") or "mcp-proxy",
                    help="the agent name in the log")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="-- then the server command")
    args = ap.parse_args(argv)
    cmd = args.cmd[1:] if args.cmd[:1] == ["--"] else args.cmd
    if not cmd:
        ap.error("give the server command after --")
    child = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    proxy = Proxy(args.name or os.path.basename(cmd[0]), args.agent, child.stdin,
                  sys.stdout.buffer, adapters.plugin_root(), adapters.data_dir())

    def pump():
        for line in iter(sys.stdin.buffer.readline, b""):
            try:
                proxy.from_client(line)
            except Exception as e:  # the message is dropped, never passed on unchecked
                sys.stderr.write("guardrails proxy: %s: %s\n" % (type(e).__name__, e))
        try:
            child.stdin.close()
        except OSError:
            pass

    threading.Thread(target=pump, daemon=True).start()
    for line in iter(child.stdout.readline, b""):
        proxy.from_server(line)
    code = child.wait()
    sys.stdout.flush()
    # The pump thread may still sit in a read of stdin. A normal exit waits on that file's lock
    # and aborts the interpreter (exit -6), so leave without the clean-up.
    os._exit(code)


if __name__ == "__main__":
    sys.exit(main())
