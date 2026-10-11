"""Synthetic MCP upstream for the power-cut machine test.

Speaks just enough MCP over HTTP POST for the broker's gateway: initialize,
notifications/initialized, tools/list and tools/call for one tool. Every
tools/call is appended to <state>/effects and fsync'd *before* any response is
written, so the effect count survives the broker losing power. When
<state>/hold exists, tools/call records the effect and then never answers,
which keeps the broker's invocation in flight until the test cuts power.

This is test infrastructure, not an opaque component.
"""

import argparse
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTOCOL_VERSION = "2025-06-18"
TOOL_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["message"],
    "properties": {"message": {"type": "string", "maxLength": 128, "minLength": 1}},
}


def append_durably(path, line):
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    directory = os.open(os.path.dirname(path), os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def make_handler(state_dir, token):
    effects = os.path.join(state_dir, "effects")
    hold = os.path.join(state_dir, "hold")
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            print("mock-mcp: " + (fmt % args), flush=True)

        def reply(self, status, body=None):
            data = b"" if body is None else json.dumps(body).encode()
            self.send_response(status)
            if body is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if self.path != "/mcp":
                return self.reply(404)
            if self.headers.get("Authorization") != f"Bearer {token}":
                return self.reply(401)
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length))
            method = request.get("method")
            print(f"mock-mcp: method={method}", flush=True)
            if method == "initialize":
                result = {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "machine-test", "version": "1"},
                }
            elif method == "notifications/initialized":
                return self.reply(202)
            elif method == "tools/list":
                result = {"tools": [{"name": "post_note", "inputSchema": TOOL_SCHEMA}]}
            elif method == "tools/call":
                with lock:
                    append_durably(effects, json.dumps(request.get("params")))
                print("mock-mcp: effect recorded", flush=True)
                while os.path.exists(hold):
                    time.sleep(0.2)
                result = {
                    "content": [{"type": "text", "text": "noted"}],
                    "structuredContent": {"id": 1, "status": "created"},
                    "isError": False,
                }
            else:
                return self.reply(400)
            self.reply(200, {"jsonrpc": "2.0", "id": request.get("id"), "result": result})

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--token-file", required=True)
    args = parser.parse_args()
    with open(args.token_file, encoding="utf-8") as handle:
        token = handle.read().strip()
    os.makedirs(args.state_dir, exist_ok=True)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(args.state_dir, token))
    print(f"mock-mcp: listening on {args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
