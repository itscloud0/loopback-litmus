from __future__ import annotations

import argparse
import json
import socketserver
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

FIXTURE_CASES = (
    "http-metadata-open",
    "websocket-no-origin",
    "websocket-origin-enforced",
    "mcp-unauth-initialize",
    "mcp-auth-required",
    "advisory-mcp-inspector-open",
    "advisory-claude-ide-ws-open",
    "advisory-kubectl-mcp-open",
    "advisory-gpt-researcher-ws-open",
)

WEBSOCKET_FIXTURE_CASES = frozenset(
    {
        "websocket-no-origin",
        "websocket-origin-enforced",
        "advisory-claude-ide-ws-open",
        "advisory-gpt-researcher-ws-open",
    }
)

HTTP_METADATA_CASES = frozenset(
    {
        "http-metadata-open",
        "advisory-mcp-inspector-open",
        "advisory-kubectl-mcp-open",
    }
)

MCP_INITIALIZE_CASES = frozenset(
    {
        "mcp-unauth-initialize",
        "advisory-mcp-inspector-open",
        "advisory-kubectl-mcp-open",
    }
)


@dataclass
class RunningFixture:
    case: str
    host: str
    port: int
    server: Any
    thread: threading.Thread

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def start_fixture(case: str, host: str = "127.0.0.1", port: int = 0) -> RunningFixture:
    if case not in FIXTURE_CASES:
        raise ValueError(f"unknown fixture case: {case}")

    if case in WEBSOCKET_FIXTURE_CASES:
        server = _ReusableTCPServer((host, port), make_websocket_handler(case))
    else:
        server = ThreadingHTTPServer((host, port), make_http_handler(case))

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    actual_port = int(server.server_address[1])
    return RunningFixture(case, host, actual_port, server, thread)


def serve_fixture(args: argparse.Namespace) -> int:
    fixture = start_fixture(args.case, args.host, args.port)
    scheme = "ws" if args.case in WEBSOCKET_FIXTURE_CASES else "http"
    path = "/ws" if args.case in WEBSOCKET_FIXTURE_CASES else "/"
    print(f"{args.case} listening at {scheme}://{args.host}:{fixture.port}{path}")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        fixture.stop()
        return 0
    return 0


def make_http_handler(case: str) -> type[BaseHTTPRequestHandler]:
    class FixtureHTTPHandler(BaseHTTPRequestHandler):
        server_version = "loopback-litmus-fixture/0.1"

        def log_message(self, format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            if case in HTTP_METADATA_CASES:
                self._send_json(200, http_metadata_payload(case))
                return
            if case == "mcp-auth-required":
                self._send_json(401, {"error": "authorization required"})
                return
            if case == "mcp-unauth-initialize":
                self._send_json(200, {"name": "mcp fixture", "jsonrpc": "2.0", "auth": False})
                return
            self._send_json(404, {"error": "not found"})

        def do_POST(self) -> None:
            if case == "mcp-auth-required":
                self._send_json(401, {"error": "authorization required"})
                return
            if case in MCP_INITIALIZE_CASES and self.path in {"/", "/mcp"}:
                self._send_json(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": "loopback-litmus",
                        "result": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {"tools": {}},
                            "serverInfo": mcp_server_info(case),
                        },
                    },
                )
                return
            self._send_json(404, {"error": "not found"})

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return FixtureHTTPHandler


def http_metadata_payload(case: str) -> dict[str, Any]:
    payloads = {
        "http-metadata-open": {
            "name": "loopback-litmus-fixture",
            "type": "mcp-control-plane",
            "auth": False,
            "transport": "http",
        },
        "advisory-mcp-inspector-open": {
            "name": "mcp-inspector-style-proxy",
            "type": "mcp-proxy",
            "auth": False,
            "transport": "http",
            "advisory_pattern": "CVE-2025-49596",
        },
        "advisory-kubectl-mcp-open": {
            "name": "kubectl-mcp-style-server",
            "type": "mcp-control-plane",
            "auth": False,
            "transport": "http",
            "advisory_pattern": "CVE-2025-65719",
        },
    }
    return payloads[case]


def mcp_server_info(case: str) -> dict[str, str]:
    names = {
        "mcp-unauth-initialize": "unsafe-mcp-fixture",
        "advisory-mcp-inspector-open": "mcp-inspector-style-proxy",
        "advisory-kubectl-mcp-open": "kubectl-mcp-style-server",
    }
    return {"name": names[case], "version": "0.1"}


def make_websocket_handler(case: str) -> type[socketserver.StreamRequestHandler]:
    class FixtureWebSocketHandler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            chunks: list[bytes] = []
            while True:
                line = self.rfile.readline(2048)
                if not line:
                    break
                chunks.append(line)
                if line in {b"\r\n", b"\n"}:
                    break
            raw = b"".join(chunks)
            text = raw.decode("iso-8859-1", errors="replace")
            origin = _header_value(text, "Origin")
            if "Upgrade: websocket" not in text and "upgrade: websocket" not in text.lower():
                self.wfile.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                return
            if case == "websocket-origin-enforced" and origin != "http://127.0.0.1":
                self.wfile.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            self.wfile.write(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: fixture\r\n"
                b"\r\n"
            )

    return FixtureWebSocketHandler


def _header_value(request_text: str, name: str) -> str | None:
    prefix = f"{name.lower()}:"
    for line in request_text.splitlines():
        if line.lower().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return None


class _ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
