from __future__ import annotations

import base64
import http.client
import json
import os
import socket
from collections.abc import Iterable

from .models import ProbeResult, ServiceTarget

HOSTILE_ORIGIN = "https://loopback-litmus.invalid"
USER_AGENT = "loopback-litmus/0.1"
MCP_PATHS = ("/mcp", "/")
WEBSOCKET_PATHS = ("/ws", "/mcp", "/")


def probe_http(target: ServiceTarget, timeout: float) -> ProbeResult:
    conn: http.client.HTTPConnection | None = None
    try:
        conn = http.client.HTTPConnection(target.host, target.port, timeout=timeout)
        conn.request(
            "GET",
            "/",
            headers={
                "Host": f"{target.host}:{target.port}",
                "Origin": HOSTILE_ORIGIN,
                "User-Agent": USER_AGENT,
            },
        )
        response = conn.getresponse()
        body = response.read(1024)
        text = body.decode("utf-8", errors="replace")
        conn.close()
    except OSError as exc:
        if conn:
            conn.close()
        return ProbeResult("http_get", "unreachable", str(exc))

    evidence = {
        "status": response.status,
        "headers": dict(response.getheaders()),
        "body_sample": text[:240],
    }
    if response.status in {401, 403}:
        return ProbeResult("http_get", "auth_required", "HTTP endpoint rejected unauthenticated request", evidence)
    if response.status < 400 and looks_like_agent_metadata(text, evidence["headers"]):
        return ProbeResult("http_get", "metadata_exposed", "HTTP metadata looks agent or MCP related", evidence)
    if response.status < 500:
        return ProbeResult("http_get", "reachable", f"HTTP responded with {response.status}", evidence)
    return ProbeResult("http_get", "error", f"HTTP responded with {response.status}", evidence)


def probe_mcp_initialize(target: ServiceTarget, timeout: float, paths: Iterable[str] = MCP_PATHS) -> ProbeResult:
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "loopback-litmus",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "loopback-litmus", "version": "0.1"},
            },
        }
    )
    attempts: list[dict[str, object]] = []
    for path in paths:
        conn: http.client.HTTPConnection | None = None
        try:
            conn = http.client.HTTPConnection(target.host, target.port, timeout=timeout)
            conn.request(
                "POST",
                path,
                body=payload,
                headers={
                    "Content-Type": "application/json",
                    "Origin": HOSTILE_ORIGIN,
                    "User-Agent": USER_AGENT,
                },
            )
            response = conn.getresponse()
            body = response.read(2048)
            text = body.decode("utf-8", errors="replace")
            conn.close()
        except OSError as exc:
            if conn:
                conn.close()
            attempts.append({"path": path, "status": "unreachable", "detail": str(exc)})
            continue

        attempt = {"path": path, "status": response.status, "body_sample": text[:240]}
        attempts.append(attempt)
        if response.status in {401, 403}:
            return ProbeResult("mcp_initialize", "auth_required", f"{path} rejected unauthenticated initialize", {"attempts": attempts})
        if response.status < 400 and looks_like_mcp_initialize_response(text):
            return ProbeResult("mcp_initialize", "accepted", f"{path} accepted unauthenticated MCP initialize", {"attempts": attempts})

    if attempts:
        return ProbeResult("mcp_initialize", "not_mcp", "No unauthenticated MCP initialize response detected", {"attempts": attempts})
    return ProbeResult("mcp_initialize", "unreachable", "No MCP probe connection succeeded")


def probe_websocket_origin(target: ServiceTarget, timeout: float, paths: Iterable[str] = WEBSOCKET_PATHS) -> ProbeResult:
    attempts: list[dict[str, object]] = []
    for path in paths:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {target.host}:{target.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Origin: {HOSTILE_ORIGIN}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "\r\n"
        )
        try:
            with socket.create_connection((target.host, target.port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(request.encode("ascii"))
                raw = sock.recv(4096)
        except OSError as exc:
            attempts.append({"path": path, "status": "unreachable", "detail": str(exc)})
            continue

        text = raw.decode("iso-8859-1", errors="replace")
        status_line = text.splitlines()[0] if text.splitlines() else ""
        status_code = parse_http_status(status_line)
        attempts.append({"path": path, "status": status_code, "status_line": status_line})
        if status_code == 101:
            return ProbeResult("websocket_origin", "accepted", f"{path} accepted hostile Origin WebSocket handshake", {"attempts": attempts})
        if status_code == 403:
            return ProbeResult("websocket_origin", "origin_rejected", f"{path} rejected hostile Origin WebSocket handshake", {"attempts": attempts})
        if status_code == 401:
            return ProbeResult("websocket_origin", "auth_required", f"{path} required authentication for WebSocket handshake", {"attempts": attempts})

    if attempts:
        return ProbeResult("websocket_origin", "not_websocket", "No WebSocket endpoint accepted hostile Origin", {"attempts": attempts})
    return ProbeResult("websocket_origin", "unreachable", "No WebSocket probe connection succeeded")


def looks_like_agent_metadata(text: str, headers: dict[str, str]) -> bool:
    haystack = (text + " " + " ".join(f"{k}:{v}" for k, v in headers.items())).lower()
    needles = ("mcp", "agent", "jsonrpc", "tools", "serverinfo", "control-plane", "websocket")
    return any(needle in haystack for needle in needles)


def looks_like_mcp_initialize_response(text: str) -> bool:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return False
    if not isinstance(parsed, dict):
        return False
    if parsed.get("jsonrpc") != "2.0":
        return False
    result = parsed.get("result")
    return isinstance(result, dict) and (
        "protocolVersion" in result or "serverInfo" in result or "capabilities" in result
    )


def parse_http_status(status_line: str) -> int | None:
    parts = status_line.split()
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None
