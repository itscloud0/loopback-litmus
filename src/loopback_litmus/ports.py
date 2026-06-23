from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass


KNOWN_AGENT_PORTS: dict[int, str] = {
    6274: "mcp-inspector",
    6277: "mcp-inspector",
    6278: "mcp-inspector",
    7331: "local-agent-control-plane",
    8765: "websocket-agent",
    18789: "loopback-litmus-fixture",
}

PROCESS_HINTS = {
    "claude": "claude-code-or-extension",
    "cursor": "cursor-or-extension",
    "mcp": "mcp-server",
    "inspector": "mcp-inspector",
    "openclaw": "openclaw-like-agent",
    "gpt-researcher": "gpt-researcher",
    "autogen": "autogen-studio",
    "playwright": "browser-automation",
}


@dataclass(frozen=True)
class Listener:
    bind_address: str
    port: int
    process: str | None = None
    pid: str | None = None


def product_hint(process: str | None, port: int) -> str | None:
    if port in KNOWN_AGENT_PORTS:
        return KNOWN_AGENT_PORTS[port]
    if not process:
        return None
    process_lower = process.lower()
    for needle, hint in PROCESS_HINTS.items():
        if needle in process_lower:
            return hint
    return None


def enumerate_listeners() -> list[Listener]:
    if shutil.which("lsof"):
        return _run_lsof()
    if shutil.which("ss"):
        return _run_ss()
    return []


def _run_lsof() -> list[Listener]:
    result = subprocess.run(
        ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    return parse_lsof(result.stdout)


def _run_ss() -> list[Listener]:
    result = subprocess.run(
        ["ss", "-H", "-ltnp"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    return parse_ss(result.stdout)


def parse_lsof(output: str) -> list[Listener]:
    listeners: list[Listener] = []
    for line in output.splitlines():
        if not line.strip() or line.startswith("COMMAND"):
            continue
        if " TCP " not in line or "(LISTEN)" not in line:
            continue

        fields = line.split()
        process = fields[0] if fields else None
        pid = fields[1] if len(fields) > 1 else None
        name = line.split(" TCP ", 1)[1].split(" (LISTEN)", 1)[0].strip()
        parsed = parse_address_port(name)
        if parsed:
            bind_address, port = parsed
            listeners.append(Listener(bind_address, port, process, pid))
    return listeners


def parse_ss(output: str) -> list[Listener]:
    listeners: list[Listener] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        local = next((field for field in fields if parse_address_port(field)), None)
        parsed = parse_address_port(local or "")
        if not parsed:
            continue
        bind_address, port = parsed
        process = None
        pid = None
        process_match = re.search(r'\("([^"]+)",pid=(\d+)', line)
        if process_match:
            process = process_match.group(1)
            pid = process_match.group(2)
        listeners.append(Listener(bind_address, port, process, pid))
    return listeners


def parse_address_port(value: str) -> tuple[str, int] | None:
    value = value.strip()
    if not value:
        return None
    if value.endswith(":*"):
        return None
    match = re.search(r"(.+):(\d+)$", value)
    if not match:
        return None
    address = match.group(1).strip("[]")
    if address in {"*", "::", "0.0.0.0"}:
        address = "0.0.0.0"
    try:
        return address, int(match.group(2))
    except ValueError:
        return None


def connect_host_for_bind(bind_address: str) -> str | None:
    if bind_address in {"127.0.0.1", "localhost"} or bind_address.startswith("127."):
        return "127.0.0.1"
    if bind_address in {"::1"}:
        return "::1"
    if bind_address in {"0.0.0.0", "*"}:
        return "127.0.0.1"
    return None
