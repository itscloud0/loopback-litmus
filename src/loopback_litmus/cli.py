from __future__ import annotations

import argparse
import sys

from .fixtures import FIXTURE_CASES, serve_fixture
from .models import ServiceTarget
from .ports import KNOWN_AGENT_PORTS, connect_host_for_bind, enumerate_listeners
from .render import render_json, render_text
from .scanner import scan_targets


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return scan_command(args)
    if args.command == "serve-fixture":
        return serve_fixture(args)
    parser.print_help(sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loopback-litmus",
        description="Safe browser-to-localhost reachability checks for local AI agent and MCP control planes.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="scan selected loopback services")
    scan.add_argument("--host", default="127.0.0.1", help="host to scan when --port is used")
    scan.add_argument("--port", type=int, action="append", default=[], help="port to scan; may be repeated")
    scan.add_argument("--ports", help="comma-separated ports to scan")
    scan.add_argument("--known-agent-ports", action="store_true", help="also scan common local agent/MCP ports")
    scan.add_argument("--json", action="store_true", help="emit JSON report")
    scan.add_argument("--timeout", type=float, default=1.0, help="per-probe timeout in seconds")

    fixture = subparsers.add_parser("serve-fixture", help="run a safe local vulnerable or hardened fixture")
    fixture.add_argument("--case", required=True, choices=FIXTURE_CASES)
    fixture.add_argument("--host", default="127.0.0.1")
    fixture.add_argument("--port", type=int, default=0)

    return parser


def scan_command(args: argparse.Namespace) -> int:
    targets = build_targets(args)
    findings = scan_targets(targets, timeout=args.timeout)
    output = render_json(findings) if args.json else render_text(findings)
    print(output)
    return 0


def build_targets(args: argparse.Namespace) -> list[ServiceTarget]:
    explicit_ports = list(args.port)
    if args.ports:
        explicit_ports.extend(parse_ports(args.ports))

    targets: list[ServiceTarget] = []
    for port in explicit_ports:
        targets.append(ServiceTarget(host=args.host, port=port, bind_address=args.host))

    if args.known_agent_ports:
        for port in KNOWN_AGENT_PORTS:
            targets.append(ServiceTarget(host=args.host, port=port, bind_address=args.host))

    if not targets:
        for listener in enumerate_listeners():
            host = connect_host_for_bind(listener.bind_address)
            if not host:
                continue
            targets.append(
                ServiceTarget(
                    host=host,
                    port=listener.port,
                    bind_address=listener.bind_address,
                    process=listener.process,
                    pid=listener.pid,
                )
            )

    return dedupe_targets(targets)


def parse_ports(value: str) -> list[int]:
    ports: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        port = int(item)
        if port < 1 or port > 65535:
            raise argparse.ArgumentTypeError(f"invalid TCP port: {port}")
        ports.append(port)
    return ports


def dedupe_targets(targets: list[ServiceTarget]) -> list[ServiceTarget]:
    by_key: dict[tuple[str, int], ServiceTarget] = {}
    for target in targets:
        by_key.setdefault((target.host, target.port), target)
    return list(by_key.values())
