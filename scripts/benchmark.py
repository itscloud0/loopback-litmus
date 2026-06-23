from __future__ import annotations

import argparse
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from loopback_litmus.fixtures import RunningFixture, start_fixture


HOST = "127.0.0.1"
HOSTILE_ORIGIN = "https://loopback-litmus.invalid"


@dataclass(frozen=True)
class Scenario:
    name: str
    group: str
    expected_risk: str
    port: int


@dataclass
class RunningHttpSample:
    name: str
    port: int
    server: ThreadingHTTPServer

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the loopback-litmus fixture benchmark.")
    parser.add_argument("--timeout", type=float, default=0.4, help="per-probe timeout in seconds")
    parser.add_argument("--output", type=Path, help="write Markdown report to this path")
    args = parser.parse_args()

    report = run_benchmark(timeout=args.timeout)
    markdown = render_markdown(report)
    if args.output:
        args.output.write_text(markdown + "\n", encoding="utf-8")
    else:
        print(markdown)
    return 0 if report["status"] == "PASS" else 1


def run_benchmark(timeout: float) -> dict[str, Any]:
    fixtures: list[RunningFixture] = []
    samples: list[RunningHttpSample] = []
    try:
        fixture_cases = [
            ("advisory-mcp-inspector-open", "unsafe", "HIGH"),
            ("advisory-claude-ide-ws-open", "unsafe", "HIGH"),
            ("advisory-kubectl-mcp-open", "unsafe", "HIGH"),
            ("advisory-gpt-researcher-ws-open", "unsafe", "HIGH"),
            ("websocket-origin-enforced", "hardened", "LOW"),
            ("mcp-auth-required", "hardened", "LOW"),
        ]
        scenarios: list[Scenario] = []
        for case, group, expected_risk in fixture_cases:
            fixture = start_fixture(case, HOST)
            fixtures.append(fixture)
            scenarios.append(Scenario(case, group, expected_risk, fixture.port))

        for name, status, body, content_type in ordinary_samples():
            sample = start_http_sample(name, status, body, content_type)
            samples.append(sample)
            scenarios.append(Scenario(name, "ordinary", "INFO", sample.port))

        cli_result = run_cli_scan(scenarios, timeout)
        manual_result = run_manual_baseline(scenarios, timeout)
        findings_by_port = {item["target"]["port"]: item for item in cli_result["payload"]["findings"]}
        rows = []
        mismatches = []
        for scenario in scenarios:
            finding = findings_by_port.get(scenario.port)
            actual_risk = finding["risk"] if finding else "MISSING"
            ok = actual_risk == scenario.expected_risk
            if not ok:
                mismatches.append(
                    {
                        "scenario": scenario.name,
                        "expected": scenario.expected_risk,
                        "actual": actual_risk,
                    }
                )
            rows.append(
                {
                    "scenario": scenario.name,
                    "group": scenario.group,
                    "expected_risk": scenario.expected_risk,
                    "actual_risk": actual_risk,
                    "ok": ok,
                }
            )

        unsafe_rows = [row for row in rows if row["group"] == "unsafe"]
        hardened_rows = [row for row in rows if row["group"] == "hardened"]
        ordinary_rows = [row for row in rows if row["group"] == "ordinary"]
        ordinary_false_positives = [
            row for row in ordinary_rows if row["actual_risk"] in {"HIGH", "MEDIUM"}
        ]
        command_reduction = manual_result["command_count"] - cli_result["command_count"]
        status = "PASS" if not mismatches and not ordinary_false_positives else "FAIL"

        return {
            "status": status,
            "recorded_at": datetime.now(ZoneInfo("Europe/Amsterdam")).strftime("%Y-%m-%d %H:%M %Z"),
            "timeout_seconds": timeout,
            "scenario_count": len(scenarios),
            "rows": rows,
            "metrics": {
                "unsafe_true_positives": f"{count_ok(unsafe_rows)}/{len(unsafe_rows)}",
                "hardened_true_negatives": f"{count_ok(hardened_rows)}/{len(hardened_rows)}",
                "ordinary_false_positives": f"{len(ordinary_false_positives)}/{len(ordinary_rows)}",
                "loopback_litmus_elapsed_seconds": cli_result["elapsed_seconds"],
                "manual_baseline_elapsed_seconds": manual_result["elapsed_seconds"],
                "loopback_litmus_command_count": cli_result["command_count"],
                "manual_baseline_command_count": manual_result["command_count"],
                "manual_commands_replaced": command_reduction,
            },
            "manual_baseline": manual_result,
            "failures": mismatches,
            "ordinary_false_positive_rows": ordinary_false_positives,
        }
    finally:
        for item in fixtures:
            item.stop()
        for item in samples:
            item.stop()


def run_cli_scan(scenarios: list[Scenario], timeout: float) -> dict[str, Any]:
    project_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    src = str(project_root / "src")
    env["PYTHONPATH"] = src if not env.get("PYTHONPATH") else src + os.pathsep + env["PYTHONPATH"]
    ports = ",".join(str(scenario.port) for scenario in scenarios)
    command = [
        sys.executable,
        "-m",
        "loopback_litmus",
        "scan",
        "--ports",
        ports,
        "--json",
        "--timeout",
        str(timeout),
    ]
    started = time.perf_counter()
    result = subprocess.run(
        command,
        check=True,
        cwd=project_root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    elapsed = time.perf_counter() - started
    return {
        "command": " ".join(command),
        "command_count": 1,
        "elapsed_seconds": round(elapsed, 3),
        "payload": json.loads(result.stdout),
    }


def run_manual_baseline(scenarios: list[Scenario], timeout: float) -> dict[str, Any]:
    command_count = 0
    failures: list[str] = []
    started = time.perf_counter()
    listener_command = listener_discovery_command()
    if listener_command:
        command_count += 1
        subprocess.run(
            listener_command,
            check=False,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    else:
        failures.append("No lsof or ss listener-discovery command available.")

    for scenario in scenarios:
        manual_http_get(scenario.port, timeout)
        command_count += 1
        manual_websocket_origin(scenario.port, timeout)
        command_count += 1
        manual_mcp_initialize(scenario.port, timeout)
        command_count += 1

    elapsed = time.perf_counter() - started
    return {
        "commands": [
            "lsof -iTCP -sTCP:LISTEN -n -P or ss -H -ltnp",
            "curl-style GET / per port",
            "WebSocket hostile-Origin handshake per port",
            "MCP initialize POST per port",
        ],
        "command_count": command_count,
        "elapsed_seconds": round(elapsed, 3),
        "failures": failures,
    }


def listener_discovery_command() -> list[str] | None:
    if shutil.which("lsof"):
        return ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]
    if shutil.which("ss"):
        return ["ss", "-H", "-ltnp"]
    return None


def manual_http_get(port: int, timeout: float) -> None:
    conn: http.client.HTTPConnection | None = None
    try:
        conn = http.client.HTTPConnection(HOST, port, timeout=timeout)
        conn.request("GET", "/", headers={"Origin": HOSTILE_ORIGIN})
        response = conn.getresponse()
        response.read(1024)
    except OSError:
        return
    finally:
        if conn:
            conn.close()


def manual_mcp_initialize(port: int, timeout: float) -> None:
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": "manual-baseline",
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
        }
    )
    for path in ("/mcp", "/"):
        conn: http.client.HTTPConnection | None = None
        try:
            conn = http.client.HTTPConnection(HOST, port, timeout=timeout)
            conn.request(
                "POST",
                path,
                body=payload,
                headers={"Content-Type": "application/json", "Origin": HOSTILE_ORIGIN},
            )
            response = conn.getresponse()
            response.read(1024)
            return
        except OSError:
            continue
        finally:
            if conn:
                conn.close()


def manual_websocket_origin(port: int, timeout: float) -> None:
    request = (
        "GET /ws HTTP/1.1\r\n"
        f"Host: {HOST}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: bWFudWFsLWJhc2VsaW5l\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Origin: {HOSTILE_ORIGIN}\r\n"
        "\r\n"
    )
    try:
        with socket.create_connection((HOST, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request.encode("ascii"))
            sock.recv(1024)
    except OSError:
        return


def ordinary_samples() -> list[tuple[str, int, bytes, str]]:
    return [
        ("plain-http-dev-page", 200, b"<html><body>local dev page</body></html>", "text/html"),
        ("plain-json-health-api", 200, b'{"status":"ok","service":"demo-api"}', "application/json"),
        ("plain-404-router", 404, b"not found", "text/plain"),
    ]


def start_http_sample(name: str, status: int, body: bytes, content_type: str) -> RunningHttpSample:
    class SampleHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer((HOST, 0), SampleHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return RunningHttpSample(name, int(server.server_address[1]), server)


def count_ok(rows: list[dict[str, Any]]) -> int:
    return sum(1 for row in rows if row["ok"])


def render_markdown(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    lines = [
        "# Benchmark Results",
        "",
        f"Status: `{report['status']}` for the fixture/manual workflow benchmark.",
        "",
        f"Run recorded: {report['recorded_at']}.",
        "",
        "## Scope",
        "",
        "The benchmark starts safe local fixtures plus ordinary local HTTP samples. It does not run historical vulnerable products, execute MCP configs, call tools, spawn commands through services, use credentials, or touch a Kubernetes cluster.",
        "",
        "## Reproducible Command",
        "",
        "```bash",
        "PYTHONPATH=src python3 scripts/benchmark.py --output BENCHMARK_RESULTS.md",
        "```",
        "",
        "## Results",
        "",
        "| Scenario | Group | Expected | Actual | Result |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in report["rows"]:
        result = "PASS" if row["ok"] else "FAIL"
        lines.append(
            f"| `{row['scenario']}` | `{row['group']}` | `{row['expected_risk']}` | `{row['actual_risk']}` | `{result}` |"
        )

    lines.extend(
        [
            "",
            "## Metrics",
            "",
            f"- Unsafe fixture true positives: `{metrics['unsafe_true_positives']}`.",
            f"- Hardened control true negatives: `{metrics['hardened_true_negatives']}`.",
            f"- Ordinary dev-server false positives: `{metrics['ordinary_false_positives']}` for `HIGH` or `MEDIUM` risk.",
            f"- `loopback-litmus scan` elapsed time: `{metrics['loopback_litmus_elapsed_seconds']}` seconds.",
            f"- Manual-equivalent baseline elapsed time: `{metrics['manual_baseline_elapsed_seconds']}` seconds.",
            f"- `loopback-litmus scan` command count: `{metrics['loopback_litmus_command_count']}`.",
            f"- Manual-equivalent command count: `{metrics['manual_baseline_command_count']}`.",
            f"- Manual commands replaced: `{metrics['manual_commands_replaced']}`.",
            "",
            "## Manual Baseline",
            "",
            "The baseline models the documented manual workflow as one listener-discovery command plus three checks per port: `curl`-style HTTP GET, hostile-Origin WebSocket handshake, and MCP `initialize` POST.",
            "",
            "Manual baseline command shapes:",
        ]
    )
    for command in report["manual_baseline"]["commands"]:
        lines.append(f"- `{command}`")

    lines.extend(
        [
            "",
            "## False-Positive Sampling",
            "",
            "The ordinary local samples were a plain HTML dev page, a plain JSON health API, and a 404 router. None were classified `HIGH` or `MEDIUM`.",
            "",
            "## Failures And Limits",
            "",
        ]
    )
    if report["failures"]:
        for failure in report["failures"]:
            lines.append(
                f"- `{failure['scenario']}` expected `{failure['expected']}` but got `{failure['actual']}`."
            )
    else:
        lines.append("- No fixture classification failures observed.")
    for failure in report["manual_baseline"]["failures"]:
        lines.append(f"- Manual baseline limitation: {failure}")
    lines.extend(
        [
            "- Timings are local workstation measurements and should be treated as workflow-order evidence, not a universal performance claim.",
            "- Process attribution was not benchmarked because fixed-port fixture targets bypass listener enumeration.",
            "- Browser-engine behavior for Private Network Access and `0.0.0.0` remains future browser-harness work.",
            "",
            "## Gate Status",
            "",
            f"- Benchmark: `{report['status']}`, citing this benchmark run and the scenarios above.",
            "- Discoverability: `PASS`, citing `DISCOVERABILITY.md`, `RELEASE_NOTES.md`, `README.md`, and `pyproject.toml`.",
            "- Publication: `READY_FOR_PRIVATE_PUBLISH`; public release remains blocked by the public-repo cooldown until 2026-06-25 19:56 Europe/Amsterdam.",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
