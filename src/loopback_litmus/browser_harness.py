from __future__ import annotations

import argparse
import json
import time
import webbrowser
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class BrowserHarnessCase:
    id: str
    label: str
    url: str
    bind_address: str
    expected_scope: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def build_browser_cases(loopback_port: int, all_interface_port: int) -> list[BrowserHarnessCase]:
    return [
        BrowserHarnessCase(
            id="localhost-to-loopback",
            label="localhost fetch to a 127.0.0.1-bound target",
            url=f"http://localhost:{loopback_port}/probe",
            bind_address="127.0.0.1",
            expected_scope="loopback",
        ),
        BrowserHarnessCase(
            id="ipv4-loopback-to-loopback",
            label="127.0.0.1 fetch to a 127.0.0.1-bound target",
            url=f"http://127.0.0.1:{loopback_port}/probe",
            bind_address="127.0.0.1",
            expected_scope="loopback",
        ),
        BrowserHarnessCase(
            id="ipv4-loopback-to-all-interface",
            label="127.0.0.1 fetch to a 0.0.0.0-bound target",
            url=f"http://127.0.0.1:{all_interface_port}/probe",
            bind_address="0.0.0.0",
            expected_scope="all-interface via loopback",
        ),
        BrowserHarnessCase(
            id="zero-address-to-all-interface",
            label="0.0.0.0 fetch to a 0.0.0.0-bound target",
            url=f"http://0.0.0.0:{all_interface_port}/probe",
            bind_address="0.0.0.0",
            expected_scope="browser-specific 0.0.0.0 behavior",
        ),
    ]


def browser_harness_command(args: argparse.Namespace) -> int:
    output = Path(args.output) if args.output else None
    harness = BrowserHarness(page_host=args.page_host, page_port=args.page_port, output=output)
    harness.start()
    url = harness.url
    print(f"browser harness: {url}")
    print("target endpoints: 127.0.0.1 and 0.0.0.0; only safe GET/OPTIONS probes are served")
    if args.open:
        webbrowser.open(url)

    try:
        deadline = time.monotonic() + args.duration
        while time.monotonic() < deadline:
            if harness.results is not None:
                if output:
                    print(f"browser results written: {output}")
                else:
                    print(json.dumps(harness.results, indent=2, sort_keys=True))
                return 0
            time.sleep(0.1)
        print("no browser results received before timeout")
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        harness.stop()


class BrowserHarness:
    def __init__(self, page_host: str = "127.0.0.1", page_port: int = 0, output: Path | None = None) -> None:
        if page_host not in {"127.0.0.1", "localhost"}:
            raise ValueError("browser harness page host must be 127.0.0.1 or localhost")
        self.output = output
        self.loopback_target = BrowserProbeServer(("127.0.0.1", 0), "127.0.0.1")
        self.all_interface_target = BrowserProbeServer(("0.0.0.0", 0), "0.0.0.0")
        self.cases = build_browser_cases(
            loopback_port=int(self.loopback_target.server_address[1]),
            all_interface_port=int(self.all_interface_target.server_address[1]),
        )
        self.page_server = BrowserPageServer((page_host, page_port), self.cases, self)
        self._servers = [self.loopback_target, self.all_interface_target, self.page_server]

    @property
    def url(self) -> str:
        host, port = self.page_server.server_address[:2]
        return f"http://{host}:{port}/"

    @property
    def results(self) -> dict[str, Any] | None:
        return self.page_server.results

    def start(self) -> None:
        for server in self._servers:
            server.start()

    def stop(self) -> None:
        for server in reversed(self._servers):
            server.stop()

    def write_results(self, browser_results: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "schema_version": "0.1",
            "safety": {
                "executes_commands": False,
                "mutates_services": False,
                "scans_public_networks": False,
            },
            "cases": [case.to_dict() for case in self.cases],
            "browser_results": browser_results,
            "target_requests": {
                "loopback": self.loopback_target.observed_requests,
                "all_interface": self.all_interface_target.observed_requests,
            },
        }
        if self.output:
            self.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.page_server.results = payload
        return payload


class ManagedThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def start(self) -> None:
        import threading

        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
        thread = getattr(self, "_thread", None)
        if thread:
            thread.join(timeout=2)


class BrowserProbeServer(ManagedThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], bind_address: str) -> None:
        self.bind_address = bind_address
        self.observed_requests: list[dict[str, str | None]] = []
        super().__init__(server_address, BrowserProbeHandler)


class BrowserProbeHandler(BaseHTTPRequestHandler):
    server_version = "loopback-litmus-browser-target/0.1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_OPTIONS(self) -> None:
        self._record_request()
        self.send_response(204)
        self._send_cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        self._record_request()
        if self.path != "/probe":
            self.send_response(404)
            self._send_cors_headers()
            self.end_headers()
            return

        payload = {
            "ok": True,
            "bind_address": self.server.bind_address,
            "host_header": self.headers.get("Host"),
            "origin": self.headers.get("Origin"),
            "sec_fetch_mode": self.headers.get("Sec-Fetch-Mode"),
            "sec_fetch_site": self.headers.get("Sec-Fetch-Site"),
        }
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(200)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Cache-Control", "no-store")

    def _record_request(self) -> None:
        self.server.observed_requests.append(
            {
                "method": self.command,
                "path": self.path,
                "host": self.headers.get("Host"),
                "origin": self.headers.get("Origin"),
                "sec_fetch_mode": self.headers.get("Sec-Fetch-Mode"),
                "sec_fetch_site": self.headers.get("Sec-Fetch-Site"),
                "access_control_request_private_network": self.headers.get("Access-Control-Request-Private-Network"),
            }
        )


class BrowserPageServer(ManagedThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], cases: list[BrowserHarnessCase], harness: BrowserHarness) -> None:
        self.cases = cases
        self.harness = harness
        self.results: dict[str, Any] | None = None
        super().__init__(server_address, BrowserPageHandler)


class BrowserPageHandler(BaseHTTPRequestHandler):
    server_version = "loopback-litmus-browser-page/0.1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        if self.path not in {"/", "/index.html"}:
            self.send_response(404)
            self.end_headers()
            return
        body = render_browser_harness_html(self.server.cases).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path != "/results":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            browser_results = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        payload = self.server.harness.write_results(browser_results)
        body = json.dumps({"ok": True, "result_count": len(payload["browser_results"].get("results", []))}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def render_browser_harness_html(cases: list[BrowserHarnessCase]) -> str:
    cases_json = json.dumps([case.to_dict() for case in cases], sort_keys=True)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>loopback-litmus browser harness</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {{ font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; color: #111827; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
    th, td {{ border: 1px solid #d1d5db; padding: 0.5rem; text-align: left; vertical-align: top; }}
    th {{ background: #f3f4f6; }}
    code, pre {{ background: #f9fafb; }}
    pre {{ padding: 1rem; overflow: auto; }}
  </style>
</head>
<body>
  <h1>loopback-litmus browser harness</h1>
  <p>This page performs safe CORS GET probes against local test endpoints and posts the observed browser results back to the harness server.</p>
  <table>
    <thead><tr><th>Case</th><th>URL</th><th>Status</th><th>Evidence</th></tr></thead>
    <tbody id="results"></tbody>
  </table>
  <pre id="json"></pre>
  <script>
    const cases = {cases_json};
    const tbody = document.getElementById("results");
    const jsonEl = document.getElementById("json");

    function rowFor(testCase, status, evidence) {{
      const row = document.createElement("tr");
      row.innerHTML = `<td>${{testCase.label}}</td><td><code>${{testCase.url}}</code></td><td>${{status}}</td><td><code>${{evidence}}</code></td>`;
      tbody.appendChild(row);
    }}

    async function runCase(testCase) {{
      const started = performance.now();
      try {{
        const response = await fetch(testCase.url, {{ method: "GET", cache: "no-store", mode: "cors" }});
        const text = await response.text();
        let parsed = null;
        try {{ parsed = JSON.parse(text); }} catch (_) {{}}
        const result = {{
          id: testCase.id,
          label: testCase.label,
          url: testCase.url,
          ok: response.ok,
          status: response.status,
          elapsed_ms: Math.round(performance.now() - started),
          body: parsed,
        }};
        rowFor(testCase, response.status, parsed ? JSON.stringify(parsed) : text.slice(0, 160));
        return result;
      }} catch (error) {{
        const result = {{
          id: testCase.id,
          label: testCase.label,
          url: testCase.url,
          ok: false,
          error_name: error.name,
          error_message: error.message,
          elapsed_ms: Math.round(performance.now() - started),
        }};
        rowFor(testCase, error.name, error.message);
        return result;
      }}
    }}

    async function main() {{
      const payload = {{
        user_agent: navigator.userAgent,
        origin: window.location.origin,
        results: [],
      }};
      for (const testCase of cases) {{
        payload.results.push(await runCase(testCase));
      }}
      jsonEl.textContent = JSON.stringify(payload, null, 2);
      await fetch("/results", {{
        method: "POST",
        headers: {{ "Content-Type": "application/json" }},
        body: JSON.stringify(payload),
      }});
    }}

    main();
  </script>
</body>
</html>
"""
