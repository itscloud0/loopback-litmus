from __future__ import annotations

import contextlib
import http.client
import io
import json
import tempfile
import unittest
from pathlib import Path

from loopback_litmus.browser_harness import BrowserHarness, BrowserProbeServer, build_browser_cases, render_browser_harness_html
from loopback_litmus.cli import build_parser


class BrowserHarnessTests(unittest.TestCase):
    def test_cases_cover_localhost_loopback_and_zero_address(self) -> None:
        cases = build_browser_cases(loopback_port=18780, all_interface_port=18781)

        self.assertEqual(
            [case.id for case in cases],
            [
                "localhost-to-loopback",
                "ipv4-loopback-to-loopback",
                "ipv4-loopback-to-all-interface",
                "zero-address-to-all-interface",
            ],
        )
        self.assertIn("http://localhost:18780/probe", [case.url for case in cases])
        self.assertIn("http://0.0.0.0:18781/probe", [case.url for case in cases])

    def test_rendered_page_embeds_cases_without_external_assets(self) -> None:
        html = render_browser_harness_html(build_browser_cases(loopback_port=18780, all_interface_port=18781))

        self.assertIn("loopback-litmus browser harness", html)
        self.assertIn("localhost-to-loopback", html)
        self.assertIn("zero-address-to-all-interface", html)
        self.assertNotIn("<script src=", html)
        self.assertNotIn("https://", html)

    def test_probe_target_handles_cors_and_private_network_preflight(self) -> None:
        server = BrowserProbeServer(("127.0.0.1", 0), "127.0.0.1")
        server.start()
        try:
            port = int(server.server_address[1])
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request(
                "OPTIONS",
                "/probe",
                headers={
                    "Origin": "http://127.0.0.1:9000",
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Private-Network": "true",
                },
            )
            preflight = conn.getresponse()
            preflight.read()
            self.assertEqual(preflight.status, 204)
            self.assertEqual(preflight.getheader("Access-Control-Allow-Private-Network"), "true")
            conn.close()

            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request("GET", "/probe", headers={"Origin": "http://127.0.0.1:9000"})
            response = conn.getresponse()
            payload = json.loads(response.read().decode("utf-8"))
            conn.close()

            self.assertEqual(response.status, 200)
            self.assertEqual(response.getheader("Access-Control-Allow-Origin"), "*")
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["bind_address"], "127.0.0.1")
            self.assertEqual(server.observed_requests[0]["access_control_request_private_network"], "true")
        finally:
            server.stop()

    def test_harness_writes_reproducible_safety_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "results.json"
            harness = BrowserHarness(output=output)
            harness.start()
            try:
                payload = harness.write_results(
                    {
                        "user_agent": "test-browser",
                        "origin": harness.url.rstrip("/"),
                        "results": [{"id": "localhost-to-loopback", "ok": True, "status": 200}],
                    }
                )
            finally:
                harness.stop()

            written = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(payload["schema_version"], "0.1")
        self.assertFalse(written["safety"]["executes_commands"])
        self.assertFalse(written["safety"]["mutates_services"])
        self.assertFalse(written["safety"]["scans_public_networks"])
        self.assertEqual(len(written["cases"]), 4)
        self.assertEqual(written["browser_results"]["user_agent"], "test-browser")

    def test_browser_harness_page_host_is_loopback_only(self) -> None:
        parser = build_parser()

        args = parser.parse_args(["browser-harness", "--page-host", "localhost"])
        self.assertEqual(args.page_host, "localhost")

        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["browser-harness", "--page-host", "0.0.0.0"])


if __name__ == "__main__":
    unittest.main()
