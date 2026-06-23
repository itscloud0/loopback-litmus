from __future__ import annotations

import json
import unittest

from loopback_litmus.fixtures import start_fixture
from loopback_litmus.models import ServiceTarget
from loopback_litmus.render import render_json
from loopback_litmus.scanner import scan_target


class FixtureScanTests(unittest.TestCase):
    def test_websocket_without_origin_check_is_high_risk(self) -> None:
        fixture = start_fixture("websocket-no-origin")
        try:
            finding = scan_target(ServiceTarget("127.0.0.1", fixture.port), timeout=1)
        finally:
            fixture.stop()

        self.assertEqual(finding.risk, "HIGH")
        self.assertTrue(any("accepted hostile Origin" in item for item in finding.evidence))

    def test_websocket_origin_enforced_is_low_risk(self) -> None:
        fixture = start_fixture("websocket-origin-enforced")
        try:
            finding = scan_target(ServiceTarget("127.0.0.1", fixture.port), timeout=1)
        finally:
            fixture.stop()

        self.assertEqual(finding.risk, "LOW")
        self.assertTrue(any("rejected hostile Origin" in item for item in finding.evidence))

    def test_mcp_unauth_initialize_is_high_risk(self) -> None:
        fixture = start_fixture("mcp-unauth-initialize")
        try:
            finding = scan_target(ServiceTarget("127.0.0.1", fixture.port), timeout=1)
        finally:
            fixture.stop()

        self.assertEqual(finding.risk, "HIGH")
        self.assertTrue(any("accepted unauthenticated MCP initialize" in item for item in finding.evidence))

    def test_mcp_auth_required_is_low_risk(self) -> None:
        fixture = start_fixture("mcp-auth-required")
        try:
            finding = scan_target(ServiceTarget("127.0.0.1", fixture.port), timeout=1)
        finally:
            fixture.stop()

        self.assertEqual(finding.risk, "LOW")
        self.assertTrue(any("rejected unauthenticated" in item for item in finding.evidence))

    def test_json_report_has_stable_shape(self) -> None:
        fixture = start_fixture("http-metadata-open")
        try:
            finding = scan_target(ServiceTarget("127.0.0.1", fixture.port), timeout=1)
        finally:
            fixture.stop()

        payload = json.loads(render_json([finding]))
        self.assertEqual(payload["schema_version"], "0.1")
        self.assertFalse(payload["safety"]["executes_commands"])
        self.assertEqual(payload["findings"][0]["risk"], "MEDIUM")

    def test_advisory_fixtures_are_high_risk(self) -> None:
        cases = (
            ("advisory-mcp-inspector-open", "accepted unauthenticated MCP initialize"),
            ("advisory-claude-ide-ws-open", "accepted hostile Origin"),
            ("advisory-kubectl-mcp-open", "accepted unauthenticated MCP initialize"),
            ("advisory-gpt-researcher-ws-open", "accepted hostile Origin"),
        )
        for case, expected_evidence in cases:
            with self.subTest(case=case):
                fixture = start_fixture(case)
                try:
                    finding = scan_target(ServiceTarget("127.0.0.1", fixture.port), timeout=1)
                finally:
                    fixture.stop()

                self.assertEqual(finding.risk, "HIGH")
                self.assertTrue(any(expected_evidence in item for item in finding.evidence))


if __name__ == "__main__":
    unittest.main()
