from __future__ import annotations

from .models import Finding, ProbeResult, ServiceTarget
from .ports import product_hint
from .probes import probe_http, probe_mcp_initialize, probe_websocket_origin

RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3, "UNREACHABLE": 4}


def scan_target(target: ServiceTarget, timeout: float = 1.0) -> Finding:
    probes = [
        probe_http(target, timeout),
        probe_websocket_origin(target, timeout),
        probe_mcp_initialize(target, timeout),
    ]
    return classify(target, probes)


def scan_targets(targets: list[ServiceTarget], timeout: float = 1.0) -> list[Finding]:
    findings = [scan_target(target, timeout) for target in targets]
    return sorted(findings, key=lambda finding: (RISK_ORDER.get(finding.risk, 99), finding.target.port))


def classify(target: ServiceTarget, probes: list[ProbeResult]) -> Finding:
    risk = "INFO"
    evidence: list[str] = []
    remediation: list[str] = []

    ws = get_probe(probes, "websocket_origin")
    mcp = get_probe(probes, "mcp_initialize")
    http = get_probe(probes, "http_get")

    if target.bind_address == "0.0.0.0":
        evidence.append("service listens on all interfaces, not loopback only")
        remediation.append("bind the control plane to 127.0.0.1 or ::1 unless remote access is required")
        risk = "MEDIUM"

    if ws and ws.status == "accepted":
        risk = "HIGH"
        evidence.append(ws.detail)
        remediation.append("require authentication and validate Origin on every WebSocket upgrade")

    if mcp and mcp.status == "accepted":
        risk = "HIGH"
        evidence.append(mcp.detail)
        remediation.append("require authentication before MCP initialize and tool discovery")

    if http and http.status == "metadata_exposed":
        if risk not in {"HIGH", "MEDIUM"}:
            risk = "MEDIUM"
        evidence.append(http.detail)
        remediation.append("avoid exposing agent or MCP metadata without authentication")

    if ws and ws.status in {"origin_rejected", "auth_required"} and risk == "INFO":
        risk = "LOW"
        evidence.append(ws.detail)

    if http and http.status == "auth_required" and risk in {"INFO", "LOW"}:
        risk = "LOW"
        evidence.append(http.detail)

    if mcp and mcp.status == "auth_required" and risk in {"INFO", "LOW"}:
        risk = "LOW"
        evidence.append(mcp.detail)

    if all(probe.status == "unreachable" for probe in probes):
        risk = "UNREACHABLE"
        evidence.append("no probe could connect to the target")

    if not evidence:
        evidence.append("service reachable, but no agent/MCP browser-origin risk evidence found")

    if not remediation and risk in {"INFO", "LOW", "UNREACHABLE"}:
        remediation.append("no immediate remediation from safe probes; review service capability if it is an agent control plane")

    return Finding(
        target=target,
        risk=risk,
        product_hint=product_hint(target.process, target.port),
        evidence=evidence,
        remediation=dedupe(remediation),
        probes=probes,
    )


def get_probe(probes: list[ProbeResult], name: str) -> ProbeResult | None:
    return next((probe for probe in probes if probe.name == name), None)


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
