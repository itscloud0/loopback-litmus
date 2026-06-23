from __future__ import annotations

import json

from .models import Finding


def render_text(findings: list[Finding]) -> str:
    if not findings:
        return "No loopback or all-interface listening services selected for scanning."

    lines: list[str] = []
    for finding in findings:
        target = finding.target
        hint = f" ({finding.product_hint})" if finding.product_hint else ""
        bind = f", bind={target.bind_address}" if target.bind_address else ""
        process = f", process={target.process}" if target.process else ""
        lines.append(f"{finding.risk}  {target.host}:{target.port}{hint}{bind}{process}")
        for item in finding.evidence:
            lines.append(f"      Evidence: {item}")
        for item in finding.remediation:
            lines.append(f"      Fix: {item}")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_json(findings: list[Finding]) -> str:
    payload = {
        "schema_version": "0.1",
        "safety": {
            "executes_commands": False,
            "mutates_services": False,
            "default_public_network_scan": False,
        },
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
