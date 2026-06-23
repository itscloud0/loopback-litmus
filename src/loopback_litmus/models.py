from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ServiceTarget:
    host: str
    port: int
    bind_address: str | None = None
    process: str | None = None
    pid: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "bind_address": self.bind_address,
            "process": self.process,
            "pid": self.pid,
        }


@dataclass
class ProbeResult:
    name: str
    status: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class Finding:
    target: ServiceTarget
    risk: str
    product_hint: str | None
    evidence: list[str]
    remediation: list[str]
    probes: list[ProbeResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "risk": self.risk,
            "product_hint": self.product_hint,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "probes": [probe.to_dict() for probe in self.probes],
        }
