"""Core data models for SecAuto.

All scanners, the orchestrator and the reporters speak in these objects so that
results are consistent, serialisable and easy to merge.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Ordered severity levels used for findings and scoring."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
            Severity.UNKNOWN: 0,
        }[self]

    @property
    def color(self) -> str:
        """ANSI colour escape for terminal rendering."""
        return {
            Severity.CRITICAL: "\033[1;97;41m",
            Severity.HIGH: "\033[1;31m",
            Severity.MEDIUM: "\033[1;33m",
            Severity.LOW: "\033[1;36m",
            Severity.INFO: "\033[1;34m",
            Severity.UNKNOWN: "\033[0;37m",
        }[self]

    @classmethod
    def from_text(cls, value: str) -> "Severity":
        value = (value or "").strip().lower()
        for member in cls:
            if member.value == value:
                return member
        aliases = {
            "crit": cls.CRITICAL,
            "error": cls.HIGH,
            "warn": cls.MEDIUM,
            "warning": cls.MEDIUM,
            "notice": cls.LOW,
            "informational": cls.INFO,
        }
        return aliases.get(value, cls.UNKNOWN)


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


@dataclass
class Finding:
    """A single security observation."""

    title: str
    severity: Severity = Severity.INFO
    description: str = ""
    target: str = ""
    category: str = "general"
    evidence: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cve: List[str] = field(default_factory=list)
    cwe: List[str] = field(default_factory=list)
    cvss: Optional[float] = None
    confidence: str = "medium"
    source_tool: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    discovered_at: str = field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    )

    @property
    def fingerprint(self) -> str:
        """Stable key used to de-duplicate findings across tools."""
        raw = f"{self.category}|{self.title}|{self.target}".lower()
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["severity"] = self.severity.value
        data["fingerprint"] = self.fingerprint
        return data


@dataclass
class ScanResult:
    """Outcome of a single scanner run."""

    scanner: str
    status: ScanStatus = ScanStatus.PENDING
    findings: List[Finding] = field(default_factory=list)
    raw_output: str = ""
    command: str = ""
    duration: float = 0.0
    error: str = ""
    started_at: str = ""
    finished_at: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner": self.scanner,
            "status": self.status.value,
            "findings": [f.to_dict() for f in self.findings],
            "command": self.command,
            "duration": round(self.duration, 3),
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "metadata": self.metadata,
            "raw_output": self.raw_output,
        }


@dataclass
class Target:
    """Normalised representation of whatever the user supplied."""

    input: str
    hostname: Optional[str] = None
    ip: Optional[str] = None
    scheme: str = "https"
    port: Optional[int] = None
    base_url: str = ""
    is_ip: bool = False
    root_domain: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class ScanReport:
    """Aggregate report produced by the orchestrator."""

    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    target: Optional[Target] = None
    results: List[ScanResult] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    duration: float = 0.0
    environment: Dict[str, Any] = field(default_factory=dict)
    tooling: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    # ---------------------------------------------------------------- findings
    @property
    def findings(self) -> List[Finding]:
        collected: List[Finding] = []
        seen = set()
        for result in self.results:
            for finding in result.findings:
                key = finding.fingerprint
                if key in seen:
                    continue
                seen.add(key)
                collected.append(finding)
        return collected

    def severity_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def risk_score(self) -> float:
        """0-100 score: higher means more exposed. Weighted + diminishing."""
        weights = {
            Severity.CRITICAL: 25.0,
            Severity.HIGH: 12.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 1.5,
            Severity.INFO: 0.2,
            Severity.UNKNOWN: 0.0,
        }
        raw = sum(weights[f.severity] for f in self.findings)
        # 100 * (1 - e^-raw/40) gives smooth saturation toward 100
        import math

        return round(100.0 * (1.0 - math.exp(-raw / 40.0)), 1)

    @property
    def posture(self) -> str:
        score = self.risk_score
        if score >= 75:
            return "CRITICAL EXPOSURE"
        if score >= 50:
            return "HIGH RISK"
        if score >= 25:
            return "MODERATE RISK"
        if score >= 8:
            return "LOW RISK"
        return "HARDENED / MINIMAL RISK"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target.to_dict() if self.target else None,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": round(self.duration, 2),
            "risk_score": self.risk_score,
            "posture": self.posture,
            "severity_counts": self.severity_counts(),
            "environment": self.environment,
            "tooling": self.tooling,
            "notes": self.notes,
            "results": [r.to_dict() for r in self.results],
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


__all__ = [
    "Severity",
    "ScanStatus",
    "Finding",
    "ScanResult",
    "Target",
    "ScanReport",
]
