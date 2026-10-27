"""Vulnerability correlation: version to CVE mapping and exploit lookup."""

from __future__ import annotations

import json
import re
from typing import Dict, List

from ..models import Finding, ScanResult, Severity
from ..utils import run_command
from .base import BaseScanner, register


VULN_KB: Dict[str, List[dict]] = {
    "apache": [
        {
            "pattern": r"^2\.4\.(4[0-9]|5[0-1])",
            "cve": "CVE-2021-42013",
            "cvss": 9.8,
            "severity": "critical",
            "title": "Apache HTTP Server path traversal and remote code execution",
            "remediation": "Upgrade Apache HTTP Server to 2.4.52 or later.",
        },
        {
            "pattern": r"^2\.4\.([0-9]|[1-3][0-9])",
            "cve": "CVE-2019-0211",
            "cvss": 7.8,
            "severity": "high",
            "title": "Apache HTTP Server local privilege escalation",
            "remediation": "Upgrade Apache HTTP Server to 2.4.39 or later.",
        },
    ],
    "nginx": [
        {
            "pattern": r"^1\.(1[0-9]|2[0-1])\.[0-9]$",
            "cve": "CVE-2021-23017",
            "cvss": 7.7,
            "severity": "high",
            "title": "nginx resolver off-by-one heap write",
            "remediation": "Upgrade nginx to 1.21.0 or later.",
        },
    ],
    "openssh": [
        {
            "pattern": r"^[0-7]\.[0-9]",
            "cve": "CVE-2020-14145",
            "cvss": 5.9,
            "severity": "medium",
            "title": "OpenSSH observable discrepancy information leak",
            "remediation": "Upgrade OpenSSH to 8.4 or later.",
        },
    ],
    "openssl": [
        {
            "pattern": r"^1\.0\.1",
            "cve": "CVE-2014-0160",
            "cvss": 7.5,
            "severity": "high",
            "title": "OpenSSL Heartbleed information disclosure",
            "remediation": "Upgrade OpenSSL to 1.0.1g or later.",
        },
        {
            "pattern": r"^3\.0\.[0-6]$",
            "cve": "CVE-2022-3786",
            "cvss": 7.5,
            "severity": "high",
            "title": "OpenSSL X.509 email address buffer overflow",
            "remediation": "Upgrade OpenSSL to 3.0.7 or later.",
        },
    ],
    "php": [
        {
            "pattern": r"^7\.[0-3]",
            "cve": "CVE-2019-11043",
            "cvss": 9.8,
            "severity": "critical",
            "title": "PHP-FPM underflow leading to remote code execution",
            "remediation": "Upgrade PHP to 7.3.11 or later and patch PHP-FPM.",
        },
    ],
    "jquery": [
        {
            "pattern": r"^([12]\.[0-9]|3\.[0-4])",
            "cve": "CVE-2020-11022",
            "cvss": 6.1,
            "severity": "medium",
            "title": "jQuery cross-site scripting in htmlPrefilter",
            "remediation": "Upgrade jQuery to 3.5.0 or later.",
        },
    ],
}


COMPONENT_PATTERN = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z0-9_.-]{1,30})[/ ](?P<version>[0-9]+\.[0-9]+(?:\.[0-9]+)?)"
)


@register
class VulnerabilityCorrelationScanner(BaseScanner):
    name = "vuln_correlate"
    category = "vulnerability"
    description = "Maps detected component versions to known CVEs and exploit references"
    requires: List[str] = []

    def scan(self, result: ScanResult) -> List[Finding]:
        findings: List[Finding] = []
        self.log.info("Correlating detected software versions against the CVE knowledge base", scope=self.name)

        for component, version, source in self._collect_banners():
            for match in self._match(component, version):
                findings.append(
                    self.finding(
                        title=match["title"],
                        severity=Severity.from_text(match["severity"]),
                        category="vulnerability",
                        description=(
                            "Detected %s %s via %s. This version is affected by %s (CVSS %.1f)."
                            % (component, version, source, match["cve"], match["cvss"])
                        ),
                        remediation=match["remediation"],
                        confidence="medium",
                        cve=[match["cve"]],
                        cvss=match["cvss"],
                    )
                )

        for item in self._searchsploit():
            findings.append(
                self.finding(
                    title="Public exploit available: %s" % (item.get("title") or "unknown"),
                    severity=Severity.HIGH,
                    category="vulnerability",
                    description="searchsploit returned a public exploit record: %s" % item.get("path", ""),
                    remediation="Patch the affected component and validate exposure.",
                    source_tool="searchsploit",
                    confidence="low",
                )
            )

        return findings

    # ---------------------------------------------------------------- helpers
    def _collect_banners(self) -> List[tuple]:
        banners: List[tuple] = []
        seen = set()
        for key in ("tech_stack", "server_banner", "http_headers", "nmap_services"):
            data = self.ctx.recall(key)
            if not data:
                continue
            text = data if isinstance(data, str) else json.dumps(data, default=str)
            for match in COMPONENT_PATTERN.finditer(text):
                key_tuple = (match.group("name").lower(), match.group("version"))
                if key_tuple in seen:
                    continue
                seen.add(key_tuple)
                banners.append((match.group("name"), match.group("version"), key))
        return banners

    def _match(self, component: str, version: str) -> List[dict]:
        entries = VULN_KB.get(component.lower())
        if not entries:
            for name, items in VULN_KB.items():
                if name in component.lower():
                    entries = items
                    break
        if not entries:
            return []
        return [entry for entry in entries if re.match(entry["pattern"], version)]

    def _searchsploit(self) -> List[dict]:
        path = self.ctx.tools.path_of("searchsploit")
        if not path:
            return []
        tech = self.ctx.recall("tech_stack") or []
        terms = [str(t) for t in tech[:5]] if isinstance(tech, list) else []
        if not terms:
            return []
        results: List[dict] = []
        for term in terms:
            outcome = run_command([path, "--json", term], timeout=60)
            if outcome.returncode != 0 or not outcome.stdout.strip():
                continue
            try:
                payload = json.loads(outcome.stdout)
            except json.JSONDecodeError:
                continue
            for record in payload.get("RESULTS_EXPLOIT", [])[:3]:
                results.append({"title": record.get("Title", ""), "path": record.get("Path", "")})
        return results
