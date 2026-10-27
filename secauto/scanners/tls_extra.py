"""Advanced TLS scanners: testssl.sh and SSLyze adapters."""

from __future__ import annotations

import json
import re
from typing import Dict, List

from ..models import Finding, ScanResult, Severity
from ..utils import run_command, truncate
from .base import BaseScanner, register


def _testssl_path(ctx) -> str:
    path = ctx.tools.path_of("testssl") or ctx.tools.path_of("testssl.sh")
    if path:
        return path
    from ..config import default_tools_dir

    candidate = default_tools_dir() / "testssl" / "testssl.sh"
    return str(candidate) if candidate.exists() else "testssl.sh"


@register
class TestSSLScanner(BaseScanner):
    name = "testssl"
    description = "Deep TLS/SSL configuration analysis with testssl.sh"
    category = "tls"
    requires = ["testssl"]

    def scan(self, result: ScanResult) -> List[Finding]:
        binary = _testssl_path(self.ctx)
        host = self.target.hostname or self.target.ip
        port = self.target.port or (443 if self.target.scheme == "https" else 80)
        target = f"{host}:{port}"
        outcome = run_command(
            [binary, "--quiet", "--color", "0", "--jsonfile", "-", target],
            timeout=min(self.config.timeout, 900),
        )
        result.command = outcome.command
        result.raw_output = truncate(outcome.stdout or outcome.stderr, 6000)

        items = self._parse(outcome.stdout)
        result.metadata["item_count"] = len(items)
        findings: List[Finding] = []
        for item in items:
            sev = self._severity(item.get("severity", ""))
            if sev in (Severity.INFO, Severity.UNKNOWN) and item.get("severity", "").upper() not in ("WARN",):
                continue
            findings.append(
                self.finding(
                    title=f"{item.get('id','TLS')}: {item.get('finding','')}"[:180],
                    severity=sev,
                    category="tls",
                    description=item.get("finding", ""),
                    evidence=f"id={item.get('id','')} severity={item.get('severity','')}",
                    remediation="Follow the testssl.sh reference for this finding.",
                    references=[item["cve"]] if item.get("cve") else [],
                )
            )
        if not findings:
            findings.append(
                self.finding(
                    title="testssl.sh reported no significant TLS weaknesses",
                    severity=Severity.INFO,
                    category="tls",
                    description=f"TLS configuration for {target} passed testssl.sh checks.",
                )
            )
        return findings

    @staticmethod
    def _parse(output: str) -> List[Dict[str, str]]:
        text = (output or "").strip()
        items: List[Dict[str, str]] = []
        start = text.find("{")
        if start >= 0:
            try:
                data = json.loads(text[start:])
            except json.JSONDecodeError:
                data = None
            if isinstance(data, dict):
                for record in data.get("scanResult", []) or []:
                    if isinstance(record, dict):
                        items.append(
                            {
                                "id": str(record.get("id", "")),
                                "severity": str(record.get("severity", "")),
                                "finding": str(record.get("finding", "")),
                                "cve": str(record.get("cve", "")),
                            }
                        )
                if items:
                    return items
        for line in text.splitlines():
            # e.g. " TLS 1.0 offered (deprecated)  [warn]"
            match = re.match(r"\s*([A-Za-z0-9_\-. ]+?)\s{2,}(.+?)\s*\[(\w+)\]\s*$", line)
            if match:
                items.append(
                    {
                        "id": match.group(1).strip(),
                        "finding": match.group(2).strip(),
                        "severity": match.group(3).strip(),
                    }
                )
        return items

    @staticmethod
    def _severity(value: str) -> Severity:
        value = (value or "").lower()
        if value in ("critical", "crit"):
            return Severity.CRITICAL
        if value in ("high", "error"):
            return Severity.HIGH
        if value in ("medium", "warn", "warning"):
            return Severity.MEDIUM
        if value in ("low", "info"):
            return Severity.LOW if value == "low" else Severity.INFO
        return Severity.UNKNOWN


@register
class SSLyzeScanner(BaseScanner):
    name = "sslyze"
    description = "TLS scanning with SSLyze (Python)"
    category = "tls"
    requires = ["sslyze"]

    def scan(self, result: ScanResult) -> List[Finding]:
        binary = self.ctx.tools.path_of("sslyze") or "sslyze"
        host = self.target.hostname or self.target.ip
        port = self.target.port or (443 if self.target.scheme == "https" else 80)
        outcome = run_command(
            [binary, "--json_out=-", f"{host}:{port}"], timeout=min(self.config.timeout, 600)
        )
        result.command = outcome.command
        result.raw_output = truncate(outcome.stdout or outcome.stderr, 5000)

        findings: List[Finding] = []
        try:
            data = json.loads(outcome.stdout)
        except json.JSONDecodeError:
            return [
                self.finding(
                    title="SSLyze produced no parsable output",
                    severity=Severity.INFO,
                    category="tls",
                    description="SSLyze did not return JSON; see raw output.",
                )
            ]

        for server in data.get("server_scan_results", []) or []:
            scan = server.get("scan_result", {}) or {}
            for key in ("ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites", "tls_1_0_cipher_suites", "tls_1_1_cipher_suites"):
                block = scan.get(key) or {}
                accepted = block.get("accepted_cipher_suites") or []
                if accepted:
                    proto = key.replace("_cipher_suites", "").replace("_", " ").upper()
                    findings.append(
                        self.finding(
                            title=f"Deprecated protocol accepted: {proto}",
                            severity=Severity.HIGH,
                            category="tls",
                            description=f"{host}:{port} accepts {proto} with {len(accepted)} cipher suite(s).",
                            remediation="Disable legacy protocol versions and require TLS 1.2+.",
                        )
                    )
            cert = (scan.get("certificate_info") or {}).get("certificate_deployments") or []
            for deployment in cert:
                chain = deployment.get("received_certificate_chain") or []
                if chain:
                    findings.append(
                        self.finding(
                            title=f"SSLyze certificate chain length: {len(chain)}",
                            severity=Severity.INFO,
                            category="tls",
                            description=f"TLS certificate chain for {host} contains {len(chain)} certificate(s).",
                        )
                    )
        if not findings:
            findings.append(
                self.finding(
                    title="SSLyze reported no legacy protocol support",
                    severity=Severity.INFO,
                    category="tls",
                    description=f"TLS configuration for {host}:{port} passed SSLyze protocol checks.",
                )
            )
        return findings


__all__ = ["TestSSLScanner", "SSLyzeScanner"]