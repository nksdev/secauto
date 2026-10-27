"""Web application vulnerability scanners.

Adapters for Nikto, Nuclei, WhatWeb and Wafw00f, plus a built-in checker for
common sensitive paths so the platform still produces web findings when no
external scanner is installed.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List

from ..models import Finding, ScanResult, Severity
from ..utils import run_command, truncate
from .base import BaseScanner, register


@register
class NiktoScanner(BaseScanner):
    name = "nikto"
    description = "Web server misconfiguration scanning with Nikto"
    category = "web"
    requires = ["nikto"]

    def scan(self, result: ScanResult) -> List[Finding]:
        binary = self.ctx.tools.path_of("nikto") or "nikto"
        url = self.target.base_url
        outcome = run_command(
            [binary, "-h", url, "-nointeractive", "-Format", "json", "-output", "-"],
            timeout=min(self.config.timeout, 600),
        )
        result.command = outcome.command
        result.raw_output = truncate(outcome.stdout or outcome.stderr, 6000)

        items = self._parse(outcome.stdout)
        if not items and outcome.returncode != 0:
            # retry without JSON in case the installed Nikto lacks that plugin
            outcome = run_command(
                [binary, "-h", url, "-nointeractive"], timeout=min(self.config.timeout, 600)
            )
            result.command = outcome.command
            items = self._parse_text(outcome.stdout)

        result.metadata["item_count"] = len(items)
        findings: List[Finding] = []
        for item in items:
            sev = self._severity(item)
            findings.append(
                self.finding(
                    title=item.get("msg", "Nikto finding")[:160],
                    severity=sev,
                    category="web-vulnerability",
                    description=item.get("msg", ""),
                    evidence=f"{item.get('method','GET')} {item.get('url','')} (id {item.get('id','')})",
                    remediation="Review the Nikto reference and harden the affected component.",
                    references=[item["references"]] if item.get("references") else [],
                )
            )
        if not findings:
            findings.append(
                self.finding(
                    title="Nikto completed without reported issues",
                    severity=Severity.INFO,
                    category="web-vulnerability",
                    description=f"Nikto scanned {url} and reported no findings.",
                )
            )
        return findings

    @staticmethod
    def _parse(output: str) -> List[Dict[str, str]]:
        items: List[Dict[str, str]] = []
        text = (output or "").strip()
        if not text:
            return items
        start = text.find("[")
        if start < 0:
            return items
        try:
            data = json.loads(text[start:])
        except json.JSONDecodeError:
            return items
        if isinstance(data, dict):
            data = [data]
        for record in data if isinstance(data, list) else []:
            if not isinstance(record, dict):
                continue
            for vuln in record.get("vulnerabilities", []) or []:
                items.append(
                    {
                        "id": str(vuln.get("id", "")),
                        "msg": vuln.get("msg", "") or vuln.get("message", ""),
                        "url": vuln.get("url", "") or vuln.get("uri", ""),
                        "method": vuln.get("method", "GET"),
                        "references": vuln.get("references", "") or vuln.get("OSVDB", ""),
                    }
                )
        return items

    @staticmethod
    def _parse_text(output: str) -> List[Dict[str, str]]:
        items: List[Dict[str, str]] = []
        for line in (output or "").splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue
            body = line.lstrip("+").strip()
            if not body or body.lower().startswith(("target", "start time", "end time", "server")):
                continue
            items.append({"msg": body, "url": "", "method": "GET", "id": "", "references": ""})
        return items

    @staticmethod
    def _severity(item: Dict[str, str]) -> Severity:
        text = (item.get("msg", "") + " " + item.get("references", "")).lower()
        if any(k in text for k in ("rce", "remote code", "sql injection", "shell", "default password")):
            return Severity.CRITICAL
        if any(k in text for k in ("xss", "cross site", "traversal", "file upload", "injection", "disclosure")):
            return Severity.HIGH
        if any(k in text for k in ("outdated", "missing", "header", "directory", "listing", "cookie")):
            return Severity.MEDIUM
        return Severity.LOW


@register
class NucleiScanner(BaseScanner):
    name = "nuclei"
    description = "Template-based vulnerability detection with Nuclei"
    category = "vulnerability"
    requires = ["nuclei"]

    def scan(self, result: ScanResult) -> List[Finding]:
        binary = self.ctx.tools.path_of("nuclei") or "nuclei"
        url = self.target.base_url
        args = [binary, "-u", url, "-jsonl", "-silent", "-no-color", "-severity", "critical,high,medium,low"]
        if self.config.aggressive:
            args += ["-stats"]
        outcome = run_command(args, timeout=min(self.config.timeout, 900))
        result.command = outcome.command
        result.raw_output = truncate(outcome.stdout or outcome.stderr, 6000)

        items = self._parse(outcome.stdout)
        result.metadata["template_hits"] = len(items)
        findings: List[Finding] = []
        for item in items:
            info = item.get("info", {}) or {}
            severity = Severity.from_text(info.get("severity", "unknown"))
            name = info.get("name") or item.get("template-id") or "Nuclei finding"
            classification = info.get("classification", {}) or {}
            cve = classification.get("cve-id") or []
            cwe = classification.get("cwe-id") or []
            if isinstance(cve, str):
                cve = [cve]
            if isinstance(cwe, str):
                cwe = [cwe]
            cvss = classification.get("cvss-score")
            findings.append(
                self.finding(
                    title=name[:180],
                    severity=severity,
                    category="vulnerability",
                    target=item.get("matched-at") or item.get("host") or url,
                    description=info.get("description", "") or f"Nuclei template {item.get('template-id','')} matched.",
                    evidence=(item.get("matched-at", "") + "\n" + (item.get("extracted-results") or ""))[:1500],
                    remediation=info.get("remediation", "") or "Follow the template reference to remediate.",
                    references=info.get("reference") or [],
                    cve=[str(c).upper() for c in cve],
                    cwe=[str(c).upper() for c in cwe],
                    cvss=float(cvss) if isinstance(cvss, (int, float)) else None,
                )
            )
        if not findings:
            findings.append(
                self.finding(
                    title="Nuclei found no matching vulnerabilities",
                    severity=Severity.INFO,
                    category="vulnerability",
                    description=f"Nuclei ran its template set against {url} with no matches.",
                )
            )
        return findings

    @staticmethod
    def _parse(output: str) -> List[Dict]:
        items: List[Dict] = []
        for line in (output or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return items


@register
class WhatWebScanner(BaseScanner):
    name = "whatweb"
    description = "Web technology fingerprinting with WhatWeb"
    category = "web"
    requires = ["whatweb"]

    def scan(self, result: ScanResult) -> List[Finding]:
        binary = self.ctx.tools.path_of("whatweb") or "whatweb"
        url = self.target.base_url
        outcome = run_command(
            [binary, "--log-json=-", "--quiet", "--no-errors", url],
            timeout=min(self.config.timeout, 240),
        )
        result.command = outcome.command
        result.raw_output = truncate(outcome.stdout, 4000)

        plugins: List[str] = []
        for line in (outcome.stdout or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            for name in (record.get("plugins") or {}):
                if name not in plugins:
                    plugins.append(name)

        result.metadata["technologies"] = plugins
        self.ctx.remember("technologies", plugins)
        if not plugins:
            return [
                self.finding(
                    title="WhatWeb could not fingerprint technologies",
                    severity=Severity.INFO,
                    category="technology",
                    description=f"No technology plugins matched for {url}.",
                )
            ]
        findings = [
            self.finding(
                title=f"Technology stack fingerprint ({len(plugins)} components)",
                severity=Severity.INFO,
                category="technology",
                description="WhatWeb identified the following technologies.",
                evidence="\n".join(plugins[:80]),
            )
        ]
        risky = [p for p in plugins if re.search(r"(jquery|wordpress|drupal|joomla|php|apache|nginx|iis|tomcat)", p, re.I)]
        if risky:
            findings.append(
                self.finding(
                    title="Fingerprinted components may require version review",
                    severity=Severity.LOW,
                    category="technology",
                    description="Detected components should be checked against current security advisories.",
                    evidence=", ".join(risky[:30]),
                    remediation="Track component versions and subscribe to vendor security advisories.",
                )
            )
        return findings


@register
class Wafw00fScanner(BaseScanner):
    name = "wafw00f"
    description = "Web application firewall detection with Wafw00f"
    category = "web"
    requires = ["wafw00f"]

    def scan(self, result: ScanResult) -> List[Finding]:
        binary = self.ctx.tools.path_of("wafw00f") or "wafw00f"
        url = self.target.base_url
        outcome = run_command([binary, url, "-f", "json", "-o", "-"], timeout=min(self.config.timeout, 240))
        if not outcome.stdout.strip().startswith("["):
            outcome = run_command([binary, url], timeout=min(self.config.timeout, 240))
        result.command = outcome.command
        result.raw_output = truncate(outcome.stdout, 3000)

        detected: List[str] = []
        try:
            data = json.loads(outcome.stdout)
            for record in data if isinstance(data, list) else [data]:
                name = record.get("firewall") or record.get("detected") or ""
                if name and name.lower() not in ("none", "false"):
                    detected.append(str(name))
        except (json.JSONDecodeError, AttributeError):
            for line in outcome.stdout.splitlines():
                match = re.search(r"is behind (.+?) WAF", line, re.I)
                if match:
                    detected.append(match.group(1).strip())

        detected = sorted(set(detected))
        result.metadata["waf"] = detected
        if detected:
            return [
                self.finding(
                    title=f"Web application firewall detected: {', '.join(detected)}",
                    severity=Severity.INFO,
                    category="waf",
                    description="A WAF is protecting the target, which may mask or block some tests.",
                    evidence="\n".join(detected),
                )
            ]
        return [
            self.finding(
                title="No web application firewall detected",
                severity=Severity.LOW,
                category="waf",
                description="Wafw00f did not identify a WAF in front of the target.",
                remediation="Consider deploying a WAF for defence in depth.",
            )
        ]


SENSITIVE_PATHS = {
    "/.git/HEAD": (Severity.HIGH, "Exposed Git repository metadata"),
    "/.env": (Severity.CRITICAL, "Exposed .env file may contain secrets"),
    "/.svn/entries": (Severity.HIGH, "Exposed Subversion metadata"),
    "/backup.zip": (Severity.HIGH, "Exposed backup archive"),
    "/backup.sql": (Severity.CRITICAL, "Exposed database dump"),
    "/phpinfo.php": (Severity.HIGH, "phpinfo() disclosure"),
    "/server-status": (Severity.MEDIUM, "Apache server-status exposed"),
    "/actuator/env": (Severity.CRITICAL, "Spring Boot Actuator environment exposed"),
    "/actuator/health": (Severity.LOW, "Spring Boot Actuator health endpoint exposed"),
    "/swagger-ui.html": (Severity.LOW, "Swagger UI publicly reachable"),
    "/admin": (Severity.LOW, "Administrative interface reachable"),
    "/wp-login.php": (Severity.LOW, "WordPress login reachable"),
    "/.well-known/security.txt": (Severity.INFO, "security.txt present"),
    "/robots.txt": (Severity.INFO, "robots.txt present"),
    "/crossdomain.xml": (Severity.MEDIUM, "crossdomain.xml may permit broad Flash access"),
}


@register
class SensitivePathScanner(BaseScanner):
    name = "sensitive_paths"
    description = "Built-in probe for commonly exposed sensitive files and endpoints"
    category = "web"

    def scan(self, result: ScanResult) -> List[Finding]:
        base = self.target.base_url.rstrip("/")

        def probe(item):
            path, (sev, label) = item
            url = base + path
            status, body = self._probe(url)
            if status is None:
                return None
            return path, sev, label, status, body

        hits = []
        workers = max(4, min(self.config.concurrency * 2, 16))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for outcome in pool.map(probe, SENSITIVE_PATHS.items()):
                if outcome:
                    hits.append(outcome)

        result.metadata["probed"] = len(SENSITIVE_PATHS)
        result.metadata["hits"] = [h[0] for h in hits]
        findings: List[Finding] = []
        for path, sev, label, status, body in hits:
            if status in (401, 403):
                findings.append(
                    self.finding(
                        title=f"Protected resource discovered: {path}",
                        severity=Severity.INFO,
                        category="discovery",
                        target=base + path,
                        description=f"{label} exists but returned HTTP {status}.",
                        evidence=(body or "")[:400],
                    )
                )
                continue
            if status >= 500:
                continue
            findings.append(
                self.finding(
                    title=f"Exposed sensitive path: {path}",
                    severity=sev,
                    category="exposure",
                    target=base + path,
                    description=f"{label} (HTTP {status}).",
                    evidence=(body or "")[:600],
                    remediation=f"Remove or restrict access to {path} and block it at the edge.",
                )
            )
        if not findings:
            findings.append(
                self.finding(
                    title="No sensitive paths exposed",
                    severity=Severity.INFO,
                    category="exposure",
                    description=f"Probed {len(SENSITIVE_PATHS)} common sensitive paths with no exposure.",
                )
            )
        return findings

    def _probe(self, url: str):
        request = urllib.request.Request(
            url, headers={"User-Agent": self.config.user_agent}, method="GET"
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as resp:
                return resp.status, resp.read(4096).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403, 404):
                try:
                    body = exc.read(1024).decode("utf-8", "replace")
                except Exception:
                    body = ""
                return exc.code, body
            return None
        except (urllib.error.URLError, OSError, ValueError):
            return None


__all__ = [
    "NiktoScanner",
    "NucleiScanner",
    "WhatWebScanner",
    "Wafw00fScanner",
    "SensitivePathScanner",
    "SENSITIVE_PATHS",
]
