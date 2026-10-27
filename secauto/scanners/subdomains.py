"""Subdomain enumeration scanners.

Uses subfinder / amass when installed, and always falls back to a built-in
DNS bruteforce over a compact high-signal wordlist plus TLS SAN harvesting.
"""

from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Set

from ..models import Finding, ScanResult, Severity
from ..utils import resolve_host, run_command, truncate
from .base import BaseScanner, register


DEFAULT_WORDLIST = [
    "www", "api", "app", "admin", "portal", "mail", "webmail", "smtp", "imap", "pop",
    "vpn", "remote", "gateway", "gw", "ns1", "ns2", "dns", "dev", "develop", "staging",
    "stage", "test", "testing", "qa", "uat", "prod", "production", "demo", "sandbox",
    "beta", "alpha", "internal", "intranet", "extranet", "corp", "office", "owa",
    "autodiscover", "exchange", "ftp", "sftp", "files", "file", "download", "uploads",
    "cdn", "static", "assets", "img", "images", "media", "video", "stream", "live",
    "blog", "news", "shop", "store", "cart", "checkout", "pay", "payments", "billing",
    "support", "help", "helpdesk", "status", "monitor", "grafana", "kibana", "prometheus",
    "jenkins", "ci", "cd", "git", "gitlab", "github", "bitbucket", "repo", "registry",
    "docker", "k8s", "kube", "rancher", "consul", "vault", "auth", "sso", "login",
    "idp", "oauth", "ldap", "ad", "dc", "db", "database", "sql", "mysql", "postgres",
    "redis", "mongo", "elastic", "search", "es", "log", "logs", "sentry", "jira",
    "confluence", "wiki", "docs", "doc", "api-dev", "api-staging", "api-test", "m",
    "mobile", "wap", "partner", "partners", "affiliate", "crm", "erp", "hr", "careers",
    "jobs", "newsletter", "email", "tracking", "analytics", "stats", "metrics", "proxy",
    "lb", "loadbalancer", "edge", "origin", "cache", "backup", "bak", "old", "legacy",
]


@register
class SubfinderScanner(BaseScanner):
    name = "subfinder"
    description = "Passive subdomain enumeration with Subfinder"
    category = "subdomain"
    requires = ["subfinder"]

    def scan(self, result: ScanResult) -> List[Finding]:
        if self.target.is_ip or not self.target.root_domain:
            result.metadata["skipped"] = "subdomain enumeration requires a domain"
            return []
        binary = self.ctx.tools.path_of("subfinder") or "subfinder"
        outcome = run_command(
            [binary, "-d", self.target.root_domain, "-silent", "-timeout", "5"],
            timeout=min(self.config.timeout, 240),
        )
        result.command = outcome.command
        result.raw_output = truncate(outcome.stdout, 4000)
        hosts = self._parse(outcome.stdout)
        result.metadata["subdomains"] = hosts
        self.ctx.remember("subdomains", sorted(set(self.ctx.recall("subdomains", [])) | set(hosts)))

        findings: List[Finding] = []
        if not hosts:
            return findings
        findings.append(
            self.finding(
                title=f"Subfinder discovered {len(hosts)} subdomain(s)",
                severity=Severity.INFO,
                category="subdomain",
                description="Passive sources revealed additional attack surface.",
                evidence="\n".join(hosts[:100]),
            )
        )
        for host in hosts:
            label = host.split(".")[0].lower()
            if any(k in label for k in ("dev", "test", "staging", "uat", "qa", "admin", "jenkins", "git")):
                findings.append(
                    self.finding(
                        title=f"Sensitive-looking subdomain exposed: {host}",
                        severity=Severity.MEDIUM,
                        category="subdomain",
                        target=host,
                        description=(
                            "A non-production or administrative hostname is publicly resolvable; "
                            "such hosts often lack production hardening."
                        ),
                        remediation="Restrict access to non-production/admin hosts with VPN or IP allow-lists.",
                    )
                )
        return findings

    @staticmethod
    def _parse(output: str) -> List[str]:
        hosts: Set[str] = set()
        for line in (output or "").splitlines():
            line = line.strip()
            if not line or " " in line:
                continue
            if re.fullmatch(r"[A-Za-z0-9._-]+\.[A-Za-z]{2,}", line):
                hosts.add(line.lower())
        return sorted(hosts)


@register
class AmassScanner(BaseScanner):
    name = "amass"
    description = "Passive attack-surface enumeration with OWASP Amass"
    category = "subdomain"
    requires = ["amass"]
    enabled_by_default = False  # slow; enable with --aggressive

    def scan(self, result: ScanResult) -> List[Finding]:
        if self.target.is_ip or not self.target.root_domain:
            return []
        binary = self.ctx.tools.path_of("amass") or "amass"
        outcome = run_command(
            [binary, "enum", "-passive", "-d", self.target.root_domain, "-timeout", "5"],
            timeout=min(self.config.timeout, 300),
        )
        result.command = outcome.command
        hosts = sorted({line.strip().lower() for line in outcome.stdout.splitlines() if " " not in line.strip() and "." in line})
        result.metadata["subdomains"] = hosts
        result.raw_output = truncate(outcome.stdout, 3000)
        if not hosts:
            return []
        self.ctx.remember("subdomains", sorted(set(self.ctx.recall("subdomains", [])) | set(hosts)))
        return [
            self.finding(
                title=f"Amass mapped {len(hosts)} asset(s)",
                severity=Severity.INFO,
                category="subdomain",
                description="Passive attack-surface mapping produced resolvable assets.",
                evidence="\n".join(hosts[:120]),
            )
        ]


@register
class DNSBruteforceScanner(BaseScanner):
    name = "dns_bruteforce"
    description = "Built-in DNS subdomain bruteforce (no external tools required)"
    category = "subdomain"

    def scan(self, result: ScanResult) -> List[Finding]:
        if self.target.is_ip or not self.target.root_domain:
            result.metadata["skipped"] = "subdomain enumeration requires a domain"
            return []
        if not self.config.subdomain_enum:
            result.metadata["skipped"] = "subdomain enumeration disabled"
            return []

        domain = self.target.root_domain
        words = self._wordlist()
        found: Dict[str, List[str]] = {}

        def probe(label: str):
            host = f"{label}.{domain}"
            addresses = resolve_host(host)
            if addresses:
                return host, addresses
            return None

        workers = max(4, min(self.config.concurrency * 4, 32))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for outcome in pool.map(probe, words):
                if outcome:
                    found[outcome[0]] = outcome[1]

        # harvest names from the certificate SANs discovered earlier
        for san in self.ctx.recall("tls_sans", []) or []:
            san = san.lstrip("*.").lower()
            if san.endswith(domain) and san not in found:
                found[san] = resolve_host(san)

        result.metadata["checked"] = len(words)
        result.metadata["found"] = found
        self.ctx.remember("subdomains", sorted(set(self.ctx.recall("subdomains", [])) | set(found)))

        findings: List[Finding] = []
        if not found:
            findings.append(
                self.finding(
                    title="No subdomains discovered by DNS bruteforce",
                    severity=Severity.INFO,
                    category="subdomain",
                    description=f"Probed {len(words)} common labels under {domain} with no resolutions.",
                )
            )
            return findings

        findings.append(
            self.finding(
                title=f"DNS bruteforce discovered {len(found)} subdomain(s)",
                severity=Severity.INFO,
                category="subdomain",
                description=f"Probed {len(words)} labels under {domain}.",
                evidence="\n".join(f"{host} -> {', '.join(ips)}" for host, ips in list(found.items())[:100]),
            )
        )

        for host, ips in found.items():
            if any(ip.startswith(("127.", "10.", "192.168.", "0.0.0.0")) for ip in ips):
                findings.append(
                    self.finding(
                        title=f"Subdomain resolves to internal/loopback address: {host}",
                        severity=Severity.MEDIUM,
                        category="subdomain",
                        target=host,
                        description=f"{host} resolves to {', '.join(ips)}, exposing internal topology via public DNS.",
                        remediation="Remove internal-only DNS records from public zones.",
                    )
                )
        return findings

    def _wordlist(self) -> List[str]:
        words = list(DEFAULT_WORDLIST)
        custom = self.config.subdomain_wordlist
        if custom:
            try:
                with open(custom, "r", encoding="utf-8", errors="replace") as handle:
                    words.extend(line.strip() for line in handle if line.strip() and not line.startswith("#"))
            except OSError:
                self.log.debug(f"could not read wordlist {custom}", scope="subdomain")
        limit = max(10, min(self.config.max_subdomains, 5000))
        seen: List[str] = []
        for word in words:
            if word not in seen:
                seen.append(word)
            if len(seen) >= limit:
                break
        return seen


__all__ = ["SubfinderScanner", "AmassScanner", "DNSBruteforceScanner", "DEFAULT_WORDLIST"]
