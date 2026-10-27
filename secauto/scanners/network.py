"""Network and port scanning scanners (Nmap plus a pure-Python fallback)."""

from __future__ import annotations

import re
import socket
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List

from ..models import Finding, ScanResult, Severity
from ..utils import port_open, run_command, truncate
from .base import BaseScanner, register


TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 587, 631,
    993, 995, 1080, 1433, 1521, 1723, 2049, 2375, 2376, 3000, 3306, 3389, 4443, 5000,
    5432, 5601, 5672, 5900, 5985, 5986, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8088,
    8443, 8888, 9000, 9090, 9200, 9300, 9443, 10000, 11211, 27017, 50000,
]

RISKY_PORTS = {
    21: ("FTP", Severity.MEDIUM, "Plaintext FTP service exposed."),
    23: ("Telnet", Severity.HIGH, "Telnet transmits credentials in plaintext."),
    25: ("SMTP", Severity.LOW, "SMTP exposed; verify relay restrictions."),
    111: ("rpcbind", Severity.MEDIUM, "rpcbind exposed; restrict to trusted networks."),
    135: ("MSRPC", Severity.MEDIUM, "Windows RPC endpoint mapper exposed."),
    139: ("NetBIOS", Severity.MEDIUM, "Legacy NetBIOS session service exposed."),
    161: ("SNMP", Severity.MEDIUM, "SNMP exposed; check community strings."),
    445: ("SMB", Severity.HIGH, "SMB exposed; ensure patching against EternalBlue-class bugs."),
    1433: ("MSSQL", Severity.HIGH, "Database port exposed to the internet."),
    1521: ("Oracle DB", Severity.HIGH, "Database port exposed to the internet."),
    2049: ("NFS", Severity.HIGH, "NFS exposed; verify export restrictions."),
    2375: ("Docker API", Severity.CRITICAL, "Unauthenticated Docker API may allow host takeover."),
    2376: ("Docker TLS", Severity.HIGH, "Docker API exposed; verify client certificate auth."),
    3306: ("MySQL", Severity.HIGH, "Database port exposed to the internet."),
    3389: ("RDP", Severity.HIGH, "Remote Desktop exposed; enforce NLA and MFA."),
    5432: ("PostgreSQL", Severity.HIGH, "Database port exposed to the internet."),
    5601: ("Kibana", Severity.HIGH, "Kibana exposed; often unauthenticated."),
    5900: ("VNC", Severity.HIGH, "VNC exposed; often weakly authenticated."),
    6379: ("Redis", Severity.CRITICAL, "Redis exposed; unauthenticated by default."),
    9200: ("Elasticsearch", Severity.CRITICAL, "Elasticsearch exposed; often unauthenticated."),
    11211: ("Memcached", Severity.HIGH, "Memcached exposed; amplification/abuse risk."),
    27017: ("MongoDB", Severity.CRITICAL, "MongoDB exposed; often unauthenticated."),
}


@register
class NmapScanner(BaseScanner):
    name = "nmap"
    description = "Service and version detection with Nmap"
    category = "network"
    requires = ["nmap"]

    def scan(self, result: ScanResult) -> List[Finding]:
        host = self.target.ip or self.target.hostname
        if not host:
            result.metadata["skipped"] = "no host to scan"
            return []
        binary = self.ctx.tools.path_of("nmap") or "nmap"
        ports = self._port_spec()
        args = [binary, "-sV", "-Pn", "-T4", "--version-light", "-oX", "-"]
        if ports:
            args += ["-p", ports]
        else:
            args.append("--top-ports")
            args.append("1000")
        args.append(host)

        timeout = max(120, min(self.config.timeout, 900))
        outcome = run_command(args, timeout=timeout)
        result.command = outcome.command
        result.raw_output = truncate(outcome.stdout or outcome.stderr, 6000)
        if outcome.returncode != 0 and not outcome.stdout.strip():
            raise RuntimeError(outcome.stderr[:300] or "nmap returned no output")

        services = self._parse_xml(outcome.stdout)
        result.metadata["open_ports"] = services
        result.metadata["port_count"] = len(services)
        self.ctx.remember("open_ports", services)

        findings: List[Finding] = []
        if not services:
            findings.append(
                self.finding(
                    title="No open TCP ports detected by Nmap",
                    severity=Severity.INFO,
                    category="network",
                    description=f"Nmap found no open ports on {host} within the selected profile.",
                )
            )
            return findings

        findings.append(
            self.finding(
                title=f"Nmap discovered {len(services)} open port(s)",
                severity=Severity.INFO,
                category="network",
                description=f"Service exposure inventory for {host}.",
                evidence="\n".join(
                    f"{s['port']}/{s['protocol']} {s['service']} {s.get('product','')} {s.get('version','')}".strip()
                    for s in services
                )[:3000],
            )
        )

        for service in services:
            port = service["port"]
            if port in RISKY_PORTS:
                label, sev, why = RISKY_PORTS[port]
                findings.append(
                    self.finding(
                        title=f"Risky service exposed: {label} on port {port}",
                        severity=sev,
                        category="network",
                        description=why,
                        evidence=f"{port}/tcp {service.get('service','')} {service.get('product','')} {service.get('version','')}".strip(),
                        remediation=f"Restrict access to port {port} with firewall rules or remove the service from the public internet.",
                    )
                )
            version = (service.get("version") or "").strip()
            product = (service.get("product") or "").strip()
            if version and product:
                findings.append(
                    self.finding(
                        title=f"Version disclosure: {product} {version} (port {port})",
                        severity=Severity.LOW,
                        category="information-disclosure",
                        description=f"Nmap fingerprinted {product} {version} on port {port}.",
                        evidence=f"{product} {version}",
                        remediation="Keep the service patched and suppress exact version banners.",
                        metadata={"product": product, "version": version, "port": port},
                    )
                )
        return findings

    def _port_spec(self) -> str:
        profile = (self.config.port_profile or "top1000").lower()
        if profile == "custom" and self.config.custom_ports:
            return self.config.custom_ports
        if profile == "top100":
            return ",".join(str(p) for p in TOP_PORTS)
        if profile == "full":
            return "1-65535"
        return ""

    @staticmethod
    def _parse_xml(xml_text: str) -> List[Dict[str, object]]:
        services: List[Dict[str, object]] = []
        if not xml_text or "<nmaprun" not in xml_text:
            return services
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return services
        for port in root.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service") or None
            entry: Dict[str, object] = {
                "port": int(port.get("portid", "0")),
                "protocol": port.get("protocol", "tcp"),
                "service": (service.get("name") if service is not None else "unknown") or "unknown",
            }
            if service is not None:
                for attr in ("product", "version", "extrainfo", "ostype"):
                    value = service.get(attr)
                    if value:
                        entry[attr] = value
                for script in service.findall("script"):
                    entry.setdefault("scripts", []).append(script.get("id"))
            services.append(entry)
        return services


@register
class PythonPortScanner(BaseScanner):
    """Fallback TCP connect scan when Nmap is unavailable."""

    name = "port_scan_python"
    description = "Built-in TCP connect port scan (no external tools)"
    category = "network"

    def scan(self, result: ScanResult) -> List[Finding]:
        if not self.config.port_scan:
            result.metadata["skipped"] = "port scanning disabled"
            return []
        host = self.target.ip or self.target.hostname
        if not host:
            return []
        ports = self._ports()
        open_ports: List[int] = []

        def probe(port: int) -> int | None:
            return port if port_open(host, port, timeout=1.2) else None

        workers = max(4, min(self.config.concurrency * 8, 64))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for outcome in pool.map(probe, ports):
                if outcome:
                    open_ports.append(outcome)

        open_ports.sort()
        result.metadata["open_ports"] = open_ports
        result.metadata["scanned"] = len(ports)
        self.ctx.remember("open_ports_python", open_ports)

        findings: List[Finding] = []
        if not open_ports:
            findings.append(
                self.finding(
                    title="No open TCP ports detected (connect scan)",
                    severity=Severity.INFO,
                    category="network",
                    description=f"Scanned {len(ports)} common ports on {host}.",
                )
            )
            return findings

        findings.append(
            self.finding(
                title=f"TCP connect scan found {len(open_ports)} open port(s)",
                severity=Severity.INFO,
                category="network",
                description=f"Scanned {len(ports)} common ports on {host}.",
                evidence=", ".join(str(p) for p in open_ports),
            )
        )
        for port in open_ports:
            if port in RISKY_PORTS:
                label, sev, why = RISKY_PORTS[port]
                findings.append(
                    self.finding(
                        title=f"Risky service exposed: {label} on port {port}",
                        severity=sev,
                        category="network",
                        description=why,
                        evidence=f"{host}:{port} reachable",
                        remediation=f"Restrict access to port {port} or remove the public listener.",
                    )
                )
        return findings

    def _ports(self) -> List[int]:
        profile = (self.config.port_profile or "top1000").lower()
        if profile == "custom" and self.config.custom_ports:
            ports: List[int] = []
            for chunk in self.config.custom_ports.split(","):
                chunk = chunk.strip()
                if "-" in chunk:
                    start, end = chunk.split("-", 1)
                    if start.isdigit() and end.isdigit():
                        ports.extend(range(int(start), min(int(end), int(start) + 1024) + 1))
                elif chunk.isdigit():
                    ports.append(int(chunk))
            return ports or TOP_PORTS
        if profile == "full":
            return TOP_PORTS  # keep the built-in fallback fast
        return TOP_PORTS


__all__ = ["NmapScanner", "PythonPortScanner", "TOP_PORTS", "RISKY_PORTS"]
