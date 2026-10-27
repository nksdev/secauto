"""Reconnaissance scanners: DNS, whois, HTTP headers, TLS certificate.

These scanners rely only on the Python standard library plus optional CLI
helpers (`dig`, `whois`, `openssl`). They always run, even when no third-party
security tool is installed, so a scan always yields useful findings.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..models import Finding, ScanResult, ScanStatus, Severity
from ..utils import resolve_host, run_command, truncate
from .base import BaseScanner, register


# ------------------------------------------------------------------ DNS recon
@register
class DNSReconScanner(BaseScanner):
    name = "dns_recon"
    description = "DNS records, mail configuration and nameserver posture"
    category = "recon"

    def scan(self, result: ScanResult) -> List[Finding]:
        findings: List[Finding] = []
        host = self.target.hostname or self.target.ip
        if not host or self.target.is_ip:
            result.metadata["skipped"] = "target is a bare IP address"
            return findings

        addresses = resolve_host(host)
        result.metadata["addresses"] = addresses
        if not addresses:
            findings.append(
                self.finding(
                    title="Target hostname does not resolve",
                    severity=Severity.HIGH,
                    category="dns",
                    description=f"No A/AAAA records could be resolved for {host}.",
                    remediation="Verify the DNS zone and A/AAAA records for the hostname.",
                    confidence="high",
                )
            )
            return findings

        findings.append(
            self.finding(
                title="DNS resolution successful",
                severity=Severity.INFO,
                category="dns",
                description=f"{host} resolves to {', '.join(addresses)}",
                evidence="\n".join(addresses),
                confidence="high",
            )
        )

        # Record inventory via dig when available
        records = self._query_dns(host)
        result.metadata["records"] = records

        ns_records = records.get("NS", [])
        if len(ns_records) == 1:
            findings.append(
                self.finding(
                    title="Single authoritative nameserver",
                    severity=Severity.LOW,
                    category="dns",
                    description=(
                        f"Only one NS record was observed for {self.target.root_domain}; "
                        "a single nameserver is a resilience risk."
                    ),
                    evidence="\n".join(ns_records),
                    remediation="Configure at least two geographically redundant nameservers.",
                )
            )

        spf = [txt for txt in records.get("TXT", []) if txt.lower().startswith("v=spf1")]
        dmarc = self._query_txt(f"_dmarc.{self.target.root_domain}")
        dmarc = [t for t in dmarc if "v=DMARC1" in t.upper()]
        result.metadata["email_posture"] = {"spf": spf, "dmarc": dmarc}

        if not spf:
            findings.append(
                self.finding(
                    title="Missing SPF record",
                    severity=Severity.MEDIUM,
                    category="dns",
                    description=(
                        f"No SPF TXT record was found for {self.target.root_domain}. "
                        "Attackers can more easily spoof email from this domain."
                    ),
                    remediation="Publish an SPF record (v=spf1 ... -all) for the domain.",
                    references=["https://www.rfc-editor.org/rfc/rfc7208"],
                )
            )
        if not dmarc:
            findings.append(
                self.finding(
                    title="Missing DMARC policy",
                    severity=Severity.MEDIUM,
                    category="dns",
                    description=(
                        f"No DMARC TXT record was found at _dmarc.{self.target.root_domain}."
                    ),
                    remediation="Publish a DMARC record with a p=quarantine or p=reject policy.",
                    references=["https://www.rfc-editor.org/rfc/rfc7489"],
                )
            )

        dnskey = records.get("DNSKEY", [])
        ds = records.get("DS", [])
        if not dnskey and not ds:
            findings.append(
                self.finding(
                    title="DNSSEC not detected",
                    severity=Severity.LOW,
                    category="dns",
                    description="No DNSKEY/DS records observed; the zone may not be signed with DNSSEC.",
                    remediation="Enable DNSSEC signing and publish DS records at the registrar.",
                )
            )
        return findings

    # ------------------------------------------------------------------ helpers
    def _dig(self, name: str, rtype: str) -> List[str]:
        if not self.ctx.tools.available("dig"):
            return []
        outcome = run_command(
            [self.ctx.tools.path_of("dig") or "dig", "+short", rtype, name], timeout=15
        )
        if outcome.returncode != 0:
            return []
        return [line.strip().strip('"') for line in outcome.stdout.splitlines() if line.strip()]

    def _query_dns(self, host: str) -> Dict[str, List[str]]:
        wanted = ["A", "AAAA", "MX", "NS", "TXT", "CAA", "DNSKEY", "DS", "SOA"]
        records: Dict[str, List[str]] = {}
        for rtype in wanted:
            values = self._dig(host, rtype)
            if values:
                records[rtype] = values
        return records

    def _query_txt(self, name: str) -> List[str]:
        return self._dig(name, "TXT")


# ----------------------------------------------------------------- whois recon
@register
class WhoisScanner(BaseScanner):
    name = "whois"
    description = "Domain registration age, registrar and expiry posture"
    category = "recon"

    def scan(self, result: ScanResult) -> List[Finding]:
        findings: List[Finding] = []
        if self.target.is_ip or not self.target.root_domain:
            result.metadata["skipped"] = "whois requires a domain target"
            return findings
        binary = self.ctx.tools.path_of("whois")
        if not binary:
            result.status = ScanStatus.SKIPPED
            return findings

        outcome = run_command([binary, self.target.root_domain], timeout=45)
        result.command = outcome.command
        result.raw_output = truncate(outcome.stdout, 4000)
        text = outcome.stdout or ""
        if not text.strip():
            return findings

        info: Dict[str, Any] = {}
        patterns = {
            "registrar": r"Registrar:\s*(.+)",
            "created": r"Creation Date:\s*(.+)",
            "expires": r"Registry Expiry Date:\s*(.+)|Expiry Date:\s*(.+)",
            "updated": r"Updated Date:\s*(.+)",
            "registrant_country": r"Registrant Country:\s*(.+)",
            "name_servers": r"Name Server:\s*(.+)",
            "status": r"Domain Status:\s*(.+)",
        }
        for key, pattern in patterns.items():
            matches = re.findall(pattern, text, flags=re.IGNORECASE)
            if not matches:
                continue
            if key == "expires":
                flat = [m for group in matches for m in (group if isinstance(group, tuple) else (group,)) if m]
                info[key] = flat[:1]
            else:
                info[key] = sorted({m.strip() for m in matches if m})[:10]

        result.metadata["whois"] = info
        if info.get("registrar"):
            findings.append(
                self.finding(
                    title="Domain registration identified",
                    severity=Severity.INFO,
                    category="whois",
                    description=f"Registrar: {info['registrar'][0]}",
                    evidence=json.dumps(info, indent=2, default=str)[:2500],
                )
            )

        created = self._parse_date(info.get("created"))
        if created:
            age_days = (datetime.now(timezone.utc) - created).days
            result.metadata["domain_age_days"] = age_days
            if age_days < 90:
                findings.append(
                    self.finding(
                        title="Recently registered domain",
                        severity=Severity.LOW,
                        category="whois",
                        description=(
                            f"The domain was registered {age_days} days ago; young domains "
                            "warrant additional scrutiny (phishing / throwaway infrastructure)."
                        ),
                        evidence=str(info.get("created")),
                    )
                )

        expires = self._parse_date(info.get("expires"))
        if expires:
            days_left = (expires - datetime.now(timezone.utc)).days
            result.metadata["domain_expiry_days"] = days_left
            if days_left < 30:
                findings.append(
                    self.finding(
                        title="Domain registration nearing expiry",
                        severity=Severity.MEDIUM,
                        category="whois",
                        description=f"The domain expires in {days_left} days.",
                        remediation="Renew the domain and enable registrar auto-renew / lock.",
                    )
                )
            elif days_left < 0:
                findings.append(
                    self.finding(
                        title="Domain registration appears expired",
                        severity=Severity.HIGH,
                        category="whois",
                        description="WHOIS reports an expiry date in the past.",
                        remediation="Renew the domain immediately and verify registrar status.",
                    )
                )
        return findings

    @staticmethod
    def _parse_date(value: Optional[List[str]]) -> Optional[datetime]:
        if not value:
            return None
        raw = value[0]
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d",
            "%d-%b-%Y",
            "%Y.%m.%d %H:%M:%S",
        ]
        cleaned = raw.split("(")[0].strip().replace("Z", "+00:00")
        for fmt in formats:
            try:
                dt = datetime.strptime(cleaned, fmt)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(cleaned)
        except ValueError:
            return None


# -------------------------------------------------------------- HTTP headers
SECURITY_HEADERS = {
    "strict-transport-security": (
        Severity.MEDIUM,
        "HTTP Strict Transport Security (HSTS) is missing.",
        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all HTTPS responses.",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "Content-Security-Policy is missing, weakening XSS mitigation.",
        "Deploy a restrictive CSP; start in report-only mode before enforcing.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "X-Content-Type-Options is missing (MIME sniffing).",
        "Send 'X-Content-Type-Options: nosniff'.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "X-Frame-Options / frame-ancestors is missing (clickjacking).",
        "Send 'X-Frame-Options: DENY' or use CSP frame-ancestors.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Referrer-Policy is missing.",
        "Send 'Referrer-Policy: strict-origin-when-cross-origin'.",
    ),
    "permissions-policy": (
        Severity.LOW,
        "Permissions-Policy is missing.",
        "Restrict powerful browser features with a Permissions-Policy header.",
    ),
}

LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator", "via"]


@register
class HTTPReconScanner(BaseScanner):
    name = "http_recon"
    description = "HTTP response headers, security header posture and information leaks"
    category = "http"

    def scan(self, result: ScanResult) -> List[Finding]:
        findings: List[Finding] = []
        url = self.target.base_url
        response = self._fetch(url)
        if response is None and url.startswith("https://"):
            fallback = "http://" + url[len("https://"):]
            response = self._fetch(fallback)
            if response is not None:
                findings.append(
                    self.finding(
                        title="HTTPS unavailable — plaintext only",
                        severity=Severity.HIGH,
                        category="http",
                        description=f"{url} did not respond over HTTPS but {fallback} did.",
                        remediation="Enable TLS with a valid certificate and redirect HTTP to HTTPS.",
                    )
                )
        if response is None:
            findings.append(
                self.finding(
                    title="Target did not return an HTTP response",
                    severity=Severity.MEDIUM,
                    category="http",
                    description=f"No HTTP response received from {url}.",
                )
            )
            return findings

        status, headers, body, final_url = response
        lower = {k.lower(): v for k, v in headers.items()}
        result.metadata["status"] = status
        result.metadata["final_url"] = final_url
        result.metadata["headers"] = lower
        result.metadata["body_length"] = len(body or "")

        findings.append(
            self.finding(
                title="HTTP endpoint reachable",
                severity=Severity.INFO,
                category="http",
                description=f"{final_url} responded with HTTP {status}.",
                evidence="\n".join(f"{k}: {v}" for k, v in list(lower.items())[:20]),
            )
        )

        for header, (sev, desc, fix) in SECURITY_HEADERS.items():
            if header not in lower:
                findings.append(
                    self.finding(
                        title=f"Missing security header: {header}",
                        severity=sev,
                        category="http-headers",
                        description=desc,
                        remediation=fix,
                    )
                )

        csp = lower.get("content-security-policy", "")
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            findings.append(
                self.finding(
                    title="Weak Content-Security-Policy directives",
                    severity=Severity.MEDIUM,
                    category="http-headers",
                    description="CSP permits 'unsafe-inline' and/or 'unsafe-eval', reducing XSS protection.",
                    evidence=csp[:500],
                    remediation="Remove unsafe-inline/unsafe-eval and use nonces or hashes.",
                )
            )

        for header in LEAKY_HEADERS:
            if header in lower:
                findings.append(
                    self.finding(
                        title=f"Technology disclosure via {header} header",
                        severity=Severity.LOW,
                        category="information-disclosure",
                        description=(
                            f"The '{header}' header exposes server technology details: {lower[header]}"
                        ),
                        evidence=f"{header}: {lower[header]}",
                        remediation="Suppress or genericise version-revealing response headers.",
                    )
                )

        cookies = headers.get("Set-Cookie", "")
        cookie_list = cookies if isinstance(cookies, list) else [cookies] if cookies else []
        for cookie in cookie_list:
            name = cookie.split("=", 1)[0].strip()
            flags = cookie.lower()
            missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in flags]
            if missing:
                findings.append(
                    self.finding(
                        title=f"Cookie missing security attributes: {name}",
                        severity=Severity.MEDIUM if "httponly" in missing else Severity.LOW,
                        category="http-headers",
                        description=(
                            f"Cookie '{name}' lacks: {', '.join(missing)}."
                        ),
                        evidence=cookie[:300],
                        remediation="Set Secure, HttpOnly and SameSite on all session cookies.",
                    )
                )

        # simple mixed-content / info probes on body
        body_lower = (body or "").lower()
        if url.startswith("https://") and "http://" in body_lower:
            findings.append(
                self.finding(
                    title="Mixed content references in HTML",
                    severity=Severity.LOW,
                    category="http",
                    description="The HTTPS page references insecure http:// resources.",
                    remediation="Serve all sub-resources over HTTPS.",
                )
            )
        for marker, title, sev in (
            ("sql syntax", "Possible SQL error disclosure", Severity.HIGH),
            ("stack trace", "Stack trace disclosure", Severity.MEDIUM),
            ("phpinfo()", "phpinfo() page exposed", Severity.HIGH),
            ("index of /", "Directory listing enabled", Severity.MEDIUM),
        ):
            if marker in body_lower:
                findings.append(
                    self.finding(
                        title=title,
                        severity=sev,
                        category="information-disclosure",
                        description=f"Response body contains marker: '{marker}'.",
                        evidence=self._snippet(body, marker),
                        remediation="Disable verbose errors and directory indexing in production.",
                    )
                )
        return findings

    def _fetch(self, url: str):
        request = urllib.request.Request(
            url,
            headers={"User-Agent": self.config.user_agent, "Accept": "*/*"},
            method="GET",
        )
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(request, timeout=20, context=context) as resp:
                headers = {k: v for k, v in resp.headers.items()}
                raw = resp.read(300_000)
                try:
                    body = raw.decode("utf-8", "replace")
                except Exception:
                    body = ""
                return resp.status, headers, body, resp.geturl()
        except urllib.error.HTTPError as exc:
            headers = {k: v for k, v in exc.headers.items()} if exc.headers else {}
            try:
                body = exc.read(100_000).decode("utf-8", "replace")
            except Exception:
                body = ""
            return exc.code, headers, body, url
        except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError):
            return None

    @staticmethod
    def _snippet(body: str, marker: str, radius: int = 90) -> str:
        idx = body.lower().find(marker)
        if idx < 0:
            return ""
        start = max(0, idx - radius)
        return body[start : idx + radius].replace("\n", " ")[:220]


# ------------------------------------------------------------------- TLS scan
@register
class TLSScanner(BaseScanner):
    name = "tls_certificate"
    description = "TLS certificate validity, expiry and protocol support"
    category = "tls"

    def scan(self, result: ScanResult) -> List[Finding]:
        findings: List[Finding] = []
        host = self.target.hostname or self.target.ip
        port = self.target.port or (443 if self.target.scheme == "https" else 80)
        if not host:
            result.metadata["skipped"] = "no host"
            return findings

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=12) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    cipher = tls.cipher()
                    version = tls.version()
        except (ssl.SSLError, socket.timeout, OSError) as exc:
            findings.append(
                self.finding(
                    title="TLS handshake failed",
                    severity=Severity.HIGH if self.target.scheme == "https" else Severity.INFO,
                    category="tls",
                    description=f"Could not establish a TLS session with {host}:{port}: {exc}",
                    remediation="Verify the certificate chain and TLS listener configuration.",
                )
            )
            return findings

        if not cert:
            findings.append(
                self.finding(
                    title="No TLS certificate presented",
                    severity=Severity.HIGH,
                    category="tls",
                    description=f"{host}:{port} did not present a certificate.",
                )
            )
            return findings

        result.metadata["tls_version"] = version
        result.metadata["cipher"] = cipher[0] if cipher else None

        # certificate verification with default trust store
        verification = self._verify(host, port)
        result.metadata["verification"] = verification
        if verification is not True:
            findings.append(
                self.finding(
                    title="TLS certificate chain is not trusted",
                    severity=Severity.HIGH,
                    category="tls",
                    description=verification if isinstance(verification, str) else "Certificate verification failed.",
                    remediation="Install a valid, publicly trusted certificate matching the hostname.",
                )
            )

        if version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
            findings.append(
                self.finding(
                    title=f"Legacy TLS protocol negotiated: {version}",
                    severity=Severity.HIGH,
                    category="tls",
                    description=f"The server negotiated deprecated protocol {version}.",
                    remediation="Disable TLS 1.0/1.1 and SSL; require TLS 1.2+.",
                )
            )

        not_after = cert.get("notAfter")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                result.metadata["certificate_expiry_days"] = days_left
                if days_left < 0:
                    findings.append(
                        self.finding(
                            title="TLS certificate has expired",
                            severity=Severity.CRITICAL,
                            category="tls",
                            description=f"Certificate expired on {not_after}.",
                            remediation="Renew and redeploy the certificate immediately.",
                        )
                    )
                elif days_left < 30:
                    findings.append(
                        self.finding(
                            title="TLS certificate expiring soon",
                            severity=Severity.MEDIUM,
                            category="tls",
                            description=f"Certificate expires in {days_left} days ({not_after}).",
                            remediation="Automate certificate renewal and deployment.",
                        )
                    )
            except ValueError:
                pass

        sans = [value for rtype, value in cert.get("subjectAltName", []) if rtype == "DNS"]
        result.metadata["subject_alt_names"] = sans
        if sans:
            findings.append(
                self.finding(
                    title="TLS certificate SAN inventory",
                    severity=Severity.INFO,
                    category="tls",
                    description=f"Certificate covers {len(sans)} DNS names.",
                    evidence="\n".join(sans[:40]),
                )
            )
        if cipher and cipher[2] and cipher[2] < 128:
            findings.append(
                self.finding(
                    title="Weak cipher strength negotiated",
                    severity=Severity.MEDIUM,
                    category="tls",
                    description=f"Cipher {cipher[0]} uses {cipher[2]}-bit keys.",
                    remediation="Prefer AEAD ciphers with 128+ bit strength (AES-GCM/ChaCha20).",
                )
            )
        return findings

    @staticmethod
    def _verify(host: str, port: int):
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=12) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    return True
        except ssl.SSLCertVerificationError as exc:
            return f"Certificate verification error: {exc.verify_message or exc}"
        except (ssl.SSLError, socket.timeout, OSError) as exc:
            return f"TLS verification failed: {exc}"


__all__ = ["DNSReconScanner", "WhoisScanner", "HTTPReconScanner", "TLSScanner"]
