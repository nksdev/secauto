"""Smoke tests for SecAuto core primitives."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secauto.models import Finding, ScanReport, ScanResult, Severity
from secauto.reporting import available_formats, format_report, write_reports
from secauto.scanners import registry
from secauto.utils import parse_target


class TargetTests(unittest.TestCase):
    def test_parse_bare_host(self):
        t = parse_target("example.com")
        self.assertEqual(t.hostname, "example.com")
        self.assertEqual(t.root_domain, "example.com")
        self.assertIn(t.scheme, ("http", "https"))

    def test_parse_url_with_port(self):
        t = parse_target("https://example.com:8443/path")
        self.assertEqual(t.hostname, "example.com")
        self.assertEqual(t.port, 8443)
        self.assertEqual(t.scheme, "https")

    def test_parse_ip(self):
        t = parse_target("192.0.2.10")
        self.assertEqual(t.hostname, "192.0.2.10")


class ModelTests(unittest.TestCase):
    def test_fingerprint_is_stable(self):
        a = Finding(title="X", severity=Severity.HIGH, category="c", target="t")
        b = Finding(title="X", severity=Severity.HIGH, category="c", target="t")
        self.assertEqual(a.fingerprint, b.fingerprint)

    def test_severity_from_text(self):
        self.assertEqual(Severity.from_text("CRITICAL"), Severity.CRITICAL)
        self.assertEqual(Severity.from_text("nonsense"), Severity.UNKNOWN)

    def test_report_risk_and_posture(self):
        report = ScanReport(target=parse_target("example.com"))
        result = ScanResult(scanner="http_recon")
        result.findings.append(
            Finding(title="Exposed .env", severity=Severity.CRITICAL, category="exposure", target="example.com")
        )
        report.results.append(result)
        self.assertEqual(len(report.findings), 1)
        self.assertGreater(report.risk_score, 0)
        self.assertIn(report.posture, ("LOW RISK", "MODERATE RISK", "HIGH RISK", "CRITICAL RISK"))

    def test_report_json_roundtrip(self):
        report = ScanReport(target=parse_target("example.com"))
        self.assertIn("scan_id", report.to_dict())
        self.assertIsInstance(report.to_json(), str)


class RegistryTests(unittest.TestCase):
    def test_expected_scanners_registered(self):
        names = registry.names()
        for expected in ("dns_recon", "http_recon", "nmap", "nikto", "nuclei", "vuln_correlate"):
            self.assertIn(expected, names)

    def test_select_by_category(self):
        chosen = registry.select(include=["tls"])
        self.assertTrue(chosen)
        self.assertTrue(all(c.category == "tls" for c in chosen))

    def test_exclude_removes_scanner(self):
        chosen = registry.select(exclude=["nmap"])
        self.assertNotIn("nmap", [c.name for c in chosen])


class ReportingTests(unittest.TestCase):
    def _report(self) -> ScanReport:
        report = ScanReport(target=parse_target("https://example.com"))
        result = ScanResult(scanner="http_recon")
        result.findings.append(
            Finding(
                title="Missing HSTS header",
                severity=Severity.MEDIUM,
                category="http-headers",
                target="https://example.com",
                description="HSTS not set",
                remediation="Add Strict-Transport-Security",
            )
        )
        report.results.append(result)
        return report

    def test_all_formats_available(self):
        self.assertEqual(sorted(available_formats()), ["csv", "html", "json", "markdown"])

    def test_write_reports_creates_files(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_reports(self._report(), Path(tmp))
            self.assertEqual(len(paths), 4)
            for path in paths:
                self.assertTrue(path.exists())
                self.assertGreater(path.stat().st_size, 0)

    def test_terminal_report_contains_author(self):
        text = format_report(self._report(), color=False)
        self.assertIn("Naman Kumar Sonker", text)
        self.assertIn("NKS", text)

    def test_html_report_contains_author_initials(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_reports(self._report(), Path(tmp), formats=["html"])
            html = paths[0].read_text(encoding="utf-8")
            self.assertIn("Naman Kumar Sonker", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
