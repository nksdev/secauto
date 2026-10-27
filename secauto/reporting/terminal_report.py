from __future__ import annotations

from ..version import AUTHOR, AUTHOR_INITIALS, PRODUCT_NAME, __version__


PALETTE = {
    "critical": "\033[1;97;41m",
    "high": "\033[1;91m",
    "medium": "\033[1;93m",
    "low": "\033[1;94m",
    "info": "\033[1;90m",
    "unknown": "\033[1;37m",
}
RESET = "\033[0m"


def format_report(report, color: bool = True) -> str:
    """Render a human-readable terminal report."""
    def paint(text, key):
        if not color:
            return text
        return PALETTE.get(key, "") + text + RESET

    out = []
    w = out.append
    w(paint("=" * 78, "info"))
    w(paint(" %s v%s - SECURITY ASSESSMENT REPORT" % (PRODUCT_NAME, __version__), "high"))
    w(paint(" built by %s (%s)" % (AUTHOR, AUTHOR_INITIALS), "info"))
    w(paint("=" * 78, "info"))
    t = report.target
    if t:
        w("Target    : %s" % t.base_url)
        w("Hostname  : %s" % (t.hostname or "-"))
        w("IP        : %s" % (t.ip or "-"))
    w("Scan ID   : %s" % report.scan_id)
    w("Duration  : %.1fs" % report.duration)
    w("Findings  : %d" % len(report.findings))
    risk = report.risk_score
    band = "critical" if risk >= 80 else "high" if risk >= 55 else "medium" if risk >= 30 else "low"
    w("Risk      : %s" % paint("%s/100  %s" % (risk, report.posture), band))
    w("")
    counts = report.severity_counts()
    w(paint("SEVERITY DISTRIBUTION", "info"))
    for key in ("critical", "high", "medium", "low", "info"):
        count = counts.get(key, 0)
        if not count:
            continue
        bar = "#" * min(40, count)
        w("  %s %4d %s" % (paint("%-8s" % key.upper(), key), count, bar))
    w("")
    w(paint("SCANNER COVERAGE", "info"))
    for res in report.results:
        note = (res.error or "")[:50]
        w("  %-18s %-10s %3d findings  %5.1fs  %s" % (res.scanner, res.status.value, res.finding_count, res.duration, note))
    w("")
    findings = sorted(report.findings, key=lambda f: (-f.severity.rank, f.category, f.title))
    if not findings:
        w("No findings were produced.")
    else:
        w(paint("FINDINGS", "info"))
        for index, f in enumerate(findings, start=1):
            w("")
            w("  %d. %s %s" % (index, paint("[%s]" % f.severity.value.upper(), f.severity.value), f.title))
            w("     Category : %s" % f.category)
            w("     Target   : %s" % f.target)
            w("     Tool     : %s" % (f.source_tool or "built-in"))
            if f.cve:
                w("     CVE      : %s" % ", ".join(f.cve))
            if f.cvss is not None:
                w("     CVSS     : %s" % f.cvss)
            if f.description:
                w("     Details  : %s" % f.description[:400])
            if f.remediation:
                w("     Fix      : %s" % f.remediation[:300])
    w("")
    w(paint("=" * 78, "info"))
    return "\n".join(out)


__all__ = ["format_report", "PALETTE"]
