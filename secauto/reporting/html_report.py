from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from ..version import AUTHOR, AUTHOR_INITIALS, ORGANIZATION, PRODUCT_NAME, __version__
from .base import BaseReporter


SEVERITY_COLOURS = {
    "critical": "#b3121f",
    "high": "#e05a00",
    "medium": "#c9a200",
    "low": "#2f7ed8",
    "info": "#5f6b7a",
    "unknown": "#6c757d",
}


def _bar(value, total, colour):
    pct = 0 if not total else round(100 * value / total)
    return (
        "<div class=\"bar\"><span style=\"width:%d%%;background:%s\"></span></div>"
        % (pct, colour)
    )


class HtmlReporter(BaseReporter):
    name = "html"
    extension = "html"

    def render(self) -> str:
        r = self.report
        t = r.target
        counts = r.severity_counts()
        total = len(r.findings)
        findings = self.ordered_findings()
        parts = []
        w = parts.append
        w("<!DOCTYPE html>")
        w("<html lang=\"en\"><head><meta charset=\"utf-8\">")
        w("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
        w("<title>%s Security Report - %s</title>" % (PRODUCT_NAME, escape(t.base_url if t else "")))
        w("<style>")
        w("*{box-sizing:border-box}")
        w("body{margin:0;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f4f6f9;color:#1c2530;line-height:1.55}")
        w(".wrap{max-width:1120px;margin:0 auto;padding:32px 20px 80px}")
        w("header{background:linear-gradient(135deg,#0b1b2b,#16324d);color:#fff;padding:36px 20px}")
        w("header .wrap{padding:0 20px}")
        w("h1{margin:0 0 6px;font-size:26px;letter-spacing:.4px}")
        w(".sub{opacity:.78;font-size:13px}")
        w(".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin:24px 0}")
        w(".card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:16px}")
        w(".card .k{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:#6b7a8c}")
        w(".card .v{font-size:22px;font-weight:700;margin-top:4px}")
        w("section{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:22px;margin-bottom:22px}")
        w("h2{font-size:17px;margin:0 0 14px;padding-bottom:8px;border-bottom:1px solid #eef2f6}")
        w("table{width:100%;border-collapse:collapse;font-size:13px}")
        w("th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #eef2f6;vertical-align:top}")
        w("th{font-size:11px;text-transform:uppercase;letter-spacing:.7px;color:#6b7a8c;background:#fafbfc}")
        w(".bar{background:#eef2f6;border-radius:4px;height:8px;overflow:hidden;min-width:110px}")
        w(".bar span{display:block;height:100%%}")
        w(".pill{display:inline-block;padding:2px 9px;border-radius:99px;font-size:11px;font-weight:700;color:#fff;letter-spacing:.5px}")
        w(".finding{border:1px solid #e2e8f0;border-left-width:5px;border-radius:8px;padding:14px 16px;margin-bottom:12px;background:#fff}")
        w(".finding h3{margin:0 0 8px;font-size:15px}")
        w(".meta{font-size:12px;color:#5d6b7c;margin-bottom:8px}")
        w("code,pre{font-family:SFMono-Regular,Consolas,Menlo,monospace;font-size:12px}")
        w("pre{background:#f7f9fb;border:1px solid #e8edf3;border-radius:6px;padding:10px;overflow:auto;max-height:260px;white-space:pre-wrap}")
        w("footer{text-align:center;font-size:12px;color:#7b8794;padding:20px}")
        w("</style></head><body>")
        w("<header><div class=\"wrap\">")
        w("<h1>%s Security Assessment Report</h1>" % PRODUCT_NAME)
        w("<div class=\"sub\">%s &middot; Built by %s (%s) &middot; Scan %s</div>"
          % (escape(ORGANIZATION), escape(AUTHOR), AUTHOR_INITIALS, escape(r.scan_id)))
        w("</div></header>")
        w("<div class=\"wrap\">")
        w("<div class=\"cards\">")
        w("<div class=\"card\"><div class=\"k\">Risk score</div><div class=\"v\">%s/100</div><div class=\"sub\">%s</div></div>"
          % (r.risk_score, escape(r.posture)))
        w("<div class=\"card\"><div class=\"k\">Findings</div><div class=\"v\">%d</div></div>" % total)
        w("<div class=\"card\"><div class=\"k\">Duration</div><div class=\"v\">%.1fs</div></div>" % r.duration)
        w("<div class=\"card\"><div class=\"k\">Scanners run</div><div class=\"v\">%d</div></div>" % len(r.results))
        w("</div>")
        w("<section><h2>Target</h2><table>")
        if t:
            for label, value in (
                ("Input", t.input),
                ("Base URL", t.base_url),
                ("Hostname", t.hostname or "-"),
                ("IP", t.ip or "-"),
                ("Root domain", t.root_domain or "-"),
            ):
                w("<tr><th style=\"width:180px\">%s</th><td><code>%s</code></td></tr>"
                  % (label, escape(str(value))))
        w("</table></section>")
        w("<section><h2>Severity distribution</h2><table>")
        for sev in self.ordered_severities():
            count = counts.get(sev.value, 0)
            colour = SEVERITY_COLOURS.get(sev.value, "#6c757d")
            w("<tr><th style=\"width:130px\">%s</th><td style=\"width:120px\">%d</td>"
              "<td>%s</td></tr>" % (sev.value.capitalize(), count, _bar(count, total, colour)))
        w("</table></section>")
        w("<section><h2>Scanner coverage</h2><table>")
        w("<tr><th>Scanner</th><th>Status</th><th>Findings</th><th>Duration</th><th>Note</th></tr>")
        for res in r.results:
            w("<tr><td><code>%s</code></td><td>%s</td><td>%d</td><td>%.1fs</td><td>%s</td></tr>"
              % (escape(res.scanner), res.status.value, res.finding_count,
                 res.duration, escape((res.error or "")[:120])))
        w("</table></section>")
        w("<section><h2>Findings (%d)</h2>" % total)
        if not findings:
            w("<p>No findings were produced.</p>")
        for f in findings:
            colour = SEVERITY_COLOURS.get(f.severity.value, "#6c757d")
            w("<div class=\"finding\" style=\"border-left-color:%s\">" % colour)
            w("<h3><span class=\"pill\" style=\"background:%s\">%s</span> %s</h3>"
              % (colour, f.severity.value.upper(), escape(f.title)))
            w("<div class=\"meta\">Category: %s &middot; Target: <code>%s</code> &middot; Tool: %s &middot; Confidence: %s</div>"
              % (escape(f.category), escape(f.target),
                 escape(f.source_tool or "built-in"), escape(f.confidence)))
            extras = []
            if f.cve:
                extras.append("CVE: " + ", ".join(f.cve))
            if f.cwe:
                extras.append("CWE: " + ", ".join(f.cwe))
            if f.cvss is not None:
                extras.append("CVSS: %s" % f.cvss)
            if extras:
                w("<div class=\"meta\">%s</div>" % escape(" | ".join(extras)))
            if f.description:
                w("<p>%s</p>" % escape(f.description))
            if f.evidence:
                w("<pre>%s</pre>" % escape(f.evidence[:1500]))
            if f.remediation:
                w("<p><strong>Remediation:</strong> %s</p>" % escape(f.remediation))
            if f.references:
                w("<div class=\"meta\">References: %s</div>"
                  % escape(", ".join(f.references[:8])))
            w("</div>")
        w("</section>")
        w("</div>")
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        w("<footer>Generated by %s v%s &middot; built by %s (%s) &middot; %s</footer>"
          % (PRODUCT_NAME, __version__, escape(AUTHOR), AUTHOR_INITIALS, stamp))
        w("</body></html>")
        return "\n".join(parts)


__all__ = ["HtmlReporter"]
