from __future__ import annotations

import csv
import io

from ..version import AUTHOR, AUTHOR_INITIALS, PRODUCT_NAME, __version__
from .base import BaseReporter


class CsvReporter(BaseReporter):
    name = "csv"
    extension = "csv"

    COLUMNS = [
        "severity",
        "title",
        "category",
        "target",
        "source_tool",
        "confidence",
        "cve",
        "cwe",
        "cvss",
        "description",
        "remediation",
        "generator",
    ]

    def render(self) -> str:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=self.COLUMNS, lineterminator="\n")
        writer.writeheader()
        for f in self.ordered_findings():
            writer.writerow(
                {
                    "severity": f.severity.value,
                    "title": f.title,
                    "category": f.category,
                    "target": f.target,
                    "source_tool": f.source_tool or "built-in",
                    "confidence": f.confidence,
                    "cve": ";".join(f.cve),
                    "cwe": ";".join(f.cwe),
                    "cvss": "" if f.cvss is None else f.cvss,
                    "description": (f.description or "")[:1000],
                    "remediation": (f.remediation or "")[:1000],
                    "generator": f"{PRODUCT_NAME} {__version__} by {AUTHOR} ({AUTHOR_INITIALS})",
                }
            )
        return buffer.getvalue()


__all__ = ["CsvReporter"]
