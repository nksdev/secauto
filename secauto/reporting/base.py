"""Reporter base class and shared formatting helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Dict

from ..models import ScanReport, Severity


class BaseReporter:
    """Contract for report writers."""

    extension: str = "txt"
    name: str = "base"

    def __init__(self, report: ScanReport) -> None:
        self.report = report

    def render(self) -> str:
        raise NotImplementedError

    def write(self, output_dir: Path, stem: str) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / f"{stem}.{self.extension}"
        path.write_text(self.render(), encoding="utf-8")
        return path

    # ---------------------------------------------------------------- helpers
    def severity_bars(self) -> Dict[str, int]:
        return self.report.severity_counts()

    def ordered_findings(self):
        return sorted(
            self.report.findings,
            key=lambda f: (-f.severity.rank, f.category, f.title),
        )

    def ordered_severities(self):
        return [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO, Severity.UNKNOWN]


__all__ = ["BaseReporter"]
