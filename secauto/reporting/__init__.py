"""Report generation: HTML, JSON, Markdown, CSV and terminal output."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Type

from .base import BaseReporter
from .csv_report import CsvReporter
from .html_report import HtmlReporter
from .json_report import JsonReporter
from .markdown_report import MarkdownReporter
from .terminal_report import format_report

REPORTERS: Dict[str, Type[BaseReporter]] = {
    "html": HtmlReporter,
    "json": JsonReporter,
    "markdown": MarkdownReporter,
    "csv": CsvReporter,
}


def available_formats() -> List[str]:
    return list(REPORTERS)


def write_reports(report, output_dir: Path, formats: List[str] | None = None, stem: str | None = None) -> List[Path]:
    """Render every requested format and return the written paths."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = stem or report.scan_id
    written: List[Path] = []
    for fmt in formats or list(REPORTERS):
        reporter_cls = REPORTERS.get(fmt.lower())
        if not reporter_cls:
            continue
        written.append(reporter_cls(report).write(output_dir, stem))
    return written


__all__ = [
    "BaseReporter",
    "HtmlReporter",
    "JsonReporter",
    "MarkdownReporter",
    "format_report",
    "CsvReporter",
    "REPORTERS",
    "available_formats",
    "write_reports",
]
