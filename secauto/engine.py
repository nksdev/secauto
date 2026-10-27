"""Scan orchestration engine.

Runs the selected scanners (respecting dependencies and a concurrency budget),
merges results into a :class:`ScanReport`, persists raw artefacts and hands the
report to the reporter layer.
"""

from __future__ import annotations

import datetime as _dt
import json
import platform
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional

from .config import Config
from .logger import Logger, Palette, Spinner
from .models import ScanReport, ScanResult, ScanStatus, Severity
from .scanners import registry
from .scanners.base import BaseScanner, ScanContext
from .tooling import ToolManager
from .utils import current_platform, is_root, parse_target


# Phase ordering: cheap, high-signal scanners first so later scanners can reuse
# context (e.g. TLS SANs feeding subdomain enumeration).
PHASES: List[List[str]] = [
    ["dns_recon", "whois", "tls_certificate", "http_recon"],
    ["port_scan_python", "nmap", "subfinder", "dns_bruteforce", "amass"],
    ["whatweb", "wafw00f", "sensitive_paths", "nikto"],
    ["sslyze", "testssl", "nuclei"],
]


class ScanEngine:
    """Coordinates tooling, scanners and reporting for one target."""

    def __init__(
        self,
        config: Config,
        logger: Logger,
        tools: Optional[ToolManager] = None,
        output_dir: Optional[Path] = None,
    ) -> None:
        self.config = config
        self.log = logger
        self.tools = tools or ToolManager(config, logger)
        self.output_dir = Path(output_dir or config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ setup
    def prepare(self, install: Optional[bool] = None) -> Dict[str, bool]:
        """Discover tools and optionally auto-install required ones."""
        self.log.rule("TOOL DISCOVERY")
        self.tools.discover(probe_versions=False)
        if self.config.auto_install if install is None else install:
            missing_required = [k for k, v in self.tools.states().items() if v.required and not v.available]
            if missing_required:
                self.log.info(
                    "Missing required tools: " + ", ".join(missing_required), scope="setup"
                )
                self.tools.ensure(missing_required, auto=True)
            # opportunistically install high-value optional tools too
            optional_targets = ["nuclei", "subfinder", "whatweb", "wafw00f", "sslyze", "testssl"]
            for key in optional_targets:
                state = self.tools.states().get(key)
                if state and not state.available:
                    self.log.info(f"Attempting optional install: {state.name}", scope="setup")
                    self.tools.install_one(key)
        self.tools.discover(probe_versions=True)
        self.tools.print_table()
        return {k: v.available for k, v in self.tools.states().items()}

    # ------------------------------------------------------------- selection
    def plan(self, include: Optional[List[str]] = None, exclude: Optional[List[str]] = None) -> List[type[BaseScanner]]:
        available_scanners = registry.select(include=include, exclude=exclude)
        ordered: List[type[BaseScanner]] = []
        seen = set()
        for phase in PHASES:
            for name in phase:
                for cls in available_scanners:
                    if cls.name == name and cls.name not in seen:
                        ordered.append(cls)
                        seen.add(cls.name)
        for cls in available_scanners:
            if cls.name not in seen:
                ordered.append(cls)
                seen.add(cls.name)
        return ordered

    # --------------------------------------------------------------- execution
    def scan(
        self,
        target_input: str,
        include: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> ScanReport:
        target = parse_target(target_input)
        report = ScanReport(target=target)
        report.started_at = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        report.environment = {
            "platform": current_platform(),
            "privileged": is_root(),
            "python": platform.python_version(),
            "config": {
                "concurrency": self.config.concurrency,
                "timeout": self.config.timeout,
                "port_profile": self.config.port_profile,
                "aggressive": self.config.aggressive,
                "passive_only": self.config.passive_only,
            },
        }
        report.tooling = self.tools.summary()

        self.log.rule("TARGET")
        self.log.kv("Input", target.input)
        self.log.kv("Base URL", target.base_url)
        if target.hostname:
            self.log.kv("Hostname", target.hostname)
        if target.ip:
            self.log.kv("IP", target.ip)
        self.log.kv("Root domain", target.root_domain or "n/a")

        context = ScanContext(target, self.config, self.tools, self.log)
        scanners = self.plan(include, exclude)
        if self.config.passive_only:
            scanners = [s for s in scanners if s.category in ("recon", "http", "tls", "dns", "whois")]

        self.log.rule("SCAN PLAN")
        for cls in scanners:
            status = "ready" if self._is_available(cls, context) else "skip (missing tools)"
            self.log.raw(f"  • {cls.name:<18} {cls.category:<14} {status}")
        self.log.rule()

        started = time.time()
        with Spinner("Executing scan pipeline", enabled=self.config.verbosity > 0 and self.log.color):
            results = self._run_scanners(scanners, context)
        report.results = results
        report.duration = time.time() - started
        report.finished_at = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")

        self._print_summary(report)
        return report

    def _is_available(self, cls: type[BaseScanner], context: ScanContext) -> bool:
        try:
            return cls(context).available()
        except Exception:
            return False

    def _run_scanners(self, scanners: List[type[BaseScanner]], context: ScanContext) -> List[ScanResult]:
        results: List[ScanResult] = []
        results_by_name: Dict[str, ScanResult] = {}

        for phase_index, phase in enumerate(PHASES, start=1):
            batch = [cls for cls in scanners if cls.name in phase]
            if not batch:
                continue
            self.log.scan(f"Phase {phase_index}: {', '.join(cls.name for cls in batch)}", scope="engine")
            done = self._execute_batch(batch, context)
            for result in done:
                results.append(result)
                results_by_name[result.scanner] = result

        leftover = [cls for cls in scanners if cls.name not in results_by_name]
        if leftover:
            self.log.scan(f"Final phase: {', '.join(cls.name for cls in leftover)}", scope="engine")
            results.extend(self._execute_batch(leftover, context))
        return results

    def _execute_batch(self, batch: List[type[BaseScanner]], context: ScanContext) -> List[ScanResult]:
        results: List[ScanResult] = []
        workers = max(1, min(self.config.concurrency, len(batch)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="secauto") as pool:
            futures = {}
            for cls in batch:
                scanner = cls(context)
                if not scanner.available():
                    skipped = ScanResult(scanner=cls.name, status=ScanStatus.SKIPPED)
                    skipped.error = "missing tools: " + ", ".join(scanner.missing_tools())
                    results.append(skipped)
                    continue
                futures[pool.submit(scanner.execute)] = cls

            for future in as_completed(futures):
                cls = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # defensive
                    result = ScanResult(scanner=cls.name, status=ScanStatus.FAILED)
                    result.error = f"{type(exc).__name__}: {exc}"
                results.append(result)
                self._log_result(result)
        return results

    def _log_result(self, result: ScanResult) -> None:
        label = f"{result.scanner}"
        if result.status == ScanStatus.SUCCESS:
            count = result.finding_count
            worst = max((f.severity for f in result.findings), key=lambda s: s.rank, default=Severity.INFO)
            colour = worst.color if self.log.color else ""
            reset = Palette.RESET if self.log.color else ""
            self.log.raw(
                f"  {Palette.GREEN if self.log.color else ''}✓{Palette.RESET if self.log.color else ''} "
                f"{label:<18} {count:>3} finding(s)  {colour}{worst.value.upper()}{reset}  "
                f"{result.duration:.1f}s"
            )
        elif result.status == ScanStatus.SKIPPED:
            self.log.raw(f"  - {label:<18} skipped: {result.error}")
        else:
            self.log.raw(f"  ✗ {label:<18} {result.status.value}: {result.error[:120]}")

    # ---------------------------------------------------------------- summary
    def _print_summary(self, report: ScanReport) -> None:
        counts = report.severity_counts()
        self.log.rule("RESULTS SUMMARY")
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            count = counts.get(sev.value, 0)
            if count == 0:
                continue
            colour = sev.color if self.log.color else ""
            reset = Palette.RESET if self.log.color else ""
            self.log.raw(f"  {colour} {sev.value.upper():<9}{reset} {count}")
        self.log.kv("Risk score", f"{report.risk_score}/100  ({report.posture})")
        self.log.kv("Duration", f"{report.duration:.1f}s")
        self.log.kv("Findings", str(len(report.findings)))
        self.log.rule()

    # -------------------------------------------------------------- artefacts
    def persist_raw(self, report: ScanReport) -> Path:
        raw_dir = self.output_dir / f"{report.scan_id}-raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        for result in report.results:
            if not result.raw_output:
                continue
            path = raw_dir / f"{result.scanner}.txt"
            path.write_text(result.raw_output, encoding="utf-8")
        (raw_dir / "report.json").write_text(report.to_json(), encoding="utf-8")
        return raw_dir


__all__ = ["ScanEngine", "PHASES"]
