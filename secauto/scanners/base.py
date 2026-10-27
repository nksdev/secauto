"""Scanner base class and registry primitives.

Every scanner is a small, testable unit with a stable name, a `available()`
check and a `run(target, context)` method returning a :class:`ScanResult`.
"""

from __future__ import annotations

import datetime as _dt
import time
from typing import Any, Dict, List, Optional

from ..logger import Logger
from ..models import Finding, ScanResult, ScanStatus, Target


class ScanContext:
    """Shared state passed to every scanner during a single scan."""

    def __init__(self, target: Target, config, tools, log: Logger) -> None:
        self.target = target
        self.config = config
        self.tools = tools
        self.log = log
        self.shared: Dict[str, Any] = {}

    def remember(self, key: str, value: Any) -> None:
        self.shared[key] = value

    def recall(self, key: str, default: Any = None) -> Any:
        return self.shared.get(key, default)


class BaseScanner:
    """Contract implemented by all scanners."""

    name: str = "base"
    description: str = ""
    category: str = "general"
    requires: List[str] = []  # tool registry keys
    enabled_by_default: bool = True

    def __init__(self, context: ScanContext) -> None:
        self.ctx = context
        self.config = context.config
        self.log = context.log
        self.target = context.target

    # ---------------------------------------------------------------- helpers
    def available(self) -> bool:
        """True when every required external tool is present."""
        return all(self.ctx.tools.available(key) for key in self.requires)

    def missing_tools(self) -> List[str]:
        return [key for key in self.requires if not self.ctx.tools.available(key)]

    def finding(self, **kwargs) -> Finding:
        kwargs.setdefault("target", self.target.base_url or self.target.input)
        kwargs.setdefault("source_tool", self.name)
        return Finding(**kwargs)

    # --------------------------------------------------------------- execution
    def execute(self) -> ScanResult:
        """Run `scan()` inside timing/error handling and normalise the result."""
        result = ScanResult(scanner=self.name)
        result.started_at = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")

        if not self.enabled_by_default and not getattr(self.config, "aggressive", False):
            result.status = ScanStatus.SKIPPED
            result.error = "disabled by configuration"
            return result

        if not self.available():
            result.status = ScanStatus.SKIPPED
            result.error = "missing tools: " + ", ".join(self.missing_tools())
            return result

        started = time.time()
        result.status = ScanStatus.RUNNING
        try:
            produced = self.scan(result) or []
            result.findings = produced
            result.status = ScanStatus.SUCCESS
        except TimeoutError as exc:
            result.status = ScanStatus.TIMEOUT
            result.error = str(exc) or "scanner timed out"
        except Exception as exc:  # noqa: BLE001 - scanners must never crash a scan
            result.status = ScanStatus.FAILED
            result.error = f"{type(exc).__name__}: {exc}"
            self.log.debug(f"{self.name} failed: {exc}", scope="scanner")
        finally:
            result.duration = time.time() - started
            result.finished_at = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        return result

    def scan(self, result: ScanResult) -> List[Finding]:
        """Implement in subclasses; return findings and optionally fill `result`."""
        raise NotImplementedError


class ScannerRegistry:
    """Ordered collection of scanner classes with lookup by name."""

    def __init__(self) -> None:
        self._scanners: List[type[BaseScanner]] = []

    def register(self, cls: type[BaseScanner]) -> type[BaseScanner]:
        if cls not in self._scanners:
            self._scanners.append(cls)
        return cls

    def all(self) -> List[type[BaseScanner]]:
        return list(self._scanners)

    def names(self) -> List[str]:
        return [c.name for c in self._scanners]

    def select(self, include: Optional[List[str]] = None, exclude: Optional[List[str]] = None) -> List[type[BaseScanner]]:
        chosen = self._scanners
        if include:
            wanted = {n.lower() for n in include}
            chosen = [c for c in chosen if c.name.lower() in wanted or c.category.lower() in wanted]
        if exclude:
            banned = {n.lower() for n in exclude}
            chosen = [c for c in chosen if c.name.lower() not in banned]
        return list(chosen)


registry = ScannerRegistry()


def register(cls: type[BaseScanner]) -> type[BaseScanner]:
    """Decorator that adds a scanner class to the global registry."""
    return registry.register(cls)


__all__ = ["ScanContext", "BaseScanner", "ScannerRegistry", "registry", "register"]
