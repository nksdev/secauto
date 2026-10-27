"""First-run bootstrap: provision the external toolset automatically.

SecAuto is designed to be self-provisioning. The first time it is launched on a
machine it downloads and installs every external tool it can drive, records the
outcome in a state file, and from then on only re-checks what is already there.

Built by Naman Kumar Sonker (@nksdev).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .config import Config, app_home, default_tools_dir
from .logger import Logger
from .tooling import TOOL_REGISTRY, ToolManager
from .version import AUTHOR, AUTHOR_INITIALS, PRODUCT_NAME, __version__


STATE_FILENAME = "bootstrap.json"
STATE_VERSION = 1


def state_path() -> Path:
    """Location of the persisted bootstrap state file."""
    return app_home() / STATE_FILENAME


def _now() -> str:
    import datetime as _dt

    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


@dataclass
class BootstrapState:
    """Persisted record of what the bootstrap has already provisioned."""

    version: int = STATE_VERSION
    completed: bool = False
    completed_at: str = ""
    last_attempt_at: str = ""
    installed: List[str] = field(default_factory=list)
    failed: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    platform: str = ""

    # ------------------------------------------------------------ persistence
    @classmethod
    def load(cls) -> "BootstrapState":
        path = state_path()
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls()
        if data.get("version") != STATE_VERSION:
            return cls()
        state = cls()
        for key in ("completed", "completed_at", "last_attempt_at", "platform"):
            if key in data:
                setattr(state, key, data[key])
        for key in ("installed", "failed", "skipped"):
            value = data.get(key)
            if isinstance(value, list):
                setattr(state, key, [str(v) for v in value])
        return state

    def save(self) -> None:
        path = state_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        except OSError:
            pass

    def to_dict(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "product": PRODUCT_NAME,
            "product_version": __version__,
            "author": AUTHOR,
            "initials": AUTHOR_INITIALS,
            "completed": self.completed,
            "completed_at": self.completed_at,
            "last_attempt_at": self.last_attempt_at,
            "platform": self.platform,
            "installed": sorted(self.installed),
            "failed": sorted(self.failed),
            "skipped": sorted(self.skipped),
        }


class Bootstrapper:
    """Drives the automatic first-run provisioning of external tools."""

    def __init__(self, config: Config, logger: Logger, tools: Optional[ToolManager] = None) -> None:
        self.config = config
        self.log = logger
        self.tools = tools or ToolManager(config, logger)
        self.state = BootstrapState.load()

    # ------------------------------------------------------------------ checks
    def is_complete(self) -> bool:
        """True when a previous bootstrap finished and nothing critical is gone."""
        if not self.state.completed:
            return False
        states = self.tools.discover(probe_versions=False)
        missing_required = [k for k, v in states.items() if v.required and not v.available]
        return not missing_required

    def should_run(self, force: bool = False) -> bool:
        if force:
            return True
        if self.config.offline:
            return False
        return not self.is_complete()

    # ------------------------------------------------------------------- runner
    def run(self, force: bool = False, quiet: bool = False) -> BootstrapState:
        """Provision every known tool, persisting the outcome."""
        states = self.tools.discover(probe_versions=False)

        already = [k for k, v in states.items() if v.available]
        targets = [k for k, v in states.items() if not v.available]

        self.state = BootstrapState(
            completed=False,
            completed_at=self.state.completed_at,
            last_attempt_at=_now(),
            installed=sorted(already),
            failed=[],
            skipped=[],
            platform=self.tools.platform,
        )

        if not quiet:
            self.log.rule("FIRST-RUN BOOTSTRAP")
            self.log.kv("Platform", self.tools.platform)
            self.log.kv("Already present", str(len(already)))
            self.log.kv("To provision", str(len(targets)))
            self.log.kv("Managed tools", str(default_tools_dir()))

        if self.config.offline:
            self.state.skipped = sorted(targets)
            self.state.save()
            if not quiet:
                self.log.warn("Offline mode: skipping tool download", scope="bootstrap")
            return self.state

        if not targets:
            self.state.completed = True
            self.state.completed_at = _now()
            self.state.save()
            if not quiet:
                self.log.success("All tools already present; nothing to download", scope="bootstrap")
            return self.state

        installed: List[str] = []
        failed: List[str] = []
        total = len(targets)
        for index, key in enumerate(targets, start=1):
            spec = TOOL_REGISTRY.get(key)
            label = spec.name if spec else key
            if not quiet:
                self.log.info(f"[{index}/{total}] installing {label} ...", scope="bootstrap")
            try:
                ok = self.tools.install_one(key)
            except Exception as exc:  # never abort the whole bootstrap
                self.log.debug(f"bootstrap install error for {key}: {exc}", scope="bootstrap")
                ok = False
            if ok:
                installed.append(key)
                if not quiet:
                    self.log.success(f"{label} ready", scope="bootstrap")
            else:
                failed.append(key)
                if not quiet:
                    self.log.warn(f"{label} could not be installed automatically", scope="bootstrap")

        self.tools.discover(probe_versions=False)
        final = self.tools.states()

        self.state.installed = sorted(k for k, v in final.items() if v.available)
        self.state.failed = sorted(k for k, v in final.items() if not v.available and k in failed)
        self.state.skipped = sorted(
            k for k, v in final.items() if not v.available and k not in failed
        )

        critical_missing = [k for k, v in final.items() if v.required and not v.available]
        self.state.completed = not critical_missing
        if self.state.completed:
            self.state.completed_at = _now()
        self.state.save()

        if not quiet:
            self.log.rule("BOOTSTRAP SUMMARY")
            self.log.kv("Ready", str(len(self.state.installed)))
            self.log.kv("Failed", str(len(self.state.failed)))
            self.log.kv("Missing", str(len(self.state.skipped)))
            if self.state.failed:
                names = ", ".join(
                    (TOOL_REGISTRY[k].name if k in TOOL_REGISTRY else k) for k in self.state.failed
                )
                self.log.warn(f"Could not auto-install: {names}", scope="bootstrap")
                self.log.info(
                    "SecAuto still runs its built-in Python scanners; install the rest manually "
                    "with 'secauto install <tool>'.",
                    scope="bootstrap",
                )
            if self.state.completed:
                self.log.success(
                    f"Bootstrap complete - {PRODUCT_NAME} {__version__} by {AUTHOR} ({AUTHOR_INITIALS})",
                    scope="bootstrap",
                )

        return self.state


__all__ = ["BootstrapState", "Bootstrapper", "state_path", "STATE_FILENAME"]
