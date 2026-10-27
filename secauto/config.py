"""Configuration handling for SecAuto.

Layered defaults -> config file (JSON) -> environment variables -> CLI flags.

The application directory defaults to ``<repo>/.secauto-home`` when the real
user home is not writable (sandboxed environments), otherwise ``~/.secauto``.
Set ``SECAUTO_HOME`` to override explicitly.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

APP_DIR_NAME = ".secauto"


def _project_root() -> Path:
    """Repository root: parent of the ``secauto`` package directory."""
    return Path(__file__).resolve().parent.parent


def _user_home_writable() -> bool:
    home = Path.home()
    try:
        probe = home / APP_DIR_NAME
        probe.mkdir(parents=True, exist_ok=True)
        testfile = probe / ".write-test"
        testfile.write_text("ok", encoding="utf-8")
        testfile.unlink(missing_ok=True)
        return True
    except (OSError, PermissionError):
        return False


def app_home() -> Path:
    """Return the per-user application directory, creating it if needed."""
    override = os.environ.get("SECAUTO_HOME")
    if override:
        base = Path(override).expanduser()
    elif _user_home_writable():
        base = Path.home() / APP_DIR_NAME
    else:
        base = _project_root() / ".secauto-home"
    base.mkdir(parents=True, exist_ok=True)
    return base


def default_config_path() -> Path:
    return app_home() / "config.json"


def default_output_dir() -> Path:
    return app_home() / "reports"


def default_tools_dir() -> Path:
    return app_home() / "tools"


def default_log_dir() -> Path:
    return app_home() / "logs"


def default_pylibs_dir() -> Path:
    """Directory holding pip --target installations managed by SecAuto."""
    return app_home() / "pylibs"


def activate_pylibs() -> None:
    """Make the managed pip --target directory importable.

    Console scripts installed by ``pip --target`` reference their package by
    name, so the target directory must be on ``sys.path`` and on ``PYTHONPATH``
    for any subprocess SecAuto launches.
    """
    import sys

    target = default_pylibs_dir()
    if not target.is_dir():
        return
    entry = str(target)
    if entry not in sys.path:
        sys.path.insert(0, entry)
    current = os.environ.get("PYTHONPATH", "")
    if entry not in current.split(os.pathsep):
        os.environ["PYTHONPATH"] = entry + (os.pathsep + current if current else "")


def default_bin_dir() -> Path:
    """Directory holding executables SecAuto installs itself."""
    path = app_home() / "bin"
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass
class Config:
    """Runtime configuration for a scan session."""

    # execution
    concurrency: int = 6
    timeout: int = 300
    retries: int = 1
    user_agent: str = (
        "Mozilla/5.0 (SecAuto; +https://github.com/nksdev/secauto) "
        "AppleWebKit/537.36 (KHTML, like Gecko)"
    )

    # behaviour toggles
    auto_install: bool = True
    offline: bool = False
    aggressive: bool = False
    passive_only: bool = False
    resolve_dns: bool = True
    subdomain_enum: bool = True
    port_scan: bool = True
    web_scan: bool = True
    tls_scan: bool = True
    tech_detect: bool = True

    # scan tuning
    port_profile: str = "top1000"  # top100 | top1000 | full | custom
    custom_ports: str = ""
    max_subdomains: int = 500
    subdomain_wordlist: Optional[str] = None

    # output
    output_dir: str = ""
    report_formats: List[str] = field(default_factory=lambda: ["html", "json", "markdown"])
    open_report: bool = False
    verbosity: int = 1  # 0 quiet, 1 normal, 2 verbose, 3 debug
    color: bool = True

    # legal / consent
    authorized: bool = False

    def __post_init__(self) -> None:
        if not self.output_dir:
            self.output_dir = str(default_output_dir())

    # ------------------------------------------------------------- persistence
    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Config":
        cfg = cls()
        path = path or default_config_path()
        if Path(path).exists():
            try:
                data = json.loads(Path(path).read_text(encoding="utf-8"))
                cfg = cfg.merge(data)
            except (OSError, json.JSONDecodeError):
                pass
        return cfg.apply_env()

    def merge(self, data: Dict[str, Any]) -> "Config":
        valid = {f for f in self.__dataclass_fields__}  # type: ignore[attr-defined]
        for key, value in data.items():
            if key in valid and value is not None:
                setattr(self, key, value)
        return self

    def apply_env(self) -> "Config":
        mapping = {
            "SECAUTO_CONCURRENCY": ("concurrency", int),
            "SECAUTO_TIMEOUT": ("timeout", int),
            "SECAUTO_OUTPUT_DIR": ("output_dir", str),
            "SECAUTO_VERBOSITY": ("verbosity", int),
            "SECAUTO_NO_COLOR": ("color", lambda v: False),
            "SECAUTO_OFFLINE": ("offline", lambda v: True),
            "SECAUTO_AUTO_INSTALL": ("auto_install", lambda v: v.lower() not in ("0", "false", "no")),
        }
        for env_key, (attr, caster) in mapping.items():
            if env_key in os.environ:
                try:
                    setattr(self, attr, caster(os.environ[env_key]))
                except (TypeError, ValueError):
                    pass
        return self

    def save(self, path: Optional[Path] = None) -> Path:
        path = path or default_config_path()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        return Path(path)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


__all__ = [
    "Config",
    "app_home",
    "default_config_path",
    "default_output_dir",
    "default_tools_dir",
    "default_log_dir",
]
