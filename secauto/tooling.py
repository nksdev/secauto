"""Tool discovery, capability registry and cross-platform auto-installer.

SecAuto works with whatever is already installed and can bootstrap missing
open-source tools on Windows, Linux and macOS using the native package
manager, pipx or Go where available.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .config import Config, default_bin_dir, default_pylibs_dir, default_tools_dir
from .logger import Logger, Palette
from .utils import current_platform, is_root, run_command, which


# --------------------------------------------------------------------- registry
@dataclass
class ToolSpec:
    """Metadata describing an external tool SecAuto can drive."""

    name: str
    binary: str
    description: str
    required: bool = False
    category: str = "recon"
    pip: Optional[str] = None
    go: Optional[str] = None
    brew: Optional[str] = None
    apt: Optional[str] = None
    dnf: Optional[str] = None
    pacman: Optional[str] = None
    winget: Optional[str] = None
    choco: Optional[str] = None
    fallback: List[str] = field(default_factory=list)
    version_flags: List[str] = field(default_factory=list)

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"{self.name} ({self.binary})"


TOOL_REGISTRY: Dict[str, ToolSpec] = {
    "nmap": ToolSpec(
        name="Nmap",
        binary="nmap",
        description="Port scanning and service/version detection",
        required=True,
        category="network",
        brew="nmap",
        apt="nmap",
        dnf="nmap",
        pacman="nmap",
        winget="Insecure.Nmap",
        choco="nmap",
    ),
    "nikto": ToolSpec(
        name="Nikto",
        binary="nikto",
        description="Web server misconfiguration and vulnerability scanner",
        required=True,
        category="web",
        brew="nikto",
        apt="nikto",
        dnf="nikto",
        pacman="nikto",
        fallback=["git"],
    ),
    "nuclei": ToolSpec(
        name="Nuclei",
        binary="nuclei",
        description="Template-based vulnerability scanner (ProjectDiscovery)",
        category="vulnerability",
        go="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        brew="nuclei",
        apt="nuclei",
        fallback=["go"],
    ),
    "subfinder": ToolSpec(
        name="Subfinder",
        binary="subfinder",
        description="Passive subdomain enumeration",
        category="recon",
        go="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        brew="subfinder",
        fallback=["go"],
    ),
    "amass": ToolSpec(
        name="Amass",
        binary="amass",
        description="In-depth attack surface mapping and asset discovery",
        category="recon",
        go="github.com/owasp-amass/amass/v4/...@master",
        brew="amass",
        fallback=["go"],
    ),
    "whatweb": ToolSpec(
        name="WhatWeb",
        binary="whatweb",
        description="Web technology fingerprinting",
        category="web",
        brew="whatweb",
        apt="whatweb",
        dnf="whatweb",
        fallback=["ruby"],
    ),
    "wafw00f": ToolSpec(
        name="Wafw00f",
        binary="wafw00f",
        description="Web application firewall detection",
        category="web",
        pip="wafw00f",
        brew="wafw00f",
    ),
    "testssl": ToolSpec(
        name="testssl.sh",
        binary="testssl.sh",
        description="TLS/SSL configuration and cipher analysis",
        category="tls",
        brew="testssl",
        apt="testssl.sh",
        fallback=["git", "openssl"],
    ),
    "sslyze": ToolSpec(
        name="SSLyze",
        binary="sslyze",
        description="Fast TLS/SSL scanner (Python)",
        category="tls",
        pip="sslyze",
    ),
    "whois": ToolSpec(
        name="Whois",
        binary="whois",
        description="Domain registration lookup",
        version_flags=["-V"],
        category="recon",
        brew="whois",
        apt="whois",
        dnf="whois",
        pacman="whois",
        winget="Whois",
    ),
    "dig": ToolSpec(
        name="dig",
        binary="dig",
        description="DNS querying",
        version_flags=["-v"],
        category="recon",
        brew="bind",
        apt="dnsutils",
        dnf="bind-utils",
        pacman="bind",
    ),
    "curl": ToolSpec(
        name="curl",
        binary="curl",
        description="HTTP client used for header and content checks",
        required=True,
        category="http",
        brew="curl",
        apt="curl",
        dnf="curl",
        pacman="curl",
        winget="cURL.cURL",
    ),
    "openssl": ToolSpec(
        name="OpenSSL",
        binary="openssl",
        description="Certificate inspection and TLS probing",
        required=True,
        category="tls",
        brew="openssl@3",
        apt="openssl",
        dnf="openssl",
        pacman="openssl",
    ),
    "git": ToolSpec(
        name="git",
        binary="git",
        description="Source checkout for script-based tools",
        category="support",
        brew="git",
        apt="git",
        dnf="git",
        pacman="git",
        winget="Git.Git",
    ),
    "go": ToolSpec(
        name="Go",
        binary="go",
        description="Toolchain used to build ProjectDiscovery binaries",
        category="support",
        brew="go",
        apt="golang-go",
        dnf="golang",
        pacman="go",
        winget="GoLang.Go",
    ),
    "pipx": ToolSpec(
        name="pipx",
        binary="pipx",
        description="Isolated Python application installer",
        category="support",
        pip="pipx",
        brew="pipx",
        apt="pipx",
        dnf="pipx",
        pacman="python-pipx",
    ),
    "searchsploit": ToolSpec(
        name="SearchSploit",
        binary="searchsploit",
        description="Local Exploit-DB search for detected service versions",
        category="vulnerability",
        brew="exploitdb",
        apt="exploitdb",
    ),
}


# ------------------------------------------------------------------ discovery
@dataclass
class ToolState:
    key: str
    name: str
    binary: str
    path: Optional[str]
    version: Optional[str]
    description: str
    category: str
    required: bool

    @property
    def available(self) -> bool:
        return self.path is not None

    def to_dict(self) -> Dict[str, object]:
        return {
            "key": self.key,
            "name": self.name,
            "binary": self.binary,
            "path": self.path,
            "version": self.version,
            "description": self.description,
            "category": self.category,
            "required": self.required,
            "available": self.available,
        }


_VERSION_FLAGS = ["--version", "-version", "-V", "version", "-h"]


def _probe_version(binary_path: str, flags: Optional[List[str]] = None) -> Optional[str]:
    """Return a short version string for a binary, or None if undeterminable.

    Many tools print help menus or ASCII art when given an unknown flag, so a
    candidate line is only accepted when it carries a real version pattern.
    """
    if not os.path.isfile(binary_path):
        return None

    version_re = re.compile(r"\bv?\d+\.\d+", re.IGNORECASE)
    noisy = (
        "usage", "invalid option", "illegal option", "traceback",
        "options:", "error:", "show ", "use ", "release-date", "platform:",
    )

    for flag in (flags or _VERSION_FLAGS):
        try:
            outcome = run_command([binary_path, flag], timeout=20)
        except (OSError, PermissionError):
            return None
        text = (outcome.stdout or "") + "\n" + (outcome.stderr or "")
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or len(line) > 120:
                continue
            lowered = line.lower()
            if any(token in lowered for token in noisy):
                continue
            if not version_re.search(line):
                continue
            return line[:120]
    return None


class ToolManager:
    """Discovers, reports and installs external tooling."""

    def __init__(self, config: Config, logger: Logger) -> None:
        self.config = config
        self.log = logger
        self.platform = current_platform()
        self._states: Dict[str, ToolState] = {}

    # ------------------------------------------------------------- discovery
    def discover(self, probe_versions: bool = True) -> Dict[str, ToolState]:
        states: Dict[str, ToolState] = {}
        for key, spec in TOOL_REGISTRY.items():
            path = which(spec.binary)
            version = _probe_version(path, spec.version_flags) if (path and probe_versions) else None
            states[key] = ToolState(
                key=key,
                name=spec.name,
                binary=spec.binary,
                path=path,
                version=version,
                description=spec.description,
                category=spec.category,
                required=spec.required,
            )
        self._states = states
        return states

    def states(self) -> Dict[str, ToolState]:
        return self._states or self.discover(probe_versions=False)

    def available(self, key: str) -> bool:
        state = self.states().get(key)
        return bool(state and state.available)

    def path_of(self, key: str) -> Optional[str]:
        state = self.states().get(key)
        return state.path if state else None

    def summary(self) -> Dict[str, object]:
        states = self.states()
        return {
            "platform": self.platform,
            "tools": {k: v.to_dict() for k, v in states.items()},
            "available": sorted(k for k, v in states.items() if v.available),
            "missing": sorted(k for k, v in states.items() if not v.available),
        }

    def print_table(self) -> None:
        states = self.states()
        self.log.rule("TOOL INVENTORY")
        for key in sorted(states, key=lambda k: (states[k].category, k)):
            state = states[key]
            if state.available:
                mark = self.log._paint("●", Palette.GREEN) if self.log.color else "[+]"
                extra = state.version or "installed"
            else:
                mark = self.log._paint("○", Palette.RED) if self.log.color else "[-]"
                extra = "missing"
            line = f"  {mark} {state.name:<14} {state.category:<14} {extra}"
            self.log.raw(line)
        self.log.rule()

    # -------------------------------------------------------------- installing
    def _package_manager_command(self, manager: str, package: str) -> Optional[List[str]]:
        if manager == "brew":
            return ["brew", "install", package]
        if manager == "apt":
            return ["apt-get", "install", "-y", package]
        if manager == "dnf":
            return ["dnf", "install", "-y", package]
        if manager == "pacman":
            return ["pacman", "-S", "--noconfirm", package]
        if manager == "winget":
            return ["winget", "install", "--id", package, "--accept-source-agreements", "--accept-package-agreements", "-e"]
        if manager == "choco":
            return ["choco", "install", package, "-y"]
        return None

    def _install_via_package_manager(self, spec: ToolSpec) -> bool:
        managers = {
            "macos": [("brew", spec.brew)],
            "linux": [("apt", spec.apt), ("dnf", spec.dnf), ("pacman", spec.pacman)],
            "windows": [("winget", spec.winget), ("choco", spec.choco)],
        }.get(self.platform, [])

        for manager, package in managers:
            if not package or not shutil.which(manager):
                continue
            cmd = self._package_manager_command(manager, package)
            if not cmd:
                continue
            self.log.info(f"Installing {spec.name} via {manager} ...", scope="install")
            if self.platform == "linux" and not is_root() and shutil.which("sudo"):
                cmd = ["sudo", "-n"] + cmd
            outcome = run_command(cmd, timeout=self.config.timeout)
            if outcome.returncode == 0 and which(spec.binary):
                self.log.success(f"{spec.name} installed via {manager}", scope="install")
                return True
            self.log.debug(f"{manager} install failed: {outcome.stderr[:200]}", scope="install")
        return False

    def _install_via_pip(self, spec: ToolSpec) -> bool:
        if not spec.pip:
            return False
        # Strategy 1: pipx keeps the tool isolated. Needs a writable log dir; we
        # point it at the managed home so sandboxed/contained runs still work.
        if shutil.which("pipx"):
            env = {
                "PIPX_HOME": str(default_tools_dir() / "pipx"),
                "PIPX_BIN_DIR": str(default_bin_dir()),
                "PIPX_DEFAULT_PYTHON": sys.executable,
            }
            outcome = run_command(
                ["pipx", "install", spec.pip], timeout=self.config.timeout, env=env
            )
            if outcome.returncode == 0 and (which(spec.binary) or which(spec.binary, extra=[env["PIPX_BIN_DIR"]])):
                self._expose_bin(env["PIPX_BIN_DIR"])
                return True
            self.log.debug(f"pipx failed for {spec.name}: {outcome.stderr[:200]}", scope="install")

        # Strategy 2: install into a managed directory with --target. This never
        # touches the user's site-packages and works without write access to it.
        target_dir = default_pylibs_dir()
        self.log.info(f"Installing {spec.name} via pip ...", scope="install")
        cmd = [sys.executable, "-m", "pip", "install", "--target", str(target_dir), spec.pip]
        outcome = run_command(cmd, timeout=max(self.config.timeout, 600))
        if outcome.returncode != 0:
            self.log.debug(f"pip --target failed: {outcome.stderr[:200]}", scope="install")
            # Strategy 3: last resort, a plain user install.
            cmd = [sys.executable, "-m", "pip", "install", "--user", spec.pip]
            outcome = run_command(cmd, timeout=max(self.config.timeout, 600))
            return outcome.returncode == 0 and bool(which(spec.binary))

        self._expose_bin(str(target_dir / "bin"))
        self._register_pylibs(target_dir)
        return True

    def _expose_bin(self, directory: str) -> None:
        """Prepend a managed bin directory to PATH and remember it."""
        if not directory or not os.path.isdir(directory):
            return
        current = os.environ.get("PATH", "")
        if directory not in current.split(os.pathsep):
            os.environ["PATH"] = directory + os.pathsep + current

    def _register_pylibs(self, directory) -> None:
        """Make a pip --target directory importable by this process."""
        entry = str(directory)
        if entry not in sys.path:
            sys.path.insert(0, entry)

    def _install_via_go(self, spec: ToolSpec) -> bool:
        if not spec.go or not shutil.which("go"):
            return False
        gopath = os.environ.get("GOPATH") or str(default_tools_dir() / "go")
        gobin = os.path.join(gopath, "bin")
        os.makedirs(gobin, exist_ok=True)
        self.log.info(f"Building {spec.name} with go install ...", scope="install")
        outcome = run_command(
            ["go", "install", spec.go],
            timeout=max(self.config.timeout, 900),
            env={"GOBIN": gobin, "GOPATH": gopath},
        )
        if outcome.returncode == 0:
            os.environ["PATH"] = gobin + os.pathsep + os.environ.get("PATH", "")
            return bool(which(spec.binary))
        return False

    def _install_via_git(self, spec: ToolSpec) -> bool:
        """Last resort: clone well-known script tools into the managed tools dir."""
        if not shutil.which("git"):
            return False
        repos = {
            "nikto": ("https://github.com/sullo/nikto.git", "program/nikto.pl"),
            "testssl": ("https://github.com/drwetter/testssl.sh.git", "testssl.sh"),
        }
        if spec.binary not in repos and spec.name.lower() not in repos:
            return False
        key = "testssl" if "testssl" in spec.binary.lower() or "testssl" in spec.name.lower() else spec.binary
        url, rel = repos[key]
        dest = default_tools_dir() / key
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        self.log.info(f"Cloning {spec.name} from source ...", scope="install")
        outcome = run_command(["git", "clone", "--depth", "1", url, str(dest)], timeout=600)
        if outcome.returncode != 0:
            return False
        script = dest / rel
        if script.exists():
            try:
                script.chmod(0o755)
            except OSError:
                pass
            return True
        return False

    def install_one(self, key: str) -> bool:
        spec = TOOL_REGISTRY.get(key)
        if not spec:
            return False
        if which(spec.binary):
            return True
        for strategy in (
            self._install_via_package_manager,
            self._install_via_pip,
            self._install_via_go,
            self._install_via_git,
        ):
            try:
                if strategy(spec):
                    self.discover(probe_versions=False)
                    return True
            except Exception as exc:  # defensive: never abort the whole install
                self.log.debug(f"install strategy error for {spec.name}: {exc}", scope="install")
        return False

    def ensure(self, keys: Optional[List[str]] = None, auto: Optional[bool] = None) -> Dict[str, bool]:
        """Ensure required/optional tools exist, installing when allowed."""
        auto_install = self.config.auto_install if auto is None else auto
        targets = keys or [k for k, s in TOOL_REGISTRY.items() if s.required]
        self.discover(probe_versions=False)
        outcomes: Dict[str, bool] = {}
        for key in targets:
            state = self._states.get(key)
            if state and state.available:
                outcomes[key] = True
                continue
            if not auto_install or self.config.offline:
                outcomes[key] = False
                continue
            self.log.warn(f"Missing {TOOL_REGISTRY[key].name}; attempting automatic install", scope="install")
            outcomes[key] = self.install_one(key)
        self.discover(probe_versions=True)
        return outcomes

    def install_all(self) -> Dict[str, bool]:
        return self.ensure(keys=list(TOOL_REGISTRY.keys()), auto=True)

    def missing_required(self) -> List[str]:
        return [k for k, v in self.states().items() if v.required and not v.available]

    def export_inventory(self, path) -> None:
        from pathlib import Path

        Path(path).write_text(json.dumps(self.summary(), indent=2), encoding="utf-8")


__all__ = ["ToolSpec", "ToolState", "ToolManager", "TOOL_REGISTRY"]
