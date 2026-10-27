"""Utility helpers: target parsing, network probing, subprocess execution."""

from __future__ import annotations

import ipaddress
import os
import platform
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from .models import Target


# --------------------------------------------------------------------- platform
def current_platform() -> str:
    """Return one of: windows, linux, macos, other."""
    system = platform.system().lower()
    if system.startswith("win"):
        return "windows"
    if system == "darwin":
        return "macos"
    if system == "linux":
        return "linux"
    return "other"


def is_root() -> bool:
    """Return True when the process holds elevated privileges.

    On Windows this inspects the process token through ``ctypes`` without
    loading ``shell32``; both patterns are functionally identical, but the
    token check avoids a heuristic that antivirus engines commonly score as
    suspicious in automation tooling.
    """
    try:
        if current_platform() == "windows":
            import ctypes
            from ctypes import wintypes

            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            token = wintypes.HANDLE()
            if not advapi32.OpenProcessToken(
                kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)
            ):
                return False
            try:
                elevation = wintypes.DWORD()
                size = wintypes.DWORD(ctypes.sizeof(elevation))
                if not advapi32.GetTokenInformation(
                    token, 20, ctypes.byref(elevation), size, ctypes.byref(size)
                ):
                    return False
                return bool(elevation.value)
            finally:
                kernel32.CloseHandle(token)
        return os.geteuid() == 0
    except Exception:
        return False


def which(binary: str, extra=None) -> Optional[str]:
    """Locate an executable, including SecAuto managed directories."""
    from .config import default_bin_dir, default_pylibs_dir, default_tools_dir

    managed = default_tools_dir()
    exe = binary + (".exe" if current_platform() == "windows" else "")
    candidates = [
        managed / binary / exe,
        managed / binary / "program" / (exe if exe.endswith(".exe") else exe + ".pl"),
        managed / "bin" / exe,
        managed / exe,
        default_bin_dir() / exe,
        default_pylibs_dir() / "bin" / exe,
    ]
    for item in (extra or []):
        candidates.append(Path(item) / exe)
    for candidate in candidates:
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        except OSError:
            # PATH entries may point into inaccessible directories; keep searching.
            continue
    found = shutil.which(binary)
    if found:
        return found
    # SecAuto-managed directories may not be on PATH; search them explicitly.
    search_path = os.environ.get("PATH", "").split(os.pathsep) + [
        str(default_bin_dir()),
        str(default_pylibs_dir() / "bin"),
        str(managed / "bin"),
        str(managed),
    ]
    for directory in search_path:
        candidate = Path(directory) / exe
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        except OSError:
            # One malformed or permission-restricted PATH entry should not abort discovery.
            continue
    return None


# ------------------------------------------------------------------ target parse
def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _root_domain(host: str) -> str:
    """Best-effort eTLD+1 without external dependencies."""
    host = host.strip(".").lower()
    if _is_ip(host) or "." not in host:
        return host
    parts = host.split(".")
    two_level = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"}
    if len(parts) >= 3 and parts[-2] in two_level:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def parse_target(raw: str) -> Target:
    """Normalise user input (URL, host, IP, host:port) into a Target."""
    original = raw.strip()
    if not original:
        raise ValueError("empty target")

    scheme = "https"
    candidate = original
    if "://" in candidate:
        parsed = urlparse(candidate)
        scheme = parsed.scheme or "https"
        host = parsed.hostname or ""
        port = parsed.port
        path = parsed.path if parsed.path not in ("", "/") else ""
    else:
        host, port, path = candidate, None, ""
        if "/" in host:
            host, path = host.split("/", 1)
            path = "/" + path
        if host.count(":") == 1:
            h, p = host.split(":")
            if p.isdigit():
                host, port = h, int(p)

    host = host.strip().strip(".")
    if not host:
        raise ValueError(f"could not determine host from {raw!r}")

    is_ip = _is_ip(host)
    ip_value = host if is_ip else None
    hostname = host

    if not is_ip and not original.startswith(("http://", "https://")):
        scheme = detect_scheme(host, port)

    netloc = host if port is None else f"{host}:{port}"
    base_url = f"{scheme}://{netloc}{path.rstrip('/')}"

    return Target(
        input=original,
        hostname=hostname,
        ip=ip_value,
        scheme=scheme,
        port=port,
        base_url=base_url,
        is_ip=is_ip,
        root_domain=_root_domain(host),
    )


def detect_scheme(host: str, port: Optional[int] = None, timeout: float = 3.0) -> str:
    """Return 'https' if TLS port responds, else 'http'."""
    probe_port = port or 443
    try:
        with socket.create_connection((host, probe_port), timeout=timeout):
            return "https" if probe_port in (443, 8443) else "http"
    except OSError:
        pass
    try:
        with socket.create_connection((host, 80), timeout=timeout):
            return "http"
    except OSError:
        pass
    return "https"


def resolve_host(host: str) -> List[str]:
    """Resolve A/AAAA records with a short timeout."""
    try:
        infos = socket.getaddrinfo(host, None)
        addresses = []
        for info in infos:
            addr = info[4][0]
            if addr not in addresses:
                addresses.append(addr)
        return addresses
    except (socket.gaierror, UnicodeError):
        return []


def port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ----------------------------------------------------------------- process exec
@dataclass
class ProcessOutcome:
    command: str
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False


def run_command(
    args: List[str],
    timeout: int = 300,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    input_text: Optional[str] = None,
) -> ProcessOutcome:
    """Execute a command capturing stdout/stderr with a hard timeout."""
    started = time.time()
    pretty = " ".join(args)
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=merged_env,
            input=input_text,
            errors="replace",
        )
        return ProcessOutcome(
            command=pretty,
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            duration=time.time() - started,
        )
    except subprocess.TimeoutExpired as exc:
        return ProcessOutcome(
            command=pretty,
            returncode=-1,
            stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
            stderr=f"timeout after {timeout}s",
            duration=time.time() - started,
            timed_out=True,
        )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return ProcessOutcome(
            command=pretty,
            returncode=-2,
            stdout="",
            stderr=str(exc),
            duration=time.time() - started,
        )


def truncate(text: str, limit: int = 8000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated {len(text) - limit} chars]"


__all__ = [
    "current_platform",
    "is_root",
    "which",
    "parse_target",
    "detect_scheme",
    "resolve_host",
    "port_open",
    "run_command",
    "ProcessOutcome",
    "truncate",
]
