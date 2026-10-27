"""Structured console + file logging with ANSI colour and progress helpers."""

from __future__ import annotations

import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional


class Palette:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"
    WHITE = "\033[97m"
    BG_BLUE = "\033[44m"


LEVELS = {
    "debug": (Palette.GREY, "DBG"),
    "info": (Palette.CYAN, "INF"),
    "success": (Palette.GREEN, "OK "),
    "warn": (Palette.YELLOW, "WRN"),
    "error": (Palette.RED, "ERR"),
    "critical": (Palette.MAGENTA, "CRT"),
    "scan": (Palette.BLUE, "SCN"),
}


class Logger:
    """Thread-safe logger with verbosity control and optional file mirroring."""

    def __init__(
        self,
        verbosity: int = 1,
        color: bool = True,
        log_file: Optional[Path] = None,
        stream=None,
    ) -> None:
        self.verbosity = verbosity
        self.color = color and self._stream_is_tty(stream)
        self.stream = stream or sys.stdout
        self.log_file = Path(log_file) if log_file else None
        self._lock = threading.Lock()
        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _stream_is_tty(stream) -> bool:
        try:
            return (stream or sys.stdout).isatty()
        except (AttributeError, ValueError):
            return False

    # ------------------------------------------------------------------ helpers
    def _should_log(self, level: str) -> bool:
        thresholds = {"debug": 3, "info": 1, "success": 1, "scan": 1, "warn": 1, "error": 0, "critical": 0}
        return self.verbosity >= thresholds.get(level, 1)

    def _paint(self, text: str, color: str) -> str:
        if not self.color:
            return text
        return f"{color}{text}{Palette.RESET}"

    def log(self, level: str, message: str, scope: str = "") -> None:
        if not self._should_log(level):
            return
        color, tag = LEVELS.get(level, LEVELS["info"])
        ts = datetime.now().strftime("%H:%M:%S")
        scope_txt = f" [{scope}]" if scope else ""
        line = f"{self._paint(ts, Palette.GREY)} {self._paint(tag, color)} {message}{self._paint(scope_txt, Palette.DIM)}"
        with self._lock:
            try:
                print(line, file=self.stream, flush=True)
            except UnicodeEncodeError:
                print(line.encode("ascii", "replace").decode(), file=self.stream, flush=True)
            if self.log_file:
                plain = f"{datetime.now().isoformat(timespec='seconds')} [{level.upper()}] {message}{scope_txt}"
                with self.log_file.open("a", encoding="utf-8") as fh:
                    fh.write(plain + "\n")

    # -------------------------------------------------------------- public API
    def debug(self, msg: str, scope: str = "") -> None:
        self.log("debug", msg, scope)

    def info(self, msg: str, scope: str = "") -> None:
        self.log("info", msg, scope)

    def success(self, msg: str, scope: str = "") -> None:
        self.log("success", msg, scope)

    def warn(self, msg: str, scope: str = "") -> None:
        self.log("warn", msg, scope)

    def error(self, msg: str, scope: str = "") -> None:
        self.log("error", msg, scope)

    def critical(self, msg: str, scope: str = "") -> None:
        self.log("critical", msg, scope)

    def scan(self, msg: str, scope: str = "") -> None:
        self.log("scan", msg, scope)

    def rule(self, title: str = "") -> None:
        width = 72
        if title:
            pad = max(0, width - len(title) - 2)
            left = pad // 2
            text = f" {title} "
            line = self._paint("─" * left + text + "─" * (width - left - len(text)), Palette.GREY)
        else:
            line = self._paint("─" * width, Palette.GREY)
        with self._lock:
            print(line, file=self.stream, flush=True)

    def kv(self, key: str, value: str, indent: int = 2) -> None:
        pad = " " * indent
        key_txt = self._paint(f"{key}:", Palette.BOLD)
        with self._lock:
            print(f"{pad}{key_txt} {value}", file=self.stream, flush=True)

    def raw(self, text: str) -> None:
        with self._lock:
            print(text, file=self.stream, flush=True)


class Spinner:
    """Minimal terminal spinner for long-running single tasks."""

    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, label: str, enabled: bool = True, stream=None) -> None:
        self.label = label
        self.enabled = enabled
        self.stream = stream or sys.stdout
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _spin(self) -> None:
        idx = 0
        while not self._stop.is_set():
            frame = self.FRAMES[idx % len(self.FRAMES)]
            try:
                self.stream.write(f"\r{Palette.CYAN}{frame}{Palette.RESET} {self.label}")
                self.stream.flush()
            except (ValueError, OSError):
                return
            idx += 1
            time.sleep(0.08)

    def __enter__(self) -> "Spinner":
        if self.enabled:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.3)
        if self.enabled:
            try:
                self.stream.write("\r" + " " * (len(self.label) + 4) + "\r")
                self.stream.flush()
            except (ValueError, OSError):
                pass


__all__ = ["Logger", "Spinner", "Palette"]
