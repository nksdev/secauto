"""Command line interface for SecAuto."""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path

from .bootstrap import Bootstrapper, state_path as bootstrap_state_path
from .config import Config, activate_pylibs, app_home, default_config_path
from .engine import ScanEngine
from .logger import Logger
from .reporting import available_formats, format_report, write_reports
from .scanners import registry
from .tooling import ToolManager
from .utils import current_platform, is_root
from .version import AUTHOR, AUTHOR_INITIALS, PRODUCT_NAME, __version__, banner_text


CONSENT = (
    "SecAuto performs ACTIVE security testing against the target you supply. "
    "You must hold explicit written authorisation to test it. Unauthorised "
    "scanning is illegal in most jurisdictions and may cause service disruption."
)


def _logger(args) -> Logger:
    verbosity = 0 if getattr(args, "quiet", False) else getattr(args, "verbose", 1)
    return Logger(verbosity=verbosity, color=not getattr(args, "no_color", False))


def _config(args) -> Config:
    cfg = Config.load(Path(args.config) if getattr(args, "config", None) else None)
    for attr in ("output", "timeout", "concurrency"):
        value = getattr(args, attr, None)
        if value:
            setattr(cfg, "output_dir" if attr == "output" else attr, value)
    formats = getattr(args, "formats", None)
    if formats:
        cfg.report_formats = [f.strip() for f in formats.split(",") if f.strip()]
    if getattr(args, "aggressive", False):
        cfg.aggressive = True
    if getattr(args, "passive", False):
        cfg.passive_only = True
    if getattr(args, "no_install", False):
        cfg.auto_install = False
    if getattr(args, "authorized", False):
        cfg.authorized = True
    if getattr(args, "no_color", False):
        cfg.color = False
    return cfg


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secauto",
        description=f"{PRODUCT_NAME} - automated security assessment and reconnaissance platform",
        epilog=f"Built by {AUTHOR} ({AUTHOR_INITIALS}). Test only systems you are authorised to test.",
    )
    parser.add_argument("--version", action="version", version=f"{PRODUCT_NAME} {__version__}")
    parser.add_argument("-v", "--verbose", action="count", default=1, help="increase output verbosity")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress non-essential output")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour output")
    parser.add_argument("--config", help="path to a configuration file")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run a full security assessment against a target")
    scan.add_argument("target", help="URL, hostname, IP address or host:port")
    scan.add_argument("-o", "--output", help="directory for generated reports")
    scan.add_argument(
        "-f", "--formats",
        help="comma separated report formats (%s)" % ",".join(available_formats()),
    )
    scan.add_argument("--only", help="comma separated scanner names to run exclusively")
    scan.add_argument("--skip", help="comma separated scanner names to skip")
    scan.add_argument("--timeout", type=int, help="per-tool timeout in seconds")
    scan.add_argument("--concurrency", type=int, help="number of scanners to run in parallel")
    scan.add_argument("--aggressive", action="store_true", help="enable more intrusive checks")
    scan.add_argument("--passive", action="store_true", help="only run passive reconnaissance")
    scan.add_argument("--no-install", action="store_true", help="never attempt to install missing tools")
    scan.add_argument("--authorized", action="store_true", help="confirm authorisation to test the target")
    scan.add_argument("-y", "--yes", action="store_true", help="skip the interactive consent prompt")
    scan.add_argument("--open", action="store_true", help="open the HTML report when finished")

    bootstrap = sub.add_parser("bootstrap", help="download and install every external tool (first run)")
    bootstrap.add_argument("--force", action="store_true", help="re-run even if a previous bootstrap completed")
    bootstrap.add_argument("--quiet", action="store_true", help="suppress per-tool progress output")

    install = sub.add_parser("install", help="download and install the external toolset")
    install.add_argument("tools", nargs="*", help="specific tool keys to install (default: all)")
    install.add_argument("--list", action="store_true", help="list available tools and exit")

    tools = sub.add_parser("tools", help="show the external tool inventory")
    tools.add_argument("--json", action="store_true", help="emit JSON instead of a table")

    scanners = sub.add_parser("scanners", help="list the built-in scanner modules")
    scanners.add_argument("--json", action="store_true", help="emit JSON instead of a table")

    config = sub.add_parser("config", help="inspect or update persistent configuration")
    config.add_argument("--json", action="store_true", help="print the full configuration as JSON")
    config.add_argument(
        "--set", nargs=2, action="append", metavar=("KEY", "VALUE"), help="set a configuration key"
    )
    config.add_argument("--reset", action="store_true", help="restore factory defaults")

    sub.add_parser("doctor", help="check the environment and tool health")
    return parser


def _consent(logger: Logger, target: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    logger.warn(CONSENT)
    try:
        answer = input(f"Type YES to confirm authorisation for {target}: ")
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer.strip().upper() == "YES"


def _open_path(path: Path) -> None:
    try:
        webbrowser.open(path.resolve().as_uri())
    except Exception:
        pass


def cmd_scan(args) -> int:
    logger = _logger(args)
    cfg = _config(args)
    logger.raw(banner_text(color=cfg.color))
    if not cfg.authorized:
        if not _consent(logger, args.target, args.yes):
            logger.error("Authorisation not confirmed - aborting.")
            return 2
        cfg.authorized = True

    engine = ScanEngine(cfg, logger)
    try:
        engine.prepare()
        only = [s.strip() for s in (args.only or "").split(",") if s.strip()] or None
        skip = [s.strip() for s in (args.skip or "").split(",") if s.strip()] or None
        report = engine.scan(args.target, include=only, exclude=skip)
    except KeyboardInterrupt:
        logger.error("Scan interrupted by user.")
        return 130

    raw_dir = engine.persist_raw(report)
    paths = write_reports(report, Path(cfg.output_dir), formats=cfg.report_formats)

    logger.rule("REPORTS")
    for path in paths:
        logger.kv(path.suffix.lstrip(".").upper(), str(path))
    logger.kv("Raw artefacts", str(raw_dir))
    logger.rule()

    print()
    print(format_report(report, color=cfg.color))

    html_paths = [p for p in paths if p.suffix == ".html"]
    if html_paths and args.open:
        _open_path(html_paths[0])
    return 0


def cmd_bootstrap(args) -> int:
    logger = _logger(args)
    cfg = _config(args)
    if cfg.offline:
        logger.warn("Offline mode is enabled; nothing will be downloaded", scope="bootstrap")
    bootstrapper = Bootstrapper(cfg, logger)
    if not args.force and bootstrapper.is_complete():
        logger.success(
            "Toolset already provisioned; use 'secauto bootstrap --force' to re-run",
            scope="bootstrap",
        )
        return 0
    state = bootstrapper.run(force=args.force, quiet=args.quiet)
    logger.info("Bootstrap state written to %s" % bootstrap_state_path(), scope="bootstrap")
    return 0 if state.completed else 1


def cmd_install(args) -> int:
    logger = _logger(args)
    cfg = _config(args)
    manager = ToolManager(cfg, logger)
    manager.discover(probe_versions=False)
    if args.list:
        manager.print_table()
        return 0
    results = manager.ensure(args.tools, auto=True) if args.tools else manager.install_all()
    manager.discover(probe_versions=True)
    manager.print_table()
    installed = sum(1 for ok in results.values() if ok)
    logger.success("Installation finished: %d/%d tools ready" % (installed, len(results)))
    return 0 if installed else 1


def cmd_tools(args) -> int:
    logger = _logger(args)
    cfg = _config(args)
    manager = ToolManager(cfg, logger)
    states = manager.discover(probe_versions=True)
    if args.json:
        print(json.dumps({k: v.to_dict() for k, v in states.items()}, indent=2))
        return 0
    manager.print_table()
    ready = sum(1 for s in states.values() if s.available)
    logger.info("%d of %d tools available" % (ready, len(states)))
    return 0


def cmd_scanners(args) -> int:
    logger = _logger(args)
    classes = registry.all()
    if args.json:
        payload = [
            {
                "name": cls.name,
                "description": cls.description,
                "category": cls.category,
                "requires": list(getattr(cls, "requires", [])),
            }
            for cls in classes
        ]
        print(json.dumps(payload, indent=2))
        return 0
    print("%-20s %-14s %-10s %s" % ("SCANNER", "CATEGORY", "REQUIRES", "DESCRIPTION"))
    print("-" * 96)
    for cls in sorted(classes, key=lambda c: (c.category, c.name)):
        req = ",".join(getattr(cls, "requires", [])) or "built-in"
        print("%-20s %-14s %-10s %s" % (cls.name, cls.category, req[:10], cls.description))
    print()
    logger.info("%d scanner modules registered" % len(classes))
    return 0


def cmd_config(args) -> int:
    logger = _logger(args)
    path = default_config_path()
    cfg = Config.load(path)
    if args.reset:
        cfg = Config()
        cfg.save(path)
        logger.success("Configuration reset to defaults at %s" % path)
        return 0
    if args.set:
        for key, value in args.set:
            if key not in Config.__dataclass_fields__:
                logger.error("Unknown configuration key: %s" % key)
                return 1
            current = getattr(cfg, key)
            try:
                if isinstance(current, bool):
                    cast = value.lower() in ("1", "true", "yes", "on")
                elif isinstance(current, int):
                    cast = int(value)
                elif isinstance(current, list):
                    cast = [v.strip() for v in value.split(",") if v.strip()]
                else:
                    cast = value
            except ValueError:
                logger.error("Invalid value for %s: %s" % (key, value))
                return 1
            setattr(cfg, key, cast)
        cfg.save(path)
        logger.success("Configuration saved to %s" % path)
    if args.json:
        print(json.dumps(cfg.to_dict(), indent=2))
        return 0
    logger.rule("CONFIGURATION")
    logger.kv("File", str(path))
    logger.kv("Home", str(app_home()))
    for key, value in cfg.to_dict().items():
        logger.kv(key, str(value))
    return 0


def cmd_doctor(args) -> int:
    logger = _logger(args)
    cfg = _config(args)
    logger.raw(banner_text(color=cfg.color))

    logger.rule("ENVIRONMENT")
    logger.kv("Platform", current_platform())
    logger.kv("Python", sys.version.split()[0])
    logger.kv("Executable", sys.executable)
    logger.kv("Privileged", "yes" if is_root() else "no")
    logger.kv("Home", str(app_home()))
    logger.kv("Output dir", cfg.output_dir)

    logger.rule("TOOL HEALTH")
    manager = ToolManager(cfg, logger)
    states = manager.discover(probe_versions=True)
    manager.print_table()

    logger.rule("MODULES")
    logger.kv("Scanners", str(len(registry.all())))
    logger.kv("Reporters", ", ".join(available_formats()))

    missing = [k for k, s in states.items() if s.required and not s.available]
    logger.rule()
    if missing:
        logger.warn("Missing required tools: %s" % ", ".join(missing))
        logger.info("Run 'secauto install' to fetch them.")
        return 1
    logger.success("Environment looks healthy.")
    return 0


COMMANDS = {
    "bootstrap": cmd_bootstrap,
    "scan": cmd_scan,
    "install": cmd_install,
    "tools": cmd_tools,
    "scanners": cmd_scanners,
    "config": cmd_config,
    "doctor": cmd_doctor,
}


SKIP_AUTO_BOOTSTRAP = {"bootstrap", "install", "tools", "scanners", "config", "doctor"}


def _auto_bootstrap(args) -> None:
    """Provision the external toolset automatically on first launch."""
    if getattr(args, "command", None) in SKIP_AUTO_BOOTSTRAP:
        return
    if getattr(args, "no_install", False):
        return
    try:
        logger = _logger(args)
        cfg = _config(args)
        if cfg.offline or not cfg.auto_install:
            return
        bootstrapper = Bootstrapper(cfg, logger)
        if bootstrapper.is_complete():
            return
        logger.rule("FIRST-RUN BOOTSTRAP")
        logger.info(
            "SecAuto is provisioning the external toolset; this happens only once.",
            scope="bootstrap",
        )
        bootstrapper.run(quiet=False)
    except KeyboardInterrupt:
        raise
    except Exception as exc:  # never block a scan because of bootstrap trouble
        print(f"[secauto] bootstrap skipped: {exc}")


def main(argv=None) -> int:
    activate_pylibs()
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = COMMANDS.get(args.command)
    if not handler:
        parser.print_help()
        return 2
    try:
        _auto_bootstrap(args)
        return handler(args)
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
