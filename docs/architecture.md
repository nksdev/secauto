# SecAuto Architecture

Built by **Naman Kumar Sonker (@nksdev)**.

## Layered design

CLI (cli.py) -> ScanEngine (engine.py) -> ToolManager + ScannerRegistry + Reporting.

Every layer depends only on the layer below it. models.py, config.py, logger.py and utils.py are leaf modules.

Bootstrap sits beside the CLI as a pre-flight step: it depends on config.py,
logger.py and tooling.py, and nothing depends on it except `cli.main()`.

## Startup sequence

    main()
      -> activate_pylibs()          # put .secauto-home/pylibs on sys.path / PYTHONPATH
      -> argparse                   # parse the command and its flags
      -> _auto_bootstrap(args)      # first-run provisioning, unless suppressed
      -> COMMANDS[command](args)    # the actual handler

`_auto_bootstrap` returns immediately when any of the following hold:

- `args.command` is in `SKIP_AUTO_BOOTSTRAP` (`bootstrap`, `install`, `tools`,
  `scanners`, `config`, `doctor`)
- `scan` was called with `--no-install`
- `Config.offline` is true (`SECAUTO_OFFLINE=1`)
- `SECAUTO_AUTO_INSTALL=0` is set

Otherwise it constructs a `Bootstrapper` and calls `run()` when
`should_run()` is true. Failures are logged, never fatal: the requested command
always proceeds, and the Python-native scanners keep working.

## Data flow

raw input -> parse_target() -> Target -> ScanContext -> for phase in PHASES -> ScanResult(findings) -> ScanReport -> risk_score + posture -> reporters.

## Scanner contract

Subclass BaseScanner, set name/category/description/requires, implement scan(result) returning List[Finding]. BaseScanner.execute() handles timing, status and exception containment.

## Execution phases

1. dns_recon, whois, tls_certificate, http_recon
2. port_scan_python, nmap, subfinder, dns_bruteforce, amass
3. whatweb, wafw00f, sensitive_paths, nikto
4. sslyze, testssl, nuclei, vuln_correlate

## Risk scoring

CRITICAL 40, HIGH 20, MEDIUM 8, LOW 3, INFO 1. Bands: LOW < 30, MODERATE < 55, HIGH < 80, CRITICAL >= 80.

## Tool management

TOOL_REGISTRY declares category, required flag and per-package-manager install strategies. ToolManager probes PATH and the managed tools dir, then installs via brew/apt/dnf/pacman/winget/choco, pipx/pip, go install or git clone.

## Bootstrap subsystem

`bootstrap.py` owns first-run provisioning and its persisted state.

- `state_path()` -> `<app_home>/bootstrap.json`
- `BootstrapState` is a dataclass with `version`, `completed`, `completed_at`,
  `last_attempt_at`, `installed`, `failed`, `skipped`, `platform`.
  `load()` returns defaults for a missing file, a corrupt file or an unknown
  `version`. `save()` writes JSON with sorted lists so the file is stable in
  version control and diffs are meaningful.
- `Bootstrapper.is_complete()` requires `state.completed` **and** that no
  `required` tool has since gone missing.
- `Bootstrapper.should_run(force)` is false when offline, true when forced, and
  otherwise the negation of `is_complete()`.
- `Bootstrapper.run(force, quiet)` discovers every tool, records what is already
  present as `installed`, installs the remainder one at a time (an exception in
  one installer never aborts the run), re-discovers, then writes the final
  partition of `installed` / `failed` / `skipped` and sets `completed` when no
  required tool is missing.

Because `installed` is recomputed from discovery rather than from the install
loop, running `bootstrap` on a machine that is already fully provisioned is a
no-op that rewrites the state file and reports `All tools already present`.

## Endpoint-protection posture

The design deliberately avoids the patterns endpoint security flags in
scanners: no `shell=True` (every process is spawned from an argument list), no
`eval`/`exec` of dynamic strings, no `__import__` for runtime module loading, no
`ctypes.windll.shell32` privilege probe (the Windows admin check reads the
process token through `advapi32`/`kernel32`), and no encoded or self-modifying
payloads. Downloads are confined to `.secauto-home/` so a single directory
exclusion in the antivirus console covers the whole footprint.

## Extension points

Add a scanner: drop a module in secauto/scanners and import it in __init__.py. Add a tool: append a ToolSpec. Add a report format: subclass BaseReporter. Add a CLI command: add a cmd_ function.
