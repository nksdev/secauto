# SecAuto Usage Guide

Built by **Naman Kumar Sonker (@nksdev)**.

## Table of contents

- [First run](#first-run)
- [Bootstrap](#bootstrap)
- [Scanning](#scanning)
- [Consent gate](#consent-gate)
- [Tool management](#tool-management)
- [Configuration](#configuration)
- [Antivirus and endpoint protection](#antivirus-and-endpoint-protection)
- [Troubleshooting](#troubleshooting)

## First run

    ./install/install.sh          # Linux / macOS
    .\install\install.ps1         # Windows

The installer verifies Python 3.10+, compiles the package, creates the runtime
home and then runs `secauto bootstrap --force` to download the external
toolset. Use `--no-tools` / `-NoTools` to skip the download.

You do not have to run the installer at all. Every entry point
(`bin/secauto`, `bin\secauto.cmd`, `python -m secauto`, the `secauto` console
script) auto-bootstraps on first use.

## Bootstrap

    secauto bootstrap              # provision anything still missing
    secauto bootstrap --force      # re-provision even if a run already completed
    secauto bootstrap --quiet      # no per-tool progress lines

State is written to `.secauto-home/bootstrap.json` with four lists: `installed`,
`failed`, `skipped` and the platform it was recorded on. The file also carries
the author attribution so a support request can identify the exact build.

The automatic bootstrap runs before `scan` and is suppressed when:

- the command is `bootstrap`, `install`, `tools`, `scanners`, `config` or `doctor`
- `--no-install` was passed to `scan`
- `SECAUTO_OFFLINE=1` is set (offline mode)
- `SECAUTO_AUTO_INSTALL=0` is set

When suppressed, the built-in Python scanners still run, so a scan always
produces a report. Only the external-tool scanners are skipped.

## Scanning

    secauto scan https://example.com -y --authorized
    secauto scan example.com --passive -y --authorized
    secauto scan example.com --only tls -y --authorized
    secauto scan example.com --skip nikto,nuclei -y --authorized
    secauto scan example.com -f html,json -o ./reports -y --authorized
    secauto scan example.com --concurrency 4 --timeout 30 -y --authorized

Reports are named `<scan_id>.<ext>`; raw tool output is preserved in
`<scan_id>-raw/`.

## Consent gate

Without `-y` / `--yes` / `--authorized` SecAuto prints an authorisation warning
and requires you to type `YES`. Both `-y` and `--authorized` assert that you own
the target or have written permission to test it.

## Tool management

    secauto tools                 # inventory table
    secauto tools --json          # machine readable
    secauto install               # install everything missing
    secauto install nmap nuclei   # install specific tools
    secauto install --list        # list without installing

## Configuration

    secauto config                # show current config
    secauto config --json
    secauto config --set concurrency 12
    secauto config --set report_formats html,json
    secauto config --reset

Config lives at `~/.secauto/config.json` when writable, otherwise
`./.secauto-home/config.json`. Override with `SECAUTO_HOME`.

Environment variables that matter during a scan:

| Variable | Effect |
| --- | --- |
| `SECAUTO_HOME` | Runtime home directory |
| `SECAUTO_CONCURRENCY` | Default parallelism |
| `SECAUTO_TIMEOUT` | Default per-tool timeout |
| `SECAUTO_OUTPUT_DIR` | Default report directory |
| `SECAUTO_VERBOSITY` | `0` quiet ... `3` debug |
| `SECAUTO_OFFLINE` | `1` disables all downloads |
| `SECAUTO_AUTO_INSTALL` | `0` disables auto-installation |

## Antivirus and endpoint protection

SecAuto performs reconnaissance, which is exactly the behaviour endpoint
protection is built to watch: TCP sweeps, HTTP path probing, subprocess
execution, and first-run binary downloads. A detection is expected and is not
an indicator of compromise.

To keep scans fast and quiet:

1. Allow-list the checkout and the runtime home:

       <checkout>/security-automation
       <checkout>/security-automation/.secauto-home

2. Allow-list the download directories before bootstrapping:

       .secauto-home/tools
       .secauto-home/bin
       .secauto-home/pylibs

3. Lower parallelism so real-time inspection does not throttle the scan:

       secauto scan example.com -y --authorized --concurrency 4

4. If the toolset is already trusted, skip the download entirely:

       secauto scan example.com -y --authorized --no-install

5. Confirm there is nothing hidden in the code:

       grep -rn 'shell=True' secauto/ || echo 'no shell invocation'
       grep -rn 'exec(\|eval(' secauto/ || echo 'no dynamic code execution'

SecAuto contains no `shell=True`, no `eval`/`exec`, no `__import__`, no
`ctypes.windll.shell32`, no encoded payloads and no persistence.

## Troubleshooting

    secauto doctor                # platform, tool health, module counts
    secauto tools --json          # machine-readable inventory
    secauto -v scan ...           # verbose
    secauto -vv scan ...          # debug

Common issues: missing tool -> `secauto install <tool>` or
`secauto bootstrap --force`; reports in `./.secauto-home` -> home not writable,
set `SECAUTO_HOME`; scanner skipped -> required tool absent; scan hangs -> lower
`--timeout` or use `--passive`; `ModuleNotFoundError: sslyze` -> launch through
`bin/secauto` or `python -m secauto` so managed `pylibs` is on the path.
