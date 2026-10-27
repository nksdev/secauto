# SecAuto

**Autonomous offensive security and reconnaissance platform.**

Built by **Naman Kumar Sonker (@nksdev)**.

SecAuto turns a single URL, hostname or IP address into a complete security
assessment: it discovers the external toolset, installs whatever is missing,
runs reconnaissance, port scanning, TLS analysis, web misconfiguration checks
and vulnerability correlation, then writes a prioritised report in HTML, JSON,
Markdown and CSV.

```bash
secauto scan https://example.com -y --authorized --open
```

---

## Table of contents

- [Highlights](#highlights)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Command reference](#command-reference)
- [Scanner modules](#scanner-modules)
- [How a scan runs](#how-a-scan-runs)
- [Reports](#reports)
- [Configuration](#configuration)
- [Antivirus and endpoint protection](#antivirus-and-endpoint-protection)
- [Troubleshooting](#troubleshooting)
- [Project layout](#project-layout)
- [Development](#development)
- [Legal](#legal)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

---

## Highlights

- **Self-provisioning.** On first launch SecAuto detects your package manager
  (Homebrew, apt, dnf, pacman, winget, Chocolatey, pipx, `go install`, git) and
  installs Nmap, Nikto, Nuclei, Subfinder, Amass, testssl.sh, WhatWeb, Wafw00f,
  SSLyze and searchsploit for you. No manual setup step.
- **Works without external tools.** Twelve of the seventeen scanners are pure
  Python, so a fresh checkout still produces a useful report with zero
  third-party dependencies.
- **17 scanner modules** across recon, subdomain enumeration, network, web, TLS
  and vulnerability correlation, executed in four dependency-ordered phases.
- **Zero mandatory third-party packages.** Python 3.10+ standard library only.
- **Cross-platform.** Windows, Linux and macOS from one codebase.
- **Professional reporting.** HTML dashboard, machine-readable JSON, Markdown
  and CSV, plus a colourised terminal summary.
- **Safe by default.** Explicit authorisation gate, passive-first ordering,
  per-tool timeouts, `subprocess` without a shell, and no destructive payloads.
- **Sandbox friendly.** If your home directory is not writable, all runtime
  state, tools and reports fall back to `./.secauto-home` inside the repo.
- **Quiet to endpoint protection.** No `shell=True`, no dynamic code execution,
  no obfuscation. See [antivirus notes](#antivirus-and-endpoint-protection).

---

## Requirements

| Requirement | Detail |
| --- | --- |
| Python | 3.10 or newer (3.12+ recommended) |
| OS | Windows 10+, macOS 12+, or any modern Linux |
| Disk | ~20 MB for SecAuto, up to ~500 MB if every external tool installs |
| Network | Needed for the first-run tool download and for scanning |

External tools are **optional**. SecAuto degrades gracefully: a missing binary
marks its scanner `skipped` and the rest of the scan continues.

---

## Installation

### One-command bootstrap (recommended)

Linux / macOS:

```bash
git clone https://github.com/nksdev/secauto.git
cd secauto
./install/install.sh
```

Windows (PowerShell):

```powershell
git clone https://github.com/nksdev/secauto.git
cd secauto
.\install\install.ps1
```

The installer verifies Python, compiles the package, initialises the runtime
home and then runs `secauto bootstrap --force` to download the toolset. Pass
`--no-tools` (or `-NoTools`) to skip the download.

### pip

```bash
pip install .          # or: pip install -e . for development
```

This places a `secauto` console script on your `PATH`.

### Run in place, no install

```bash
python3 -m secauto scan example.com -y --authorized
```

### Installation methods compared

| Method | Command | Installs tools? |
| --- | --- | --- |
| Bootstrap script | `./install/install.sh` | Yes |
| pip (editable) | `pip install -e .` | On first scan |
| pip (wheel) | `pip install .` | On first scan |
| Run in place | `python3 -m secauto ...` | On first scan |
| Launcher script | `./bin/secauto` / `bin\secauto.cmd` | On first scan |

Every entry point auto-bootstraps on first use, so the script is a convenience
rather than a requirement.

---

## Quick start

```bash
# 1. Scan a domain (bootstraps the toolset on the first run)
./bin/secauto scan example.com -y --authorized

# 2. Reports land here
ls .secauto-home/reports/
```

Common variations:

```bash
# Bare IP address
./bin/secauto scan 1.1.1.1 -y --authorized

# Full URL, custom output directory, HTML + JSON only
./bin/secauto scan https://example.com -y --authorized -f html,json -o ~/Desktop/reports

# Open the HTML report when the scan finishes
./bin/secauto scan example.com -y --authorized --open

# Passive reconnaissance only (fast, non-intrusive)
./bin/secauto scan example.com -y --authorized --passive

# Only the TLS scanners
./bin/secauto scan example.com -y --authorized --only tls

# Everything except Nmap and Nuclei
./bin/secauto scan example.com -y --authorized --skip nmap,nuclei

# Retry the tool download in isolation
./bin/secauto bootstrap --force

# Inspect what is installed
./bin/secauto doctor
./bin/secauto tools
```

### The `-y --authorized` flags

Without them SecAuto prints a consent notice and requires you to type `YES`.
Both flags together assert that you are authorised to test the target. Use them
only against systems you own or have written permission to test.

---

## Command reference

```
secauto [--version] [-v] [-q] [--no-color] [--config FILE] <command> [options]
```

Global flags:

| Flag | Description |
| --- | --- |
| `--version` | Print the version and exit |
| `-v, --verbose` | Increase verbosity (repeatable) |
| `-q, --quiet` | Suppress non-essential output |
| `--no-color` | Disable ANSI colours |
| `--config FILE` | Use a specific configuration file |

### `scan`

```
secauto scan <target> [options]
```

| Option | Description |
| --- | --- |
| `-o, --output DIR` | Directory for generated reports |
| `-f, --formats LIST` | Comma separated: `html,json,markdown,csv` |
| `--only LIST` | Run only these scanners (names or categories) |
| `--skip LIST` | Skip these scanners |
| `--timeout N` | Per-tool timeout in seconds |
| `--concurrency N` | Scanners executed in parallel |
| `--passive` | Passive reconnaissance only |
| `--aggressive` | Enable more intrusive checks |
| `--no-install` | Never attempt tool installation |
| `-y, --yes` | Skip the interactive consent prompt |
| `--authorized` | Pre-confirm authorisation |
| `--open` | Open the HTML report when finished |

### `bootstrap`

```
secauto bootstrap [--force] [--quiet]
```

Provisions the external toolset and writes `.secauto-home/bootstrap.json`. It
runs automatically before `scan` when the state file says provisioning is
incomplete, so a first scan is a single command.

| Option | Description |
| --- | --- |
| `--force` | Re-run even if a previous bootstrap completed |
| `--quiet` | Suppress per-tool progress output |

Auto-bootstrap is suppressed when any of these apply:

- the command is `bootstrap`, `install`, `tools`, `scanners`, `config` or `doctor`
- `--no-install` was passed to `scan`
- `SECAUTO_OFFLINE=1` is set
- `SECAUTO_AUTO_INSTALL=0` is set

In every suppressed case the Python-native scanners still run, so you always
get a report.

### `install`

```
secauto install [tool ...] [--list]
```

Installs the whole toolset, or only the named tools. `--list` prints the
inventory without installing anything.

### `tools`

```
secauto tools [--json]
```

Shows every known tool, its category, resolved path and detected version.

### `scanners`

```
secauto scanners [--json]
```

Lists the registered scanner modules, their category and required tools.

### `config`

```
secauto config [--json] [--set KEY VALUE ...] [--reset]
```

Reads or updates the persistent configuration file.

### `doctor`

```
secauto doctor
```

Prints platform details, tool health, module counts and remediation advice.

---

## Scanner modules

| Scanner | Category | Requires | Purpose |
| --- | --- | --- | --- |
| `dns_recon` | recon | built-in | DNS records, SPF/DMARC, nameserver posture |
| `whois` | recon | built-in | Registrar, creation age, expiry |
| `http_recon` | http | built-in | Security headers, cookies, information leaks |
| `tls_certificate` | tls | built-in | Certificate validity, expiry, protocol support |
| `subfinder` | subdomain | subfinder | Passive subdomain enumeration |
| `amass` | subdomain | amass | Attack-surface enumeration |
| `dns_bruteforce` | subdomain | built-in | DNS brute force |
| `nmap` | network | nmap | Service and version detection |
| `port_scan_python` | network | built-in | TCP connect scan |
| `nikto` | web | nikto | Web server misconfiguration |
| `nuclei` | vulnerability | nuclei | Template-based vulnerability detection |
| `whatweb` | web | whatweb | Technology fingerprinting |
| `wafw00f` | web | wafw00f | WAF detection |
| `sensitive_paths` | web | built-in | Exposed files and endpoints |
| `testssl` | tls | testssl | Deep TLS configuration analysis |
| `sslyze` | tls | sslyze | TLS scanning (Python) |
| `vuln_correlate` | vulnerability | built-in | Version to CVE mapping, searchsploit lookup |

**Built-in** scanners need no external binary and always run.

---

## How a scan runs

1. **Target parsing** -- normalises the input into scheme, host, port and root
   domain, and resolves the IP address.
2. **Tool discovery** -- probes `PATH`, the managed tools directory and known
   install locations; optionally installs what is missing.
3. **Phase 1 -- passive reconnaissance.** DNS, WHOIS, HTTP and TLS certificate.
   Cheap, non-intrusive, and it populates the shared context.
4. **Phase 2 -- attack surface.** Port scanning, subdomain enumeration.
5. **Phase 3 -- web assessment.** Technology fingerprinting, WAF detection,
   sensitive path probing, Nikto.
6. **Phase 4 -- deep analysis.** SSLyze, testssl.sh, Nuclei, vulnerability
   correlation against the collected banners.
7. **Scoring.** Findings are fingerprinted, de-duplicated and weighted into a
   0-100 risk score with a posture band.
8. **Reporting.** HTML, JSON, Markdown and CSV, plus raw tool output preserved
   next to the reports.

Risk scoring weights: `CRITICAL 40`, `HIGH 20`, `MEDIUM 8`, `LOW 3`, `INFO 1`.
Bands: `LOW < 30`, `MODERATE < 55`, `HIGH < 80`, `CRITICAL >= 80`.

---

## Reports

Each scan writes into its own directory under the output root:

```
.secauto-home/reports/<scan-id>/
|-- report.html          standalone dashboard (no external assets)
|-- report.json          full machine-readable result
|-- report.md            Markdown summary
|-- report.csv           one row per finding
`-- <scan-id>-raw/       verbatim stdout/stderr from every external tool
```

The raw directory is deliberately kept: when a finding looks surprising you can
read exactly what the underlying tool printed.

Every report carries the generator attribution
`SecAuto <version> by Naman Kumar Sonker (NKS)`.

---

## Configuration

Configuration is JSON, loaded from `~/.secauto/config.json` (or
`./.secauto-home/config.json` when the home directory is not writable), and can
be overridden by environment variables.

| Variable | Effect |
| --- | --- |
| `SECAUTO_HOME` | Override the runtime home directory |
| `SECAUTO_CONCURRENCY` | Default parallelism |
| `SECAUTO_TIMEOUT` | Default per-tool timeout |
| `SECAUTO_OUTPUT_DIR` | Default report directory |
| `SECAUTO_VERBOSITY` | `0` quiet ... `3` debug |
| `SECAUTO_NO_COLOR` | Disable ANSI colours |
| `SECAUTO_OFFLINE` | Prevent network tool installation |
| `SECAUTO_AUTO_INSTALL` | Set to `0` to disable automatic installation |
| `SECAUTO_PYTHON` | Interpreter used by the launcher scripts |

Runtime layout:

```
.secauto-home/
|-- bootstrap.json       provisioning state (installed / failed / skipped)
|-- config.json          persisted configuration
|-- bin/                 pip-installed console scripts (wafw00f, ...)
|-- pylibs/              pip --target site-packages (sslyze, ...)
|-- tools/               git-cloned and pipx-managed tools
`-- reports/             scan output
```

---

## Antivirus and endpoint protection

SecAuto is a security scanner, and scanners do things that endpoint protection
is designed to notice: TCP connection sweeps, HTTP path probing, subprocess
execution and tool downloads. **A detection is expected; it is not a
compromise.** The code contains no persistence, no credential access, no
obfuscation, no `shell=True`, and no hidden payloads.

If your antivirus quarantines the tool or slows a scan to a crawl:

**1. Exclude the project directory.** Add both the checkout and the runtime
home to your allow-list:

```
<checkout>/security-automation
<checkout>/security-automation/.secauto-home
```

On Windows use the equivalent paths, for example:
`C:\Tools\secauto` and `C:\Tools\secauto\.secauto-home`.

**2. Exclude the download directory.** Freshly written binaries are the most
common false positive. Allow-list `.secauto-home/tools`, `.secauto-home/bin`
and `.secauto-home/pylibs` before running `bootstrap`, so scan-time real-time
inspection does not fight the installer.

**3. Reduce noise during a scan.** Real-time protection inspecting every
socket operation can multiply scan time. Either exclude the SecAuto process, or
run scans with a lower concurrency:

```bash
./bin/secauto scan example.com -y --authorized --concurrency 4
```

**4. Skip the download if you already trust your toolset.**

```bash
./bin/secauto scan example.com -y --authorized --no-install
```

**5. Verify what you are running.** Everything is plain Python source, no
compiled blobs:

```bash
grep -rn 'shell=True' secauto/ || echo 'no shell invocation'
grep -rn 'exec(\|eval(' secauto/ || echo 'no dynamic code execution'
```

**6. Report a false positive to your vendor.** Include the file path and the
detection name. Vendors normally clear scanner false positives within a few
days once a sample is submitted.

If a scan is blocked entirely by a proxy or gateway, set `SECAUTO_OFFLINE=1`
and re-run -- offline mode skips all downloads and keeps the built-in Python
scanners working.

### What SecAuto deliberately avoids

These patterns are common antivirus heuristics, and none of them appear in the
codebase:

- no `shell=True` -- every process is spawned from an argument list
- no `exec()` or `eval()` of dynamic strings
- no `__import__()` for runtime module loading
- no `ctypes.windll.shell32` privilege probes (the Windows admin check reads the
  process token instead)
- no packed, encoded or self-modifying payloads
- no persistence, registry writes or scheduled tasks

---

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `no Python 3 interpreter found` | Python not on `PATH` | Install Python 3.10+ or set `SECAUTO_PYTHON` |
| `Homebrew is not writable` | Homebrew prefix owned by root | `sudo chown -R $USER /opt/homebrew` |
| Tools show `missing` | Package manager blocked | Run `secauto bootstrap --force` and read the per-tool output |
| `ModuleNotFoundError: sslyze` | Managed `pylibs` not on the path | Handled automatically; ensure you launch via `bin/secauto` or `python -m secauto` |
| Scan is very slow | Concurrency too high for the network, or AV inspection | Lower `--concurrency`, exclude SecAuto in your AV |
| `permission denied` on `bin/secauto` | Executable bit lost when copying | `chmod +x bin/secauto install/install.sh` |
| Report directory unwritable | Home directory not writable | Set `SECAUTO_HOME` to a writable path |

Deeper diagnosis:

```bash
./bin/secauto doctor        # environment, tool health, module counts
./bin/secauto tools --json  # machine-readable tool inventory
```

---

## Project layout

```
secauto/
|-- bootstrap.py        first-run toolset provisioning
|-- cli.py              command line interface
|-- config.py           configuration model, persistence, pylibs activation
|-- engine.py           phase-ordered scan orchestration
|-- logger.py           colourised, levelled logging
|-- models.py           Finding, ScanResult, ScanReport, Target, Severity
|-- tooling.py          tool registry, discovery and installation
|-- utils.py            platform, networking and process helpers
|-- version.py          product metadata and ASCII banner
|-- scanners/           17 scanner modules
`-- reporting/          HTML, JSON, Markdown, CSV and terminal reporters
bin/                    cross-platform launchers
install/                bootstrap installers
docs/                   architecture and usage notes
templates/              standalone HTML report template
tests/                  smoke and unit tests
```

---

## Development

```bash
# Run the test suite
python3 -m unittest discover -s tests -v

# Compile check
python3 -m compileall -q secauto tests

# Exercise a full scan locally
python3 -m secauto --no-color scan example.com -y --authorized \
  --no-install --passive --timeout 20 -o /tmp/secauto-out \
  -f html,json,markdown,csv
```

Adding a scanner: subclass `BaseScanner`, implement
`scan(self, result: ScanResult) -> List[Finding]`, and decorate the class with
`@register`. The engine picks it up automatically and the `scanners` command
lists it.

Adding a tool: append a `ToolSpec` to `TOOL_REGISTRY` in `secauto/tooling.py`
with its `binary`, `category`, `required` flag, install strategies and, where
the tool needs it, explicit `version_flags`.

---

## Legal

SecAuto performs **active** security testing. Only use it against systems you
own or have explicit written permission to test. Unauthorised scanning is
illegal in most jurisdictions. The author accepts no liability for misuse.

---

## Author

**Naman Kumar Sonker** -- [@nksdev](https://github.com/nksdev)

SecAuto Security Labs - MIT licensed.


## Security

See [SECURITY.md](SECURITY.md) for responsible use and vulnerability reporting guidance.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution expectations and test instructions.

## License

This project is distributed under the [MIT License](LICENSE).
