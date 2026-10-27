<#
.SYNOPSIS
    SecAuto bootstrap installer for Windows.
.DESCRIPTION
    Verifies Python, compiles the SecAuto package and optionally downloads
    the external reconnaissance and vulnerability toolset.
.NOTES
    Built by Naman Kumar Sonker (@nksdev).
#>
[CmdletBinding()]
param(
    [switch]$NoTools,
    [string]$Python = $env:SECAUTO_PYTHON
)

$ErrorActionPreference = "Stop"

function Write-Log  { param($m) Write-Host "[secauto] $m" -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "[  ok  ] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[ warn ] $m" -ForegroundColor Yellow }
function Write-Fail { param($m) Write-Host "[ fail ] $m" -ForegroundColor Red }

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

Write-Host @"
   _____ ______ _____  _    _   _ _______ ____
  / ____|  ____/ ____|/ \  | | | |__   __/ __ \
 | (___ | |__ | |    /   \ | | | |  | | | |  | |
  \___ \|  __|| |   / /_\ \| | | |  | | | |  | |
  ____) | |___| |__/ _____ \ |_| |  | | | |__| |
 |_____/|______\_____/_/   \_\___/   |_|  \____/
"@ -ForegroundColor DarkCyan
Write-Host "  Autonomous Offensive Security Platform - by Naman Kumar Sonker (@nksdev)" -ForegroundColor DarkGray
Write-Host ""

if (-not $Python) {
    $candidates = @("python3.14", "python3.13", "python3.12", "python3.11", "python3.10", "python3", "python", "py")
    foreach ($candidate in $candidates) {
        $found = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($found) { $Python = $found.Source; break }
    }
}

if (-not $Python) {
    Write-Fail "Python 3.10+ is required but was not found on PATH"
    exit 1
}

Write-Log "Project root : $Root"
Write-Log "Interpreter  : $Python"

& $Python -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)"
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Python 3.10 or newer is required"
    exit 1
}
Write-Ok "Python version check passed"

Set-Location $Root

Write-Log "Compiling SecAuto modules ..."
& $Python -m compileall -q secauto | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Warn "compileall reported issues" } else { Write-Ok "Modules compiled" }

Write-Log "Initialising runtime home ..."
& $Python -m secauto doctor --no-color | Out-Null
Write-Ok "Runtime home ready"

if (-not $NoTools) {
    Write-Log "Bootstrapping external toolset (this may take several minutes) ..."
    & $Python -m secauto bootstrap --force
    if ($LASTEXITCODE -ne 0) { Write-Warn "some tools could not be installed; run 'secauto tools' to review" }
} else {
    Write-Warn "Skipping external toolset installation (-NoTools)"
}

Write-Host ""
Write-Ok "SecAuto is ready."
Write-Host "  Launch with: $Root\bin\secauto.cmd scan <target> -y --authorized" -ForegroundColor DarkGray
Write-Host "  Add to PATH: `$env:Path += `";$Root\bin`"" -ForegroundColor DarkGray
Write-Host ""
