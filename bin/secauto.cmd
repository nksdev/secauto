@echo off
REM SecAuto launcher - built by Naman Kumar Sonker (@nksdev)
setlocal
set "ROOT=%~dp0.."
pushd "%ROOT%" >nul

set "PYTHON=%SECAUTO_PYTHON%"
if not defined PYTHON (
  where py >nul 2>&1 && set "PYTHON=py -3"
)
if not defined PYTHON (
  where python >nul 2>&1 && set "PYTHON=python"
)
if not defined PYTHON (
  echo secauto: no Python 3 interpreter found on PATH 1>&2
  popd >nul
  exit /b 127
)

%PYTHON% -m secauto %*
set "CODE=%ERRORLEVEL%"
popd >nul
endlocal & exit /b %CODE%
