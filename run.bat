@echo off
REM Build (release) and run Shodanify. Just double-click, or:
REM   run.bat            build if needed, then run
REM   run.bat --rebuild  force a fresh release build first
REM Delegates to run.ps1 so the logic lives in one place.
setlocal
cd /d "%~dp0"

set REBUILD=
if /I "%~1"=="--rebuild" set REBUILD=-Rebuild
if /I "%~1"=="-rebuild"  set REBUILD=-Rebuild

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %REBUILD%
endlocal
