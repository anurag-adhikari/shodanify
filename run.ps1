<#
  Build (release) and run Shodanify on Windows.

    .\run.ps1              build if needed, then run
    .\run.ps1 -Rebuild     force a fresh release build first
    $env:PORT=9000; .\run.ps1   override config via env vars (see README)
#>
param([switch]$Rebuild)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# PowerShell sessions don't always inherit the cargo PATH — pull it in.
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("PATH","User")
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Error "cargo not found. Install Rust from https://rustup.rs and re-run."
}

$bin = "target\release\shodanify.exe"

if ($Rebuild -or -not (Test-Path $bin)) {
    Write-Host "==> Building release binary..." -ForegroundColor Cyan
    # Stop a running instance so the linker can overwrite the locked .exe.
    Get-Process shodanify -ErrorAction SilentlyContinue | Stop-Process -Force
    cargo build --release
    if ($LASTEXITCODE -ne 0) { Write-Error "Build failed." }
}

$bindHost = if ($env:HOST) { $env:HOST } else { "127.0.0.1" }
$port     = if ($env:PORT) { $env:PORT } else { "8080" }
Write-Host "==> Starting Shodanify  (http://${bindHost}:${port})" -ForegroundColor Green
& ".\$bin"
