#!/usr/bin/env pwsh
[CmdletBinding()]
param(
    [switch]$CheckOllama,
    [switch]$Launch,
    [switch]$OpenBrowser
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Get-PythonCommand {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        return @{ Exe = "py"; Args = @("-3") }
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        return @{ Exe = "python"; Args = @() }
    }
    throw "Python is required but was not found on PATH. Install Python 3.12+ and try again."
}

function Assert-Command([string]$Name, [bool]$Required = $true) {
    if (Get-Command $Name -ErrorAction SilentlyContinue) {
        $version = & $Name --version 2>&1
        Write-Host "${Name}: $version"
        return
    }
    $level = if ($Required) { "required" } else { "optional" }
    Write-Host "${Name}: missing ($level)"
    if ($Required) {
        throw "$Name is required but was not found on PATH."
    }
}

Write-Host "Pengetic Windows bootstrap"
Assert-Command "git" $false
Assert-Command "node" $true
Assert-Command "npm" $true

$Python = Get-PythonCommand
$PythonExe = $Python.Exe
$PythonArgs = $Python.Args
$PythonVersion = & $PythonExe @PythonArgs -c "import sys; print(sys.version.split()[0])"
Write-Host "python: $PythonVersion"
& $PythonExe @PythonArgs -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)"
if ($LASTEXITCODE -ne 0) {
    throw "Python 3.12 or newer is required."
}

$VenvDir = Join-Path $Root ".venv"
if (-not (Test-Path $VenvDir)) {
    Write-Host "Creating virtual environment at $VenvDir"
    & $PythonExe @PythonArgs -m venv $VenvDir
}

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    throw "Virtual environment bootstrap failed: $VenvPython was not created."
}

Write-Host "Upgrading pip"
& $VenvPython -m pip install --upgrade pip

Write-Host "Installing Pengetic in editable mode"
& $VenvPython -m pip install -e .

Write-Host "Installing frontend dependencies"
Push-Location (Join-Path $Root "frontend")
try {
    & npm install
    Write-Host "Building frontend production bundle"
    & npm run build
}
finally {
    Pop-Location
}

Write-Host "Running Pengetic doctor"
if ($CheckOllama) {
    & $VenvPython -m pengetic doctor --check-ollama
} else {
    & $VenvPython -m pengetic doctor --no-check-ollama
}

Write-Host ""
Write-Host "Install complete."
Write-Host "Launch Pengetic with:"
Write-Host "  .\scripts\run_pengetic.ps1"
Write-Host "or:"
Write-Host "  $VenvPython -m pengetic serve"
if ($Launch) {
    $runArgs = @("-File", (Join-Path $PSScriptRoot "run_pengetic.ps1"))
    if ($OpenBrowser) {
        $runArgs += "-OpenBrowser"
    }
    & powershell @runArgs
}
