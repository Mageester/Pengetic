#!/usr/bin/env pwsh
[CmdletBinding()]
param(
    [switch]$OpenBrowser,
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 8000,
    [switch]$Reload
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
if (Test-Path $VenvPython) {
    $Python = $VenvPython
    $PythonArgs = @()
}
elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $Python = "python"
    $PythonArgs = @()
}
elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $Python = "py"
    $PythonArgs = @("-3")
}
else {
    throw "Python is required. Run scripts/install_windows.ps1 first."
}

if ($OpenBrowser) {
    $browserHost = if ($BindHost -in @("0.0.0.0", "::")) { "127.0.0.1" } else { $BindHost }
    Start-Process "http://$browserHost`:$Port/"
}

$serveArgs = @("-m", "pengetic", "serve", "--host", $BindHost, "--port", $Port)
if ($Reload) {
    $serveArgs += "--reload"
}
else {
    $serveArgs += "--no-reload"
}
$serveArgs += "--no-open-browser"
& $Python @PythonArgs @serveArgs
