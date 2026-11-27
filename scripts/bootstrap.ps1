<#
  One-time setup of a git-managed FatBox on the VM.
  Run from inside the fresh clone. Migrates config.toml and data\ from an old (zip-based) folder if given.

  powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1 -Migrate ..\fatbox.old
#>
param([string]$Migrate = "")

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw "git not found: winget install --id Git.Git -e" }
$py = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }

if ($Migrate) {
    $old = Resolve-Path $Migrate
    foreach ($item in @("config.toml", "data")) {
        $src = Join-Path $old $item
        if ((Test-Path $src) -and -not (Test-Path (Join-Path $root $item))) {
            Move-Item $src $root
            Write-Host "migrated $item from $old"
        }
    }
}
if (-not (Test-Path "config.toml")) {
    Copy-Item "config.example.toml" "config.toml"
    Write-Host "created config.toml from the example"
}

& $py -m pip install --require-hashes --only-binary :all: -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
& $py -m fatbox --version
Write-Host "`nDone. From now on, to get new code:  python -m fatbox update"
