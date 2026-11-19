# Active l'environnement Rust local au projet (equivalent d'un "venv").
# Usage : . .\scripts\activate.ps1
$root = Split-Path -Parent $PSScriptRoot
$env:RUSTUP_HOME = Join-Path $root ".rust\rustup"
$env:CARGO_HOME = Join-Path $root ".rust\cargo"
$bin = Join-Path $env:CARGO_HOME "bin"
if (-not ($env:PATH -split ";" | Where-Object { $_ -eq $bin })) {
    $env:PATH = "$bin;$env:PATH"
}
Write-Host "Environnement Rust local active : $(& "$bin\rustc.exe" --version)"
