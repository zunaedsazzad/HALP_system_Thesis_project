# HALP Circuit Build Script for Windows
# This script compiles the circuit, runs trusted setup, and exports keys
#
# Prerequisites:
#   1. Rust and Cargo installed (https://rustup.rs/)
#   2. Circom compiler installed via Cargo:
#      git clone https://github.com/iden3/circom.git
#      cd circom
#      cargo build --release
#      cargo install --path circom
#   3. Node.js 18+ and npm installed
#
# For production: Use Hermez Powers of Tau files from:
# https://github.com/iden3/snarkjs#7-prepare-phase-2

param(
    [switch]$Clean,
    [switch]$SkipSetup,
    [switch]$SkipPtau,
    [switch]$UseHermezPtau,
    [int]$PtauPower = 16,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildDir = Join-Path $ScriptDir "build"

# Hermez trusted setup files (production-grade)
$HermezPtauUrl = "https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_16.ptau"
$HermezPtauFile = "powersOfTau28_hez_final_16.ptau"

function Show-Help {
    Write-Host @"
HALP Circuit Build Script
=========================

Usage: .\build-circuit.ps1 [options]

Options:
    -Clean          Clean build directory before building
    -SkipSetup      Skip trusted setup (use existing ptau/zkey)
    -SkipPtau       Skip Powers of Tau generation (use existing)
    -UseHermezPtau  Download production Hermez Powers of Tau (recommended)
    -PtauPower N    Powers of Tau size 2^N (default: 16, supports ~65K constraints)
    -Help           Show this help message

Prerequisites (IMPORTANT):
    1. Install Rust via rustup:
       - Windows: Download rustup-init.exe from https://rustup.rs/
       - Run it and follow prompts
       - Restart terminal after installation

    2. Install Circom compiler from source:
       git clone https://github.com/iden3/circom.git
       cd circom
       cargo build --release
       cargo install --path circom
       
       Verify: circom --version

    3. Node.js 18+ and npm installed
       Verify: node --version && npm --version

Steps performed:
    1. Check prerequisites (Node, npm, Circom)
    2. Install npm dependencies (circomlib, snarkjs)
    3. Compile Circom circuit to R1CS + WASM
    4. Download/Generate Powers of Tau
    5. Run Groth16 trusted setup (Phase 2)
    6. Export keys to wallet-sdk and verifier-service

For Production:
    Use -UseHermezPtau flag to download production-grade Powers of Tau
    from the Hermez trusted setup ceremony (recommended for security).

"@
}

function Test-Prerequisites {
    Write-Host "`n[Checking Prerequisites]" -ForegroundColor Cyan
    
    # Check Node.js
    try {
        $nodeVersion = node --version
        Write-Host "  Node.js: $nodeVersion" -ForegroundColor Green
    } catch {
        Write-Host "  Node.js: NOT FOUND" -ForegroundColor Red
        Write-Host "  Please install Node.js from https://nodejs.org" -ForegroundColor Yellow
        exit 1
    }
    
    # Check npm
    try {
        $npmVersion = npm --version
        Write-Host "  npm: $npmVersion" -ForegroundColor Green
    } catch {
        Write-Host "  npm: NOT FOUND" -ForegroundColor Red
        exit 1
    }
    
    # Check Circom (must be installed via Cargo, not npm)
    try {
        $circomOutput = circom --version 2>&1
        Write-Host "  Circom: $circomOutput" -ForegroundColor Green
    } catch {
        Write-Host "  Circom: NOT FOUND" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Circom must be installed from source using Rust/Cargo:" -ForegroundColor Yellow
        Write-Host "    1. Install Rust: https://rustup.rs/" -ForegroundColor Yellow
        Write-Host "    2. Clone circom: git clone https://github.com/iden3/circom.git" -ForegroundColor Yellow
        Write-Host "    3. Build: cd circom && cargo build --release" -ForegroundColor Yellow
        Write-Host "    4. Install: cargo install --path circom" -ForegroundColor Yellow
        Write-Host ""
        exit 1
    }
    
    # Check snarkjs (will be installed locally, but check global for convenience)
    try {
        $snarkjsVersion = npx snarkjs --version 2>&1
        Write-Host "  snarkjs: available via npx" -ForegroundColor Green
    } catch {
        Write-Host "  snarkjs: Will be installed with npm" -ForegroundColor Yellow
    }
}

function Install-Dependencies {
    Write-Host "`n[Installing Dependencies]" -ForegroundColor Cyan
    Push-Location $ScriptDir
    
    if (-not (Test-Path "node_modules")) {
        npm install
    } else {
        Write-Host "  Dependencies already installed" -ForegroundColor Green
    }
    
    Pop-Location
}

function Compile-Circuit {
    Write-Host "`n[Compiling Circuit]" -ForegroundColor Cyan
    
    # Create build directory
    if (-not (Test-Path $BuildDir)) {
        New-Item -ItemType Directory -Path $BuildDir | Out-Null
    }
    
    $circomFile = Join-Path $ScriptDir "halp-auth.circom"
    
    Write-Host "  Source: halp-auth.circom" -ForegroundColor White
    Write-Host "  Compiling with circom 2.1.6+ ..." -ForegroundColor White
    Write-Host "  (This generates R1CS constraints, WASM witness calculator, and symbols)" -ForegroundColor Gray
    
    # Compile with circom - use -l flag to specify library path for includes
    Push-Location $ScriptDir
    
    # Run circom with proper flags:
    # --r1cs: Generate R1CS constraint system
    # --wasm: Generate WASM witness calculator  
    # --sym: Generate symbol file for debugging
    # -o build: Output directory
    # -l node_modules: Library path for circomlib includes
    $compileCmd = "circom halp-auth.circom --r1cs --wasm --sym -o build -l node_modules"
    Write-Host "  Command: $compileCmd" -ForegroundColor Gray
    
    Invoke-Expression $compileCmd
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  Compilation failed!" -ForegroundColor Red
        Pop-Location
        exit 1
    }
    
    Pop-Location
    
    # Verify outputs
    $r1csFile = Join-Path $BuildDir "halp-auth.r1cs"
    $wasmDir = Join-Path $BuildDir "halp-auth_js"
    
    if ((Test-Path $r1csFile) -and (Test-Path $wasmDir)) {
        $r1csSize = (Get-Item $r1csFile).Length / 1KB
        Write-Host "  R1CS generated: $([math]::Round($r1csSize, 1)) KB" -ForegroundColor Green
        Write-Host "  WASM generated: $wasmDir" -ForegroundColor Green
    } else {
        Write-Host "  Compilation outputs not found!" -ForegroundColor Red
        exit 1
    }
}

function Run-TrustedSetup {
    Write-Host "`n[Running Trusted Setup]" -ForegroundColor Cyan
    
    Push-Location $ScriptDir
    
    # Build the command with appropriate flags
    $setupArgs = @()
    
    if ($UseHermezPtau) {
        Write-Host "  Using Hermez production Powers of Tau (recommended for production)" -ForegroundColor Yellow
        $setupArgs += "--hermez"
    } elseif ($SkipPtau) {
        Write-Host "  Skipping PTAU generation (using existing file)" -ForegroundColor Yellow
        $setupArgs += "--skip-ptau"
    } else {
        Write-Host "  Generating local Powers of Tau (2^$PtauPower)" -ForegroundColor Yellow
        Write-Host "  Note: For production, use -UseHermezPtau flag" -ForegroundColor Gray
        $setupArgs += "--power=$PtauPower"
    }
    
    Write-Host "  This may take several minutes..." -ForegroundColor Yellow
    
    $argsString = $setupArgs -join " "
    $command = "node scripts/trusted-setup.js $argsString"
    Write-Host "  Command: $command" -ForegroundColor Gray
    
    Invoke-Expression $command
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  Trusted setup failed!" -ForegroundColor Red
        Pop-Location
        exit 1
    }
    
    Pop-Location
}

function Export-Keys {
    Write-Host "`n[Exporting Keys]" -ForegroundColor Cyan
    
    Push-Location $ScriptDir
    node scripts/export-keys.js
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  Key export failed!" -ForegroundColor Red
        Pop-Location
        exit 1
    }
    
    Pop-Location
}

function Clean-Build {
    Write-Host "`n[Cleaning Build Directory]" -ForegroundColor Cyan
    
    if (Test-Path $BuildDir) {
        Remove-Item -Recurse -Force $BuildDir
        Write-Host "  Removed: $BuildDir" -ForegroundColor Green
    }
    
    # Also clean target directories
    $walletCircuits = Join-Path $ScriptDir ".." "wallet-sdk" "circuits"
    $verifierCircuits = Join-Path $ScriptDir ".." "verifier-service" "circuits"
    
    if (Test-Path $walletCircuits) {
        Remove-Item -Recurse -Force $walletCircuits
        Write-Host "  Removed: wallet-sdk/circuits" -ForegroundColor Green
    }
    
    if (Test-Path $verifierCircuits) {
        Remove-Item -Recurse -Force $verifierCircuits
        Write-Host "  Removed: verifier-service/circuits" -ForegroundColor Green
    }
}

# Main execution
if ($Help) {
    Show-Help
    exit 0
}

Write-Host ""
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "  HALP Authentication Circuit Builder" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan

Write-Host "`nConfiguration:" -ForegroundColor White
Write-Host "  Clean build:     $Clean"
Write-Host "  Skip setup:      $SkipSetup"
Write-Host "  Skip PTAU:       $SkipPtau"
Write-Host "  Use Hermez PTAU: $UseHermezPtau"
Write-Host "  PTAU Power:      2^$PtauPower"

if ($Clean) {
    Clean-Build
}

Test-Prerequisites
Install-Dependencies
Compile-Circuit

if (-not $SkipSetup) {
    Run-TrustedSetup
}

Export-Keys

Write-Host ""
Write-Host "=" * 70 -ForegroundColor Green
Write-Host "  BUILD COMPLETE!" -ForegroundColor Green
Write-Host "=" * 70 -ForegroundColor Green
Write-Host @"

Generated files in circuits/build/:
  - halp-auth.r1cs           (constraint system)
  - halp-auth_js/halp-auth.wasm (witness calculator)
  - halp-auth_final.zkey     (proving key)
  - verification_key.json    (verification key)

Exported to services:
  - wallet-sdk/circuits/     (wasm, zkey, vkey)
  - verifier-service/circuits/ (vkey)

Next steps:
  1. Stop existing services:
     Stop-Job *; Remove-Job *

  2. Restart all services:
     .\scripts\start-all-services.ps1

  3. Test the full ZKP flow:
     .\scripts\test-full-flow.ps1

"@
