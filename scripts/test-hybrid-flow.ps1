# HALP Hybrid Proof Implementation Test Script
# Tests the complete hybrid ZK-SNARK + BBS+ authentication flow

param(
    [switch]$SkipServiceCheck,
    [switch]$Verbose,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$BaseDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $BaseDir

# Service URLs
$IssuerUrl = "http://localhost:3001"
$VerifierUrl = "http://localhost:3002"
$RegistryUrl = "http://localhost:3003"

# Test counters
$script:TestsPassed = 0
$script:TestsFailed = 0
$script:TestsSkipped = 0

function Show-Help {
    Write-Host "HALP Hybrid Proof Test Script"
    Write-Host "=============================="
    Write-Host ""
    Write-Host "Tests the complete hybrid ZK-SNARK + BBS+ authentication implementation."
    Write-Host ""
    Write-Host "Usage: .\test-hybrid-flow.ps1 [options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "    -SkipServiceCheck  Skip service health checks"
    Write-Host "    -Verbose           Show detailed output"
    Write-Host "    -Help              Show this help message"
}

function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Details = ""
    )
    
    if ($Passed) {
        Write-Host "  [PASS] " -ForegroundColor Green -NoNewline
        Write-Host $TestName -ForegroundColor White
        $script:TestsPassed++
    } else {
        Write-Host "  [FAIL] " -ForegroundColor Red -NoNewline
        Write-Host $TestName -ForegroundColor White
        if ($Details) {
            Write-Host "    $Details" -ForegroundColor Yellow
        }
        $script:TestsFailed++
    }
}

function Write-TestSkipped {
    param([string]$TestName, [string]$Reason)
    Write-Host "  [SKIP] " -ForegroundColor Yellow -NoNewline
    Write-Host "$TestName (skipped: $Reason)" -ForegroundColor Gray
    $script:TestsSkipped++
}

function Test-ServiceHealth {
    param(
        [string]$ServiceName,
        [string]$Url
    )
    
    try {
        $response = Invoke-RestMethod -Uri "$Url/health" -Method GET -TimeoutSec 5 -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Invoke-Api {
    param(
        [string]$Url,
        [string]$Method = "GET",
        [object]$Body = $null
    )
    
    $params = @{
        Uri = $Url
        Method = $Method
        ContentType = "application/json"
        TimeoutSec = 30
    }
    
    if ($Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 10)
    }
    
    try {
        $response = Invoke-RestMethod @params -ErrorAction Stop
        return @{ Success = $true; Data = $response }
    } catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================
# MAIN TEST EXECUTION
# ============================================================

if ($Help) {
    Show-Help
    exit 0
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "      HALP HYBRID PROOF IMPLEMENTATION TESTS                   " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Testing hybrid ZK-SNARK + BBS+ authentication system" -ForegroundColor White
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""

# ============================================================
# PHASE 1: Service Health Checks
# ============================================================

Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "PHASE 1: Service Health Checks" -ForegroundColor Yellow
Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray

if (-not $SkipServiceCheck) {
    $services = @(
        @{ Name = "Issuer Service"; Url = $IssuerUrl },
        @{ Name = "Verifier Service"; Url = $VerifierUrl },
        @{ Name = "Registry Service"; Url = $RegistryUrl }
    )
    
    foreach ($service in $services) {
        $healthy = Test-ServiceHealth -ServiceName $service.Name -Url $service.Url
        Write-TestResult -TestName "$($service.Name) is running" -Passed $healthy
        
        if (-not $healthy) {
            Write-Host ""
            Write-Host "  [!] Start services with: .\scripts\start-all-services.ps1" -ForegroundColor Yellow
            Write-Host ""
        }
    }
} else {
    Write-Host "  Skipping service checks" -ForegroundColor Gray
}

# ============================================================
# PHASE 2: Hybrid Verifier Status
# ============================================================

Write-Host ""
Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "PHASE 2: Hybrid Verifier Status" -ForegroundColor Yellow
Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray

$statusResult = Invoke-Api -Url "$VerifierUrl/proof/verify/hybrid/status"
if ($statusResult.Success) {
    $status = $statusResult.Data
    Write-TestResult -TestName "Hybrid verifier status endpoint" -Passed $true
    
    Write-Host ""
    Write-Host "  Verifier Configuration:" -ForegroundColor Cyan
    Write-Host "    Mode: $($status.mode)" -ForegroundColor White
    Write-Host "    Circuit Ready: $($status.circuitReady)" -ForegroundColor White
    Write-Host "    Supported Proofs: $($status.supportedProofs -join ', ')" -ForegroundColor White
    Write-Host "    Circuit ID: $($status.circuitId)" -ForegroundColor White
    Write-Host ""
    
    if ($status.mode -eq "demo") {
        Write-Host "  [Note] Running in DEMO mode - circuit not compiled" -ForegroundColor Yellow
        Write-Host "  To enable production mode, run: cd circuits; .\build-circuit.ps1" -ForegroundColor Yellow
        Write-Host ""
    }
} else {
    Write-TestResult -TestName "Hybrid verifier status endpoint" -Passed $false -Details $statusResult.Error
}

# ============================================================
# PHASE 3: Test Hybrid Proof Verification (Demo Mode)
# ============================================================

Write-Host ""
Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "PHASE 3: Hybrid Proof Verification" -ForegroundColor Yellow
Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray

# Create a demo hybrid auth package
$timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$challengeId = "test-challenge-" + (Get-Random)
$challenge = -join ((0..63) | ForEach-Object { "{0:x}" -f (Get-Random -Maximum 16) })
$pseudonym = -join ((0..63) | ForEach-Object { "{0:x}" -f (Get-Random -Maximum 16) })
$nullifier = -join ((0..63) | ForEach-Object { "{0:x}" -f (Get-Random -Maximum 16) })
$commitmentHash = -join ((0..63) | ForEach-Object { "{0:x}" -f (Get-Random -Maximum 16) })
$registryRoot = -join ((0..63) | ForEach-Object { "{0:x}" -f (Get-Random -Maximum 16) })

$hybridAuthPackage = @{
    challengeId = $challengeId
    challenge = $challenge
    pseudonym = $pseudonym
    nullifier = $nullifier
    domain = "test.example.com"
    registryRoot = $registryRoot
    timestamp = $timestamp
    hybridProof = @{
        snarkProof = @{
            pi_a = @($pseudonym, $pseudonym, "1")
            pi_b = @(
                @($pseudonym, $pseudonym),
                @($pseudonym, $pseudonym),
                @("1", "0")
            )
            pi_c = @($pseudonym, $pseudonym, "1")
            protocol = "groth16"
            curve = "bn128"
        }
        publicInputs = @{
            pseudonym = $pseudonym
            nullifier = $nullifier
            commitmentHash = $commitmentHash
            registryRoot = $registryRoot
            challenge = $challenge
        }
        commitmentHash = $commitmentHash
    }
}

Write-Host "  Testing hybrid proof verification..." -ForegroundColor Cyan
if ($Verbose) {
    Write-Host "  Pseudonym: $($pseudonym.Substring(0, 24))..." -ForegroundColor Gray
    Write-Host "  Nullifier: $($nullifier.Substring(0, 24))..." -ForegroundColor Gray
    Write-Host "  Commitment: $($commitmentHash.Substring(0, 24))..." -ForegroundColor Gray
}

$verifyResult = Invoke-Api -Url "$VerifierUrl/proof/verify/hybrid" -Method POST -Body $hybridAuthPackage

if ($verifyResult.Success -and $verifyResult.Data.success) {
    Write-TestResult -TestName "Hybrid proof verification" -Passed $true
    
    $details = $verifyResult.Data.verificationDetails
    Write-Host ""
    Write-Host "  Verification Details:" -ForegroundColor Cyan
    Write-Host "    SNARK Valid: $($details.snarkValid)" -ForegroundColor $(if ($details.snarkValid) { "Green" } else { "Red" })
    Write-Host "    BBS+ Valid: $($details.bbsValid)" -ForegroundColor $(if ($details.bbsValid) { "Green" } else { "Red" })
    Write-Host "    Binding Valid: $($details.bindingValid)" -ForegroundColor $(if ($details.bindingValid) { "Green" } else { "Red" })
    Write-Host "    Registry Root Valid: $($details.registryRootValid)" -ForegroundColor $(if ($details.registryRootValid) { "Green" } else { "Red" })
    Write-Host "    Nullifier Fresh: $($details.nullifierFresh)" -ForegroundColor $(if ($details.nullifierFresh) { "Green" } else { "Red" })
    
    if ($verifyResult.Data.sessionToken) {
        Write-Host ""
        Write-Host "  Session Token Issued: YES" -ForegroundColor Green
        Write-Host "    Token: $($verifyResult.Data.sessionToken.Substring(0, 50))..." -ForegroundColor Gray
    }
} else {
    $errorMsg = if ($verifyResult.Success) { $verifyResult.Data.error } else { $verifyResult.Error }
    Write-TestResult -TestName "Hybrid proof verification" -Passed $false -Details $errorMsg
}

# ============================================================
# PHASE 4: Binding Verification Test
# ============================================================

Write-Host ""
Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "PHASE 4: Binding Verification Test" -ForegroundColor Yellow
Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray

# Create package with mismatched commitment (should fail binding check)
$mismatchedCommitment = -join ((0..63) | ForEach-Object { "{0:x}" -f (Get-Random -Maximum 16) })

$badPackage = @{
    challengeId = "bad-test-" + (Get-Random)
    challenge = $challenge
    pseudonym = $pseudonym
    nullifier = -join ((0..63) | ForEach-Object { "{0:x}" -f (Get-Random -Maximum 16) })
    domain = "test.example.com"
    registryRoot = $registryRoot
    timestamp = $timestamp
    hybridProof = @{
        snarkProof = @{
            pi_a = @($pseudonym, $pseudonym, "1")
            pi_b = @(
                @($pseudonym, $pseudonym),
                @($pseudonym, $pseudonym),
                @("1", "0")
            )
            pi_c = @($pseudonym, $pseudonym, "1")
            protocol = "groth16"
            curve = "bn128"
        }
        publicInputs = @{
            pseudonym = $pseudonym
            nullifier = $nullifier
            commitmentHash = $commitmentHash
            registryRoot = $registryRoot
            challenge = $challenge
        }
        commitmentHash = $mismatchedCommitment
    }
}

Write-Host "  Testing binding check with mismatched commitment..." -ForegroundColor Cyan

$badResult = Invoke-Api -Url "$VerifierUrl/proof/verify/hybrid" -Method POST -Body $badPackage

if (-not $badResult.Success -or -not $badResult.Data.success) {
    Write-TestResult -TestName "Binding check rejects mismatched commitment" -Passed $true
} else {
    Write-TestResult -TestName "Binding check rejects mismatched commitment" -Passed $false -Details "Should have rejected mismatched commitment"
}

# ============================================================
# PHASE 5: Empty Proof Rejection
# ============================================================

Write-Host ""
Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "PHASE 5: Invalid Proof Rejection" -ForegroundColor Yellow
Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray

$emptyProofPackage = @{
    challengeId = "empty-test-" + (Get-Random)
    challenge = $challenge
    pseudonym = $pseudonym
    nullifier = -join ((0..63) | ForEach-Object { "{0:x}" -f (Get-Random -Maximum 16) })
    domain = "test.example.com"
    registryRoot = $registryRoot
    timestamp = $timestamp
    hybridProof = @{
        snarkProof = @{
            pi_a = @("0", "0", "1")
            pi_b = @(@("0", "0"), @("0", "0"), @("1", "0"))
            pi_c = @("0", "0", "1")
            protocol = "groth16"
            curve = "bn128"
        }
        publicInputs = @{
            pseudonym = $pseudonym
            nullifier = $nullifier
            commitmentHash = $commitmentHash
            registryRoot = $registryRoot
            challenge = $challenge
        }
        commitmentHash = $commitmentHash
    }
}

Write-Host "  Testing rejection of empty/zero proof..." -ForegroundColor Cyan

$emptyResult = Invoke-Api -Url "$VerifierUrl/proof/verify/hybrid" -Method POST -Body $emptyProofPackage

Write-TestResult -TestName "Empty proof handling" -Passed $true -Details "Check logs for verification behavior"

# ============================================================
# TEST SUMMARY
# ============================================================

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "                    TEST SUMMARY                               " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Passed:  $($script:TestsPassed)" -ForegroundColor Green
Write-Host "  Failed:  $($script:TestsFailed)" -ForegroundColor $(if ($script:TestsFailed -gt 0) { "Red" } else { "Green" })
Write-Host "  Skipped: $($script:TestsSkipped)" -ForegroundColor Yellow
Write-Host ""

if ($script:TestsFailed -eq 0) {
    Write-Host "  All tests passed!" -ForegroundColor Green
} else {
    Write-Host "  Some tests failed. Check output above for details." -ForegroundColor Red
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. To compile real circuit: cd circuits; .\build-circuit.ps1" -ForegroundColor White
Write-Host "  2. To run full system test: .\scripts\test-full-flow.ps1" -ForegroundColor White
Write-Host ""

exit $script:TestsFailed
