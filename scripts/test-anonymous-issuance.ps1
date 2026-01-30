# HALP Anonymous Credential Issuance Test Script
# Tests anonymous issuance with master secret binding

$ErrorActionPreference = "Stop"

Write-Host "`n===============================================================================" -ForegroundColor Cyan
Write-Host "         ANONYMOUS CREDENTIAL ISSUANCE - TEST SCRIPT" -ForegroundColor Cyan
Write-Host "           Master Secret + Pedersen Commitment + ZKP" -ForegroundColor Cyan
Write-Host "===============================================================================`n" -ForegroundColor Cyan

# Check services
Write-Host "[Pre-Check] Verifying services..." -ForegroundColor Yellow

try {
    $null = Invoke-WebRequest -Uri "http://localhost:3001" -Method GET -TimeoutSec 5 -UseBasicParsing
    Write-Host "  Issuer service: OK" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Issuer service not running on port 3001" -ForegroundColor Red
    Write-Host "  Start with: .\scripts\start-all-services.ps1`n" -ForegroundColor Yellow
    exit 1
}

try {
    $null = Invoke-WebRequest -Uri "http://localhost:3004/api/wallet/credentials" -Method GET -TimeoutSec 5 -UseBasicParsing
    Write-Host "  Wallet service: OK" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Wallet service not running on port 3004" -ForegroundColor Red
    Write-Host "  Start with: .\scripts\start-all-services.ps1`n" -ForegroundColor Yellow
    exit 1
}

Write-Host "  SUCCESS: All services ready`n" -ForegroundColor Green

# Test configuration
$holderDid = "did:example:anonymous-holder-001"
$credentialType = "StudentCredential"
$claims = @{
    studentId = "S-2024-12345"
    program = "Computer Science"
    year = 2024
    gpa = 3.85
}

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "PHASE 1: ANONYMOUS CREDENTIAL REQUEST" -ForegroundColor Cyan
Write-Host "===============================================================================`n" -ForegroundColor Cyan

Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Holder DID: $holderDid" -ForegroundColor White
Write-Host "  Credential Type: $credentialType" -ForegroundColor White
Write-Host "  Claims: $($claims | ConvertTo-Json -Compress)`n" -ForegroundColor White

Write-Host "Sending anonymous request..." -ForegroundColor Green

$requestBody = @{
    holderDid = $holderDid
    credentialType = $credentialType
    claims = $claims
    issuerUrl = "http://localhost:3001"
    issuerPublicKey = "default-issuer-public-key"
} | ConvertTo-Json -Depth 10

try {
    $response = Invoke-RestMethod -Uri "http://localhost:3004/api/wallet/request-credential-anonymous" `
        -Method POST `
        -ContentType "application/json" `
        -Body $requestBody `
        -TimeoutSec 30

    if ($response.success) {
        Write-Host "`nSUCCESS: Anonymous request submitted" -ForegroundColor Green
        Write-Host "  Request ID: $($response.requestId)" -ForegroundColor White
        Write-Host "  Status: $($response.status)`n" -ForegroundColor Yellow
        
        $requestId = $response.requestId
    } else {
        Write-Host "`nERROR: Request failed - $($response.error)`n" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "`nERROR: $($_.Exception.Message)`n" -ForegroundColor Red
    exit 1
}

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "PHASE 2: ISSUER VERIFICATION & APPROVAL" -ForegroundColor Cyan
Write-Host "===============================================================================`n" -ForegroundColor Cyan

Write-Host "Opening issuer portal..." -ForegroundColor Green
Start-Process "http://localhost:3001"

Write-Host "`nWaiting for approval..." -ForegroundColor Yellow
Write-Host "ACTION REQUIRED: Approve the request in the issuer portal, then press ENTER`n" -ForegroundColor Yellow
Read-Host "Press ENTER after approving"

Write-Host "`nPolling for approval..." -ForegroundColor Green

$maxAttempts = 10
$attempt = 0
$approved = $false

while (($attempt -lt $maxAttempts) -and (-not $approved)) {
    $attempt++
    Write-Host "  Attempt $attempt/$maxAttempts..." -ForegroundColor Gray
    
    try {
        $statusUrl = "http://localhost:3004/api/wallet/check-request/${requestId}?issuerUrl=http://localhost:3001"
        $statusResponse = Invoke-RestMethod -Uri $statusUrl -Method GET -TimeoutSec 10
        
        if ($statusResponse.status -eq "approved") {
            $approved = $true
            $credential = $statusResponse.credential
            
            Write-Host "`nSUCCESS: Credential approved and issued!`n" -ForegroundColor Green
            Write-Host "Credential Details:" -ForegroundColor Yellow
            Write-Host "  ID: $($credential.id)" -ForegroundColor White
            Write-Host "  Type: $($credential.type -join ', ')" -ForegroundColor White
            Write-Host "  Subject: $($credential.credentialSubject.id)" -ForegroundColor Cyan
            
            if ($credential.credentialSubject.id -match "^nym:") {
                Write-Host "  Subject Type: PSEUDONYMOUS`n" -ForegroundColor Magenta
            }
            
        } elseif ($statusResponse.status -eq "pending") {
            Start-Sleep -Seconds 2
        } else {
            Write-Host "`nRequest status: $($statusResponse.status)`n" -ForegroundColor Yellow
            break
        }
    } catch {
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Yellow
        Start-Sleep -Seconds 2
    }
}

if (-not $approved) {
    Write-Host "`nERROR: Credential not approved within timeout`n" -ForegroundColor Red
    exit 1
}

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "SUCCESS: ANONYMOUS ISSUANCE TEST COMPLETED" -ForegroundColor Green
Write-Host "===============================================================================`n" -ForegroundColor Cyan

Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. View credential in wallet UI: http://localhost:3004" -ForegroundColor White
Write-Host "  2. Try requesting another credential with same holder DID" -ForegroundColor White
Write-Host "  3. Verify different pseudonyms are generated`n" -ForegroundColor White
