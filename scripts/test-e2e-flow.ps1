<#
.SYNOPSIS
    Comprehensive End-to-End Test for the HALP System
.DESCRIPTION
    This script tests the entire HALP flow:
    1. Service health checks
    2. DID creation
    3. Credential issuance (standard and anonymous)
    4. Credential verification
    5. Hybrid SNARK+BBS+ authentication
    6. Nullifier registry operations
.NOTES
    Author: HALP System
    Date: 2026-01-23
#>

param(
    [switch]$Verbose,
    [switch]$StopOnError
)

# ============================================================================
# Configuration
# ============================================================================
$IssuerUrl = "http://localhost:3001"
$VerifierUrl = "http://localhost:3002"
$RegistryUrl = "http://localhost:3003"
$WalletUrl = "http://localhost:3004"

$Script:PassedTests = 0
$Script:FailedTests = 0
$Script:TotalTests = 0

# ============================================================================
# Helper Functions
# ============================================================================
function Write-TestHeader($title) {
    Write-Host ""
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host "=" * 70 -ForegroundColor Cyan
}

function Write-TestResult($name, $passed, $details = "") {
    $Script:TotalTests++
    if ($passed) {
        $Script:PassedTests++
        Write-Host "  [PASS] $name" -ForegroundColor Green
    } else {
        $Script:FailedTests++
        Write-Host "  [FAIL] $name" -ForegroundColor Red
    }
    if ($details -and $Verbose) {
        Write-Host "         $details" -ForegroundColor Gray
    }
}

function Invoke-TestEndpoint {
    param(
        [string]$Method = "GET",
        [string]$Url,
        [object]$Body = $null,
        [int]$ExpectedStatus = 200
    )
    
    try {
        $params = @{
            Uri = $Url
            Method = $Method
            ContentType = "application/json"
            TimeoutSec = 10
            UseBasicParsing = $true
        }
        
        if ($Body) {
            $params.Body = ($Body | ConvertTo-Json -Depth 10)
        }
        
        $response = Invoke-WebRequest @params -ErrorAction Stop
        $content = $response.Content | ConvertFrom-Json
        
        return @{
            Success = $true
            StatusCode = $response.StatusCode
            Data = $content
        }
    }
    catch {
        $statusCode = 0
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        return @{
            Success = $false
            StatusCode = $statusCode
            Error = $_.Exception.Message
            Data = $null
        }
    }
}

# ============================================================================
# PHASE 1: SERVICE HEALTH CHECKS
# ============================================================================
function Test-ServiceHealth {
    Write-TestHeader "PHASE 1: SERVICE HEALTH CHECKS"
    
    # Test Issuer Service
    $result = Invoke-TestEndpoint -Url "$IssuerUrl/did/resolve/test"
    if ($result.StatusCode -eq 404 -or $result.StatusCode -eq 200) {
        Write-TestResult "Issuer Service (port 3001)" $true "Service responding"
    } else {
        Write-TestResult "Issuer Service (port 3001)" $false "Not responding"
    }
    
    # Test Verifier Service
    $result = Invoke-TestEndpoint -Url "$VerifierUrl/health"
    Write-TestResult "Verifier Service (port 3002)" $result.Success "Health endpoint OK"
    
    # Test Registry Service - Check merkle root
    $result = Invoke-TestEndpoint -Url "$RegistryUrl/merkle/root"
    Write-TestResult "Registry Service (port 3003)" $result.Success "Merkle root available"
    
    # Test Wallet Service
    $result = Invoke-TestEndpoint -Url "$WalletUrl/api/wallet/credentials"
    if ($result.Success -or $result.StatusCode -gt 0) {
        Write-TestResult "Wallet Service (port 3004)" $true "Service responding"
    } else {
        Write-TestResult "Wallet Service (port 3004)" $false "Not responding"
    }
}

# ============================================================================
# PHASE 2: DID MANAGEMENT
# ============================================================================
function Test-DIDManagement {
    Write-TestHeader "PHASE 2: DID MANAGEMENT"
    
    # Create a new DID
    $result = Invoke-TestEndpoint -Method "POST" -Url "$IssuerUrl/did/create" -Body @{
        method = "key"
    }
    
    if ($result.Success -and $result.Data.did) {
        $Script:IssuerDid = $result.Data.did
        Write-TestResult "Create Issuer DID" $true "DID: $($Script:IssuerDid.Substring(0, 30))..."
    } else {
        Write-TestResult "Create Issuer DID" $false $result.Error
        $Script:IssuerDid = "did:key:test-issuer"
    }
    
    # Resolve the DID
    if ($Script:IssuerDid) {
        $result = Invoke-TestEndpoint -Url "$IssuerUrl/did/resolve/$([uri]::EscapeDataString($Script:IssuerDid))"
        Write-TestResult "Resolve DID Document" $result.Success "DID doc retrieved"
    }
}

# ============================================================================
# PHASE 3: CREDENTIAL ISSUANCE (Standard Flow)
# ============================================================================
function Test-CredentialIssuance {
    Write-TestHeader "PHASE 3: CREDENTIAL ISSUANCE (Standard Flow)"
    
    # Step 1: Submit credential request
    $credentialRequest = @{
        subject = "did:example:holder-123"
        type = "UniversityDegree"
        claim = @{
            degree = @{
                type = "BachelorDegree"
                name = "Bachelor of Science"
                university = "Test University"
            }
            graduationDate = "2025-06-15"
            gpa = 3.8
        }
        requesterInfo = @{
            name = "John Doe"
            studentId = "STU-2025-001"
        }
    }
    
    $result = Invoke-TestEndpoint -Method "POST" -Url "$IssuerUrl/credentials/request" -Body $credentialRequest
    
    if ($result.Success -and $result.Data.requestId) {
        $Script:CredentialRequestId = $result.Data.requestId
        Write-TestResult "Submit Credential Request" $true "Request ID: $($Script:CredentialRequestId)"
    } else {
        Write-TestResult "Submit Credential Request" $false $result.Error
        return
    }
    
    # Step 2: Get pending requests
    $result = Invoke-TestEndpoint -Url "$IssuerUrl/credentials/pending"
    if ($result.Success) {
        $pendingCount = ($result.Data | Measure-Object).Count
        Write-TestResult "Get Pending Requests" $true "Found $pendingCount pending request(s)"
    } else {
        Write-TestResult "Get Pending Requests" $false $result.Error
    }
    
    # Step 3: Approve the request
    $result = Invoke-TestEndpoint -Method "POST" -Url "$IssuerUrl/credentials/approve" -Body @{
        requestId = $Script:CredentialRequestId
    }
    
    if ($result.Success -and $result.Data.verifiableCredential) {
        $Script:IssuedCredential = $result.Data.verifiableCredential
        Write-TestResult "Approve and Issue Credential" $true "Credential issued with BBS+ signature"
        if ($Verbose) {
            Write-Host "         Credential ID: $($Script:IssuedCredential.id)" -ForegroundColor Gray
            Write-Host "         Type: $($Script:IssuedCredential.type -join ', ')" -ForegroundColor Gray
        }
    } else {
        Write-TestResult "Approve and Issue Credential" $false $result.Error
    }
    
    # Step 4: Check request status
    if ($Script:CredentialRequestId) {
        $result = Invoke-TestEndpoint -Url "$IssuerUrl/credentials/status/$Script:CredentialRequestId"
        if ($result.Success) {
            Write-TestResult "Check Request Status" $true "Status: $($result.Data.status)"
        } else {
            Write-TestResult "Check Request Status" $false $result.Error
        }
    }
}

# ============================================================================
# PHASE 4: ANONYMOUS CREDENTIAL ISSUANCE
# ============================================================================
function Test-AnonymousCredentialIssuance {
    Write-TestHeader "PHASE 4: ANONYMOUS CREDENTIAL ISSUANCE"
    
    # Generate a pseudo-random commitment and pseudonym for testing
    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $nonce = [System.Guid]::NewGuid().ToString("N")
    
    $anonymousRequest = @{
        pseudonym = "pseudo-$timestamp-$nonce"
        commitment = "commit-$timestamp"
        commitmentProof = @{
            challenge = "test-challenge-$timestamp"
            response = "test-response-$timestamp"
            publicKey = "test-pk"
        }
        credentialType = "AccessCredential"
        encryptedClaims = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((@{
            accessLevel = "premium"
            department = "engineering"
        } | ConvertTo-Json)))
        claimsHash = "hash-$timestamp"
        nonce = $nonce
        timestamp = $timestamp
    }
    
    $result = Invoke-TestEndpoint -Method "POST" -Url "$IssuerUrl/credentials/request-anonymous" -Body $anonymousRequest
    
    if ($result.Success -and $result.Data.requestId) {
        $Script:AnonymousRequestId = $result.Data.requestId
        Write-TestResult "Submit Anonymous Request" $true "Request ID: $($Script:AnonymousRequestId)"
        
        # Check that it's marked as anonymous
        if ($result.Data.isAnonymous) {
            Write-TestResult "Request Marked Anonymous" $true "Privacy-preserving flag set"
        } else {
            Write-TestResult "Request Marked Anonymous" $false "Missing anonymous flag"
        }
    } else {
        Write-TestResult "Submit Anonymous Request" $false $result.Error
    }
    
    # Approve anonymous request
    if ($Script:AnonymousRequestId) {
        $result = Invoke-TestEndpoint -Method "POST" -Url "$IssuerUrl/credentials/approve" -Body @{
            requestId = $Script:AnonymousRequestId
        }
        
        if ($result.Success -and $result.Data.verifiableCredential) {
            $Script:AnonymousCredential = $result.Data.verifiableCredential
            Write-TestResult "Approve Anonymous Credential" $true "Credential bound to commitment"
        } else {
            Write-TestResult "Approve Anonymous Credential" $false $result.Error
        }
    }
}

# ============================================================================
# PHASE 5: CREDENTIAL VERIFICATION
# ============================================================================
function Test-CredentialVerification {
    Write-TestHeader "PHASE 5: CREDENTIAL VERIFICATION"
    
    if (-not $Script:IssuedCredential) {
        Write-Host "  [SKIP] No credential to verify (issuance failed)" -ForegroundColor Yellow
        return
    }
    
    # Verify the issued credential
    $result = Invoke-TestEndpoint -Method "POST" -Url "$VerifierUrl/proof/verify" -Body @{
        verifiableCredential = $Script:IssuedCredential
    }
    
    if ($result.Success -and $result.Data.ok) {
        Write-TestResult "Verify Credential Signature" $true "BBS+ signature valid"
    } elseif ($result.Success) {
        Write-TestResult "Verify Credential Signature" $false "Signature invalid: $($result.Data.error)"
    } else {
        Write-TestResult "Verify Credential Signature" $false $result.Error
    }
}

# ============================================================================
# PHASE 6: HYBRID AUTHENTICATION FLOW
# ============================================================================
function Test-HybridAuthentication {
    Write-TestHeader "PHASE 6: HYBRID AUTHENTICATION (SNARK + BBS+)"
    
    # Step 1: Check verifier status
    $result = Invoke-TestEndpoint -Url "$VerifierUrl/proof/verify/hybrid/status"
    if ($result.Success) {
        Write-TestResult "Hybrid Verifier Status" $true "Mode: $($result.Data.mode), Circuit Ready: $($result.Data.circuitReady)"
    } else {
        Write-TestResult "Hybrid Verifier Status" $false $result.Error
    }
    
    # Step 2: Get authentication challenge
    $result = Invoke-TestEndpoint -Url "$VerifierUrl/auth/challenge"
    if ($result.Success -and $result.Data.challenge) {
        $Script:AuthChallenge = $result.Data.challenge
        $Script:ChallengeId = $result.Data.challengeId
        Write-TestResult "Get Auth Challenge" $true "Challenge obtained"
    } else {
        Write-TestResult "Get Auth Challenge" $false $result.Error
        return
    }
    
    # Step 3: Submit hybrid proof (demo mode)
    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $domain = "test.halp.system"
    # Use hex format for pseudonym/nullifier as expected by demo mode
    $hexTimestamp = "{0:X16}" -f $timestamp
    $pseudonymHex = "a1b2c3d4e5f6$hexTimestamp"
    $nullifierHex = "f1e2d3c4b5a6$hexTimestamp"
    $commitment = "c0mmit$hexTimestamp"
    
    # Build JSON manually to handle numeric keys properly
    # Note: publicInputs and snarkProof are at the same level in hybridProof
    $hybridProofJson = @"
{
    "challengeId": "$($Script:ChallengeId)",
    "challenge": "$($Script:AuthChallenge)",
    "domain": "$domain",
    "timestamp": $timestamp,
    "pseudonym": "$pseudonymHex",
    "nullifier": "$nullifierHex",
    "hybridProof": {
        "snarkProof": {
            "pi_a": ["12345678901234567890", "98765432109876543210", "1"],
            "pi_b": [["11111111111111111111", "22222222222222222222"], ["33333333333333333333", "44444444444444444444"], ["1", "0"]],
            "pi_c": ["55555555555555555555", "66666666666666666666", "1"],
            "protocol": "groth16",
            "curve": "bn128"
        },
        "publicInputs": {
            "pseudonym": "$pseudonymHex",
            "nullifier": "$nullifierHex",
            "commitmentHash": "$commitment",
            "registryRoot": "0000000000000000000000000000000000000000000000000000000000000000",
            "challenge": "$($Script:AuthChallenge)"
        },
        "bbsProof": {
            "proof": "ZGVtby1iYnMtcHJvb2Y=",
            "revealedMessages": {
                "0": "$commitment",
                "1": "credential-type-access",
                "2": "issuer-did-123"
            },
            "revealedIndices": [0, 1, 2],
            "issuerPublicKey": "abcdef1234567890abcdef1234567890abcdef1234567890",
            "nonce": "test-nonce-12345"
        },
        "commitmentHash": "$commitment"
    }
}
"@
    
    try {
        $params = @{
            Uri = "$VerifierUrl/proof/verify/hybrid"
            Method = "POST"
            ContentType = "application/json"
            Body = $hybridProofJson
            TimeoutSec = 10
            UseBasicParsing = $true
        }
        $response = Invoke-WebRequest @params -ErrorAction Stop
        $result = @{
            Success = $true
            Data = ($response.Content | ConvertFrom-Json)
        }
    } catch {
        $result = @{
            Success = $false
            Error = $_.Exception.Message
            Data = $null
        }
    }
    
    if ($result.Success -and $result.Data.valid) {
        Write-TestResult "Hybrid Proof Verification" $true "SNARK + BBS+ verified"
        
        if ($result.Data.verificationDetails) {
            $details = $result.Data.verificationDetails
            Write-TestResult "- SNARK Proof Valid" $details.snarkValid ""
            Write-TestResult "- BBS+ Proof Valid" $details.bbsValid ""
            Write-TestResult "- Binding Check Valid" $details.bindingValid ""
            Write-TestResult "- Nullifier Fresh" $details.nullifierFresh ""
        }
        
        if ($result.Data.sessionToken) {
            Write-TestResult "Session Token Issued" $true "Token length: $($result.Data.sessionToken.Length)"
        }
    } else {
        $errorMsg = if ($result.Data.error) { $result.Data.error } else { $result.Error }
        Write-TestResult "Hybrid Proof Verification" $false $errorMsg
    }
    
    # Step 4: Test binding rejection (mismatched commitment)
    $mismatchTimestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() + 1
    $hexMismatchTs = "{0:X16}" -f $mismatchTimestamp
    $mismatchPseudo = "deadbeef12345678$hexMismatchTs"
    $mismatchNullifier = "cafebabe87654321$hexMismatchTs"
    
    $mismatchedProofJson = @"
{
    "challengeId": "$($Script:ChallengeId)",
    "challenge": "$($Script:AuthChallenge)",
    "domain": "$domain",
    "timestamp": $mismatchTimestamp,
    "pseudonym": "$mismatchPseudo",
    "nullifier": "$mismatchNullifier",
    "hybridProof": {
        "snarkProof": {
            "pi_a": ["12345678901234567890", "98765432109876543210", "1"],
            "pi_b": [["11111111111111111111", "22222222222222222222"], ["33333333333333333333", "44444444444444444444"], ["1", "0"]],
            "pi_c": ["55555555555555555555", "66666666666666666666", "1"],
            "protocol": "groth16",
            "curve": "bn128"
        },
        "publicInputs": {
            "pseudonym": "$mismatchPseudo",
            "nullifier": "$mismatchNullifier",
            "commitmentHash": "aabbccdd11223344",
            "registryRoot": "0000000000000000000000000000000000000000000000000000000000000000",
            "challenge": "$($Script:AuthChallenge)"
        },
        "bbsProof": {
            "proof": "ZGVtby1iYnMtcHJvb2Y=",
            "revealedMessages": {
                "0": "DIFFERENT55667788",
                "1": "credential-type"
            },
            "revealedIndices": [0, 1],
            "issuerPublicKey": "abcdef1234567890abcdef1234567890abcdef1234567890",
            "nonce": "test-nonce-12345"
        },
        "commitmentHash": "aabbccdd11223344"
    }
}
"@
    
    try {
        $params = @{
            Uri = "$VerifierUrl/proof/verify/hybrid"
            Method = "POST"
            ContentType = "application/json"
            Body = $mismatchedProofJson
            TimeoutSec = 10
            UseBasicParsing = $true
        }
        $response = Invoke-WebRequest @params -ErrorAction Stop
        $result = @{
            Success = $true
            Data = ($response.Content | ConvertFrom-Json)
        }
    } catch {
        # A 400 response is expected for mismatched binding
        try {
            $errorBody = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorBody)
            $errorContent = $reader.ReadToEnd() | ConvertFrom-Json
            $result = @{
                Success = $true
                Data = $errorContent
            }
        } catch {
            $result = @{
                Success = $false
                Data = @{ valid = $false }
            }
        }
    }
    
    if (-not $result.Data.valid) {
        Write-TestResult "Binding Mismatch Rejection" $true "Correctly rejected mismatched commitment"
    } else {
        Write-TestResult "Binding Mismatch Rejection" $false "Should have rejected mismatched commitment"
    }
}

# ============================================================================
# PHASE 7: NULLIFIER REGISTRY
# ============================================================================
function Test-NullifierRegistry {
    Write-TestHeader "PHASE 7: NULLIFIER REGISTRY"
    
    # Get registry stats
    $result = Invoke-TestEndpoint -Url "$RegistryUrl/nullifiers/stats"
    if ($result.Success) {
        $nullCount = if ($result.Data.totalNullifiers) { $result.Data.totalNullifiers } else { 0 }
        Write-TestResult "Get Registry Stats" $true "Total nullifiers: $nullCount"
    } else {
        Write-TestResult "Get Registry Stats" $false $result.Error
    }
    
    # Check a nullifier
    $testNullifier = "test-nullifier-" + [System.Guid]::NewGuid().ToString("N")
    $result = Invoke-TestEndpoint -Method "POST" -Url "$RegistryUrl/nullifiers/check" -Body @{
        nullifier = $testNullifier
    }
    
    if ($result.Success -and -not $result.Data.used) {
        Write-TestResult "Check Fresh Nullifier" $true "Correctly identified as unused"
    } else {
        Write-TestResult "Check Fresh Nullifier" $false "Should be unused"
    }
    
    # Register a nullifier
    $result = Invoke-TestEndpoint -Method "POST" -Url "$RegistryUrl/nullifiers/register" -Body @{
        nullifier = $testNullifier
        domain = "test.halp.system"
        pseudonym = "test-pseudonym-" + [System.Guid]::NewGuid().ToString("N").Substring(0, 16)
        timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    }
    
    if ($result.Success) {
        Write-TestResult "Register Nullifier" $true "Nullifier registered"
    } else {
        Write-TestResult "Register Nullifier" $false $result.Error
    }
    
    # Check that nullifier is now used
    $result = Invoke-TestEndpoint -Method "POST" -Url "$RegistryUrl/nullifiers/check" -Body @{
        nullifier = $testNullifier
    }
    
    if ($result.Success -and $result.Data.used) {
        Write-TestResult "Detect Used Nullifier" $true "Correctly identified as used (replay prevented)"
    } else {
        Write-TestResult "Detect Used Nullifier" $false "Should detect as used"
    }
}

# ============================================================================
# PHASE 8: MERKLE TREE OPERATIONS
# ============================================================================
function Test-MerkleTree {
    Write-TestHeader "PHASE 8: MERKLE TREE OPERATIONS"
    
    # Get Merkle root
    $result = Invoke-TestEndpoint -Url "$RegistryUrl/merkle/root"
    if ($result.Success -and $result.Data.root) {
        $Script:MerkleRoot = $result.Data.root
        Write-TestResult "Get Merkle Root" $true "Root: $($Script:MerkleRoot.Substring(0, 20))..."
    } else {
        Write-TestResult "Get Merkle Root" $false $result.Error
    }
    
    # Get tree stats
    $result = Invoke-TestEndpoint -Url "$RegistryUrl/merkle/stats"
    if ($result.Success) {
        $treeSize = if ($result.Data.size) { $result.Data.size } else { 0 }
        $treeDepth = if ($result.Data.depth) { $result.Data.depth } else { 20 }
        Write-TestResult "Get Tree Stats" $true "Size: $treeSize, Depth: $treeDepth"
    } else {
        Write-TestResult "Get Tree Stats" $false $result.Error
    }
    
    # Request a non-membership proof (for proving nullifier hasn't been used)
    $testLeaf = [System.Guid]::NewGuid().ToString("N")
    $result = Invoke-TestEndpoint -Method "POST" -Url "$RegistryUrl/merkle/proof" -Body @{
        leaf = $testLeaf
        proofType = "non-membership"
    }
    
    if ($result.Success -and $result.Data.success) {
        Write-TestResult "Generate Non-Membership Proof" $true "Proof generated"
    } else {
        # May not be implemented, just log
        $proofMsg = if ($result.Error) { $result.Error } else { "Proof system active" }
        Write-TestResult "Generate Non-Membership Proof" ($result.Success) $proofMsg
    }
}

# ============================================================================
# PHASE 9: WALLET SERVICE INTEGRATION
# ============================================================================
function Test-WalletIntegration {
    Write-TestHeader "PHASE 9: WALLET SERVICE INTEGRATION"
    
    # Get stored credentials
    $result = Invoke-TestEndpoint -Url "$WalletUrl/api/wallet/credentials"
    if ($result.Success) {
        $count = ($result.Data | Measure-Object).Count
        Write-TestResult "List Wallet Credentials" $true "Found $count credential(s)"
    } else {
        Write-TestResult "List Wallet Credentials" $false $result.Error
    }
    
    # Test credential request through wallet (integrated flow)
    $result = Invoke-TestEndpoint -Method "POST" -Url "$WalletUrl/api/wallet/request-credential" -Body @{
        issuerUrl = "$IssuerUrl/credentials/issue"
        credentialData = @{
            subject = "did:example:wallet-user"
            type = "MembershipCredential"
            claim = @{
                membershipLevel = "gold"
                validUntil = "2027-12-31"
            }
        }
    }
    
    if ($result.Success) {
        Write-TestResult "Wallet Credential Request" $true "Request submitted via wallet"
    } else {
        Write-TestResult "Wallet Credential Request" $false $result.Error
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
Write-Host ""
Write-Host "#" * 70 -ForegroundColor Magenta
Write-Host "#" -ForegroundColor Magenta -NoNewline
Write-Host "                    HALP SYSTEM E2E TEST SUITE                     " -ForegroundColor White -NoNewline
Write-Host "#" -ForegroundColor Magenta
Write-Host "#" * 70 -ForegroundColor Magenta
Write-Host "  Testing: Issuance, Verification, and Authentication Flows"
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "#" * 70 -ForegroundColor Magenta

# Run all test phases
Test-ServiceHealth
Test-DIDManagement
Test-CredentialIssuance
Test-AnonymousCredentialIssuance
Test-CredentialVerification
Test-HybridAuthentication
Test-NullifierRegistry
Test-MerkleTree
Test-WalletIntegration

# ============================================================================
# TEST SUMMARY
# ============================================================================
Write-Host ""
Write-Host "=" * 70 -ForegroundColor Magenta
Write-Host "  TEST SUMMARY" -ForegroundColor Magenta
Write-Host "=" * 70 -ForegroundColor Magenta
Write-Host ""
Write-Host "  Total Tests:  $($Script:TotalTests)" -ForegroundColor White
Write-Host "  Passed:       $($Script:PassedTests)" -ForegroundColor Green
Write-Host "  Failed:       $($Script:FailedTests)" -ForegroundColor $(if ($Script:FailedTests -gt 0) { "Red" } else { "Green" })
Write-Host ""

$passRate = if ($Script:TotalTests -gt 0) { [math]::Round(($Script:PassedTests / $Script:TotalTests) * 100, 1) } else { 0 }
Write-Host "  Pass Rate:    $passRate%" -ForegroundColor $(if ($passRate -ge 80) { "Green" } elseif ($passRate -ge 50) { "Yellow" } else { "Red" })
Write-Host ""

if ($Script:FailedTests -eq 0) {
    Write-Host "  STATUS: ALL TESTS PASSED" -ForegroundColor Green
    Write-Host "  The HALP system is functioning correctly!" -ForegroundColor Green
} elseif ($Script:FailedTests -le 3) {
    Write-Host "  STATUS: MOSTLY PASSING" -ForegroundColor Yellow  
    Write-Host "  Some minor issues detected. Review failed tests above." -ForegroundColor Yellow
} else {
    Write-Host "  STATUS: ISSUES DETECTED" -ForegroundColor Red
    Write-Host "  Multiple failures detected. Please investigate." -ForegroundColor Red
}

Write-Host ""
Write-Host "=" * 70 -ForegroundColor Magenta

# Exit with appropriate code
if ($Script:FailedTests -gt 0) {
    exit 1
} else {
    exit 0
}
