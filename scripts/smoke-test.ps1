<#
PowerShell smoke-test script for HALP services.
Runs a minimal end-to-end flow:
  1) POST to issuer /credentials/issue to request a credential (JSON body)
  2) POST to verifier /proofs/verify with the token returned by the issuer

Usage:
  Open a PowerShell window (separate from the windows running the servers).
  Set secrets if required (see notes below).
  Run: .\smoke-test.ps1

Exit codes:
  0 - success (verified)
  1 - network / request error
  2 - verification failed (verifier returned ok:false)
  3 - unexpected error

Notes:
 - Make sure the issuer and verifier services are running and reachable at the URLs below.
 - If you use environment secrets, ensure both services share the same secret (ISSUER_JWT_SECRET and JWT_SECRET).
#>

param(
  [string]$IssuerUrl = '',
  [string]$VerifierUrl = 'http://localhost:3002/proofs/verify',
  [int]$TimeoutSeconds = 10
)

function Write-Json($obj) {
  $obj | ConvertTo-Json -Depth 10
}

try {
  Write-Host "Starting HALP smoke test"
  Write-Host "Issuer URL: $IssuerUrl"
  Write-Host "Verifier URL: $VerifierUrl"

  # 1) Issue credential
  Write-Host "\n1) Requesting credential from issuer..."
  $body = @{ subject = 'did:example:holder'; claim = @{ name = 'Alice' } } | ConvertTo-Json

  $issueResponse = Invoke-RestMethod -Method Post -Uri $IssuerUrl -ContentType 'application/json' -Body $body -TimeoutSec $TimeoutSeconds -ErrorAction Stop

  Write-Host "Issuer response:" -ForegroundColor Cyan
  Write-Host (Write-Json $issueResponse)

  if (-not $issueResponse.token) {
    Write-Host "Issuer did not return a token. Aborting." -ForegroundColor Red
    exit 1
  }

  $token = $issueResponse.token
  Write-Host "Token received (length): $($token.Length)"

  # 2) Verify token with verifier
  Write-Host "\n2) Sending token to verifier..."
  $verifyBody = @{ token = $token } | ConvertTo-Json

  $verifyResponse = Invoke-RestMethod -Method Post -Uri $VerifierUrl -ContentType 'application/json' -Body $verifyBody -TimeoutSec $TimeoutSeconds -ErrorAction Stop

  Write-Host "Verifier response:" -ForegroundColor Cyan
  Write-Host (Write-Json $verifyResponse)

  if ($verifyResponse.ok -eq $true) {
    Write-Host "\nSmoke test succeeded: token verified." -ForegroundColor Green
    exit 0
  } else {
    Write-Host "\nSmoke test failed: verifier returned ok:false" -ForegroundColor Yellow
    exit 2
  }
} catch [System.Net.WebException] {
  Write-Host "Network or HTTP error: $_" -ForegroundColor Red
  exit 1
} catch {
  Write-Host "Unexpected error: $_" -ForegroundColor Red
  exit 3
}
