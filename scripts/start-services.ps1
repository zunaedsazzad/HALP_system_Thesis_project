<#
Starts issuer and verifier services with a shared JWT secret.
Usage: .\start-services.ps1 [-Secret dev-shared-secret] [-IssuerPort 3001] [-VerifierPort 3002]
#>
param(
	[string]$Secret = 'dev-shared-secret',
	[int]$IssuerPort = 3001,
	[int]$VerifierPort = 3002
)

Write-Host "Starting services with shared secret: $Secret" -ForegroundColor Cyan

$env:JWT_SECRET = $Secret
Write-Host "Issuer on port $IssuerPort"
Start-Job -Name issuer -ScriptBlock {
	cd $using:PWD
	cd issuer-service
	$env:PORT = $using:IssuerPort
	$env:JWT_SECRET = $using:Secret
	npm run dev
} | Out-Null

Write-Host "Verifier on port $VerifierPort"
Start-Job -Name verifier -ScriptBlock {
	cd $using:PWD
	cd verifier-service
	$env:PORT = $using:VerifierPort
	$env:JWT_SECRET = $using:Secret
	npm run dev
} | Out-Null

Write-Host "Jobs started. Check status with: Get-Job" -ForegroundColor Green
Write-Host "To see logs: Receive-Job -Name issuer -Keep; Receive-Job -Name verifier -Keep"
Write-Host "When ready, run smoke test in a new terminal: .\\scripts\\smoke-test.ps1" -ForegroundColor Yellow