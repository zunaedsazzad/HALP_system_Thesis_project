<#
Starts issuer, verifier, registry, and wallet services with a shared JWT secret.
Usage: .\start-all-services.ps1 [-Secret dev-shared-secret] [-IssuerPort 3001] [-VerifierPort 3002] [-RegistryPort 3003] [-WalletPort 3004]
#>
param(
	[string]$Secret = 'dev-shared-secret',
	[int]$IssuerPort = 3001,
	[int]$VerifierPort = 3002,
	[int]$RegistryPort = 3003,
	[int]$WalletPort = 3004
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  HALP SYSTEM - STARTING ALL SERVICES" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Shared JWT Secret: $Secret" -ForegroundColor Yellow
Write-Host ""

$env:JWT_SECRET = $Secret

# Start Issuer Service
Write-Host "[1/4] Starting Issuer Service on port $IssuerPort..." -ForegroundColor Green
Start-Job -Name issuer -ScriptBlock {
	cd $using:PWD
	cd issuer-service
	$env:PORT = $using:IssuerPort
	$env:JWT_SECRET = $using:Secret
	npm run dev
} | Out-Null

# Start Verifier Service
Write-Host "[2/4] Starting Verifier Service on port $VerifierPort..." -ForegroundColor Green
Start-Job -Name verifier -ScriptBlock {
	cd $using:PWD
	cd verifier-service
	$env:PORT = $using:VerifierPort
	$env:JWT_SECRET = $using:Secret
	npm run dev
} | Out-Null

# Start Registry Service
Write-Host "[3/4] Starting Registry Service on port $RegistryPort..." -ForegroundColor Green
Start-Job -Name registry -ScriptBlock {
	cd $using:PWD
	cd registry-service
	$env:PORT = $using:RegistryPort
	$env:JWT_SECRET = $using:Secret
	npm run dev
} | Out-Null

# Start Wallet Service
Write-Host "[4/4] Starting Wallet Service on port $WalletPort..." -ForegroundColor Green
Start-Job -Name wallet -ScriptBlock {
	cd $using:PWD
	cd wallet-service
	$env:PORT = $using:WalletPort
	$env:JWT_SECRET = $using:Secret
	npm run dev
} | Out-Null

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  ALL SERVICES STARTED!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Service Status:" -ForegroundColor Yellow
Write-Host "  Issuer Service:   http://localhost:$IssuerPort"
Write-Host "  Verifier Service: http://localhost:$VerifierPort"
Write-Host "  Registry Service: http://localhost:$RegistryPort"
Write-Host "  Wallet Service:   http://localhost:$WalletPort"
Write-Host "  Wallet UI:        http://localhost:$WalletPort (Open in browser)"
Write-Host ""

Write-Host "Useful Commands:" -ForegroundColor Yellow
Write-Host "  Get-Job                                          - Check job status"
Write-Host "  Receive-Job -Name issuer -Keep                   - View issuer logs"
Write-Host "  Receive-Job -Name verifier -Keep                 - View verifier logs"
Write-Host "  Receive-Job -Name registry -Keep                 - View registry logs"
Write-Host "  Receive-Job -Name wallet -Keep                   - View wallet logs"
Write-Host "  Stop-Job *; Remove-Job *                         - Stop all services"
Write-Host ""

Write-Host "Testing:" -ForegroundColor Yellow
Write-Host "  .\scripts\test-full-flow.ps1                     - Run full system test"
Write-Host ""

Write-Host "⏳ Services are initializing (wait 10-15 seconds)..." -ForegroundColor Yellow
Write-Host "Then open: http://localhost:$WalletPort`n" -ForegroundColor Green
