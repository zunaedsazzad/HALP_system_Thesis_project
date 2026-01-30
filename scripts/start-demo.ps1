# HALP System - Teacher Demonstration Startup Script
# This script opens 3 terminal windows to run all required services

Write-Host "`n╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     HALP Credential System - Teacher Demonstration Setup        ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

Write-Host "This script will open 3 PowerShell windows:" -ForegroundColor Yellow
Write-Host "  1. Issuer Service (port 3001)" -ForegroundColor White
Write-Host "  2. Wallet Service (port 3004)" -ForegroundColor White
Write-Host "  3. Frontend Demo (port 3000)" -ForegroundColor White
Write-Host ""

$workspaceRoot = $PSScriptRoot

Write-Host "Starting services..." -ForegroundColor Green
Write-Host ""

# Start Issuer Service
Write-Host "Starting Issuer Service..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", @"
    Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Green
    Write-Host '║          ISSUER SERVICE (Terminal 1)                        ║' -ForegroundColor Green
    Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Green
    Write-Host ''
    Write-Host 'Port: 3001' -ForegroundColor Yellow
    Write-Host 'Watch this terminal for:' -ForegroundColor Yellow
    Write-Host '  - Incoming credential requests' -ForegroundColor White
    Write-Host '  - BBS+ signature creation' -ForegroundColor White
    Write-Host '  - Credential approval process' -ForegroundColor White
    Write-Host ''
    cd '$workspaceRoot\issuer-service'
    npm run dev
"@

Start-Sleep -Seconds 2

# Start Wallet Service
Write-Host "Starting Wallet Service..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", @"
    Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Green
    Write-Host '║          WALLET SERVICE (Terminal 2)                        ║' -ForegroundColor Green
    Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Green
    Write-Host ''
    Write-Host 'Port: 3004' -ForegroundColor Yellow
    Write-Host 'Watch this terminal for:' -ForegroundColor Yellow
    Write-Host '  - Master secret generation' -ForegroundColor White
    Write-Host '  - Pseudonym derivation' -ForegroundColor White
    Write-Host '  - API requests to issuer' -ForegroundColor White
    Write-Host '  - Credential storage' -ForegroundColor White
    Write-Host ''
    cd '$workspaceRoot\wallet-service'
    npm run dev
"@

Start-Sleep -Seconds 2

# Start Frontend
Write-Host "Starting Frontend..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", @"
    Write-Host '╔══════════════════════════════════════════════════════════════╗' -ForegroundColor Green
    Write-Host '║          FRONTEND DEMO (Terminal 3)                         ║' -ForegroundColor Green
    Write-Host '╚══════════════════════════════════════════════════════════════╝' -ForegroundColor Green
    Write-Host ''
    Write-Host 'Port: 3000' -ForegroundColor Yellow
    Write-Host 'User Interface:' -ForegroundColor Yellow
    Write-Host '  - Wallet: http://localhost:3000' -ForegroundColor White
    Write-Host '  - Issuer: http://localhost:3001' -ForegroundColor White
    Write-Host ''
    Write-Host 'Open your browser to these URLs after services start.' -ForegroundColor Cyan
    Write-Host ''
    cd '$workspaceRoot\frontend-demo'
    npm run dev
"@

Write-Host ""
Write-Host "✅ All services starting!" -ForegroundColor Green
Write-Host ""
Write-Host "What to do next:" -ForegroundColor Yellow
Write-Host "  1. Wait 10-15 seconds for all services to start" -ForegroundColor White
Write-Host "  2. Open browser to http://localhost:3000" -ForegroundColor White
Write-Host "  3. Request a credential from the wallet interface" -ForegroundColor White
Write-Host "  4. Watch the terminal windows for detailed logs" -ForegroundColor White
Write-Host ""
Write-Host "  Terminal 1 (Issuer):  Shows credential signing with BBS+" -ForegroundColor Cyan
Write-Host "  Terminal 2 (Wallet):  Shows master secret & pseudonym generation" -ForegroundColor Cyan
Write-Host "  Terminal 3 (Frontend): Shows Next.js server" -ForegroundColor Cyan
Write-Host ""
Write-Host "Read TEACHER_DEMO_GUIDE.md for full demonstration instructions." -ForegroundColor Yellow
Write-Host ""
Write-Host "Press any key to exit this script (services will keep running)..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
