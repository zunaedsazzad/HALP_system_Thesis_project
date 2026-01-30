# HALP Production System

This repository contains the HALP Production System with **W3C Verifiable Credentials** support. It includes three backend services, a wallet service with web UI, a wallet SDK, and a Next.js frontend demo.

## 🚀 Quick Start

**Start all services with one command:**
```powershell
.\scripts\start-all-services.ps1
```

**Then open the wallet**: http://localhost:3004

See **[WALLET_QUICK_REFERENCE.md](WALLET_QUICK_REFERENCE.md)** for instant usage guide!

## 📁 Project Structure

- **issuer-service/** — Issues W3C Verifiable Credentials (Fastify + TypeScript)
- **verifier-service/** — Verifies W3C VCs (Fastify + TypeScript)
- **registry-service/** — Registry service (Fastify + TypeScript)
- **wallet-service/** — 🆕 Wallet with Web UI & API (Express + TypeScript)
- **wallet-sdk/** — Vanilla TypeScript library for credential management
- **frontend-demo/** — Next.js demo UI (app directory)
- **scripts/** — Startup and testing scripts

## 🎒 NEW: Wallet Service

A complete wallet application for managing W3C Verifiable Credentials:

- **Web Interface**: User-friendly UI at http://localhost:3004
- **Request Credentials**: Get credentials from the issuer
- **Store & Manage**: View, verify, and delete credentials
- **REST API**: Programmatic access to wallet features
- **W3C Compliant**: Full W3C VC Data Model v2.0 support

**Quick Links**:
- [Wallet Quick Reference](WALLET_QUICK_REFERENCE.md) - One-page cheat sheet
- [Wallet Quickstart Guide](WALLET_QUICKSTART.md) - Detailed usage guide
- [Implementation Summary](wallet-service/IMPLEMENTATION_SUMMARY.md) - Technical details
- [W3C VC Implementation](W3C_VC_IMPLEMENTATION.md) - W3C VC details

## 🏗️ Architecture

```
┌─────────────┐
│   Browser   │ ← User Interface
└──────┬──────┘
       │
┌──────▼──────────┐
│ Wallet Service  │ :3004 (Web UI + API)
└──┬──────────┬───┘
   │          │
┌──▼──────┐ ┌▼──────────┐
│ Issuer  │ │ Verifier  │
│ :3001   │ │ :3002     │
└─────────┘ └───────────┘
```

## 🛠️ Setup

### Install Dependencies

```powershell
# Issuer service
cd issuer-service
npm install
cd ..

# Verifier service
cd verifier-service
npm install
cd ..

# Wallet service
cd wallet-service
npm install
cd ..
```

### Start Services

**Option 1: All Services (Recommended)**
```powershell
.\scripts\start-all-services.ps1
```
This starts issuer (3001), verifier (3002), and wallet (3004).

**Option 2: Individual Services**
```powershell
# Issuer and verifier only
.\scripts\start-services.ps1

# Wallet only (issuer and verifier must be running)
cd wallet-service
npm run dev
```

## 📚 Documentation

- **[WALLET_QUICK_REFERENCE.md](WALLET_QUICK_REFERENCE.md)** - Quick reference guide
- **[WALLET_QUICKSTART.md](WALLET_QUICKSTART.md)** - Detailed wallet guide
- **[W3C_VC_IMPLEMENTATION.md](W3C_VC_IMPLEMENTATION.md)** - W3C VC implementation
- **[QUICKSTART.md](QUICKSTART.md)** - General quickstart guide
- **[wallet-service/README.md](wallet-service/README.md)** - Wallet API documentation
- **[wallet-service/IMPLEMENTATION_SUMMARY.md](wallet-service/IMPLEMENTATION_SUMMARY.md)** - Implementation details

## ✨ Features

### W3C Verifiable Credentials v2.0
- ✅ Full W3C VC Data Model v2.0 compliance
- ✅ DID-based issuer identification (did:local)
- ✅ JWT signing with RS256/HS256
- ✅ Cryptographic verification
- ✅ Temporal validation

### Wallet Features
- ✅ Request credentials from issuer
- ✅ Store W3C Verifiable Credentials
- ✅ View all credentials
- ✅ Verify credentials
- ✅ Delete credentials
- ✅ Modern web UI
- ✅ REST API

### Services
- ✅ Issuer: Create and sign W3C VCs
- ✅ Verifier: Validate W3C VCs
- ✅ Registry: Merkle tree & nullifier management
- ✅ Comprehensive logging

## 🧪 Testing

Run the smoke test:
```powershell
.\scripts\smoke-test.ps1
```

This tests the complete credential issuance and verification flow.

## 🔧 Service Management

### Check Status
```powershell
Get-Job
```

### View Logs
```powershell
Receive-Job -Name issuer -Keep
Receive-Job -Name verifier -Keep
Receive-Job -Name wallet -Keep
```

### Stop Services
```powershell
Stop-Job -Name issuer,verifier,wallet
Remove-Job -Name issuer,verifier,wallet
```

## 🌐 Service Endpoints

| Service | Port | Endpoints |
|---------|------|-----------|
| **Issuer** | 3001 | POST /credentials/issue<br>GET /credentials/status/:id<br>POST /did/create<br>GET /did/resolve/:did |
| **Verifier** | 3002 | POST /proofs/verify<br>POST /auth/challenge |
| **Wallet** | 3004 | POST /api/wallet/request-credential<br>POST /api/wallet/store<br>GET /api/wallet/credentials<br>POST /api/wallet/verify |

## 🔐 Security Notes

⚠️ **Development Mode**: This is configured for development/testing.

For production:
- Implement persistent encrypted storage
- Add authentication/authorization
- Use HTTPS/TLS
- Implement key management
- Enable audit logging
- Add rate limiting

## 📖 Learn More

- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/)
- [Decentralized Identifiers](https://www.w3.org/TR/did-core/)
- [Verifiable Credentials Use Cases](https://www.w3.org/TR/vc-use-cases/)

## 📄 License

MIT
