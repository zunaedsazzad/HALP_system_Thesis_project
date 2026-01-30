# HALP Wallet Service

A simple wallet application for managing W3C Verifiable Credentials.

## Features

- **Request Credentials**: Request credentials from the issuer service
- **Store Credentials**: Store W3C Verifiable Credentials in the wallet
- **View Credentials**: Browse and view all stored credentials
- **Verify Credentials**: Verify credentials using the verifier service
- **Delete Credentials**: Remove credentials from the wallet

## Installation

```powershell
cd wallet-service
npm install
```

## Running the Wallet

```powershell
npm run dev
```

The wallet service will start on **http://localhost:3004**

## Using the Wallet

### Web Interface

Open your browser and navigate to:
```
http://localhost:3004
```

### API Endpoints

#### Request Credential
```bash
POST /api/wallet/request-credential
Content-Type: application/json

{
  "issuerUrl": "http://localhost:3001/credentials/issue",
  "credentialData": {
    "subject": "did:example:alice",
    "type": "ExampleCredential",
    "claim": {
      "name": "Alice",
      "age": 25
    }
  }
}
```

#### Store Credential
```bash
POST /api/wallet/store
Content-Type: application/json

{
  "credential": { /* W3C VC object */ },
  "token": "eyJhbGci..." // optional JWT token
}
```

#### Get All Credentials
```bash
GET /api/wallet/credentials
```

#### Get Specific Credential
```bash
GET /api/wallet/credentials/:id
```

#### Verify Credential
```bash
POST /api/wallet/verify
Content-Type: application/json

{
  "token": "eyJhbGci...",
  "verifierUrl": "http://localhost:3002/proofs/verify" // optional
}
```

#### Delete Credential
```bash
DELETE /api/wallet/credentials/:id
```

## Quick Start Guide

1. **Start all services**:
   ```powershell
   .\scripts\start-services.ps1
   ```

2. **Start the wallet**:
   ```powershell
   cd wallet-service
   npm install
   npm run dev
   ```

3. **Open the wallet UI**:
   - Navigate to http://localhost:3004

4. **Request a credential**:
   - Fill in the form with subject DID and claim data
   - Click "Request Credential"
   - The credential will be automatically stored

5. **View your credentials**:
   - Scroll down to see all stored credentials
   - Click "View Details" to see the full credential
   - Click "Verify" to check if it's valid
   - Click "Delete" to remove it

## Architecture

```
┌─────────────┐
│   Browser   │
│  (Frontend) │
└──────┬──────┘
       │ HTTP
┌──────▼──────────┐
│ Wallet Service  │ :3004
│  (Express API)  │
└────┬─────┬──────┘
     │     │
     │     └─────────┐
     │               │
┌────▼────┐    ┌────▼────┐
│ Issuer  │    │Verifier │
│ Service │    │ Service │
│  :3001  │    │  :3002  │
└─────────┘    └─────────┘
```

## Storage

Currently uses **in-memory storage** (Map). Credentials are lost when the service restarts.

For production, implement persistent storage using:
- SQLite
- PostgreSQL
- Encrypted file system
- Browser localStorage (for client-side wallet)

## Security Notes

⚠️ This is a **basic implementation** for development/testing purposes.

For production use, consider:
- Encrypting stored credentials
- Adding authentication/authorization
- Using HTTPS
- Implementing backup/recovery
- Adding audit logging
- Using secure key storage
- Implementing rate limiting

## Dependencies

- `express` - Web server
- `cors` - Cross-origin resource sharing
- `node-fetch` - HTTP client
- `typescript` - Type safety
- `ts-node-dev` - Development server

## License

MIT
