import express, { Request, Response } from 'express';
import cors from 'cors';
import path from 'path';
import walletRoutes from './routes/wallet';

const app = express();
const PORT = process.env.PORT || 3004;

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files (frontend)
app.use(express.static(path.join(__dirname, '../public')));

// API Routes
app.use('/api/wallet', walletRoutes);

// Serve frontend for all non-API routes
app.get('*', (req: Request, res: Response) => {
  if (!req.path.startsWith('/api')) {
    res.sendFile(path.join(__dirname, '../public/index.html'));
  }
});

app.listen(PORT, () => {
  console.log('\n┌──────────────────────────────────────────┐');
  console.log('│   HALP WALLET SERVICE STARTING...        │');
  console.log('└──────────────────────────────────────────┘\n');
  console.log('🎒 Wallet Service Ready');
  console.log(`🚀 Server listening at http://localhost:${PORT}`);
  console.log('\nAvailable endpoints:');
  console.log('  POST /api/wallet/request-credential  - Request credential from issuer');
  console.log('  POST /api/wallet/store               - Store a credential');
  console.log('  GET  /api/wallet/credentials         - Get all stored credentials');
  console.log('  GET  /api/wallet/credentials/:id     - Get specific credential');
  console.log('  POST /api/wallet/verify              - Verify a credential');
  console.log('  DELETE /api/wallet/credentials/:id   - Delete a credential');
  console.log('\nFrontend UI available at: http://localhost:3004');
  console.log('\nReady to manage credentials...\n');
});
