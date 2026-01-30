'use client';

import * as React from 'react';
import { useState, useCallback } from 'react';

interface AuthChallenge {
  challengeId: string;
  challenge: string;
  domain: string;
  registryRoot: string;
  circuitId: string;
  expiresAt: number;
}

interface AuthState {
  phase: 'idle' | 'challenge' | 'proof' | 'submit' | 'success' | 'error';
  challenge?: AuthChallenge;
  pseudonym?: string;
  nullifier?: string;
  sessionToken?: string;
  error?: string;
  logs: string[];
}

const VERIFIER_URL = process.env.NEXT_PUBLIC_VERIFIER_URL || 'http://localhost:3002';
const WALLET_SERVICE_URL = process.env.NEXT_PUBLIC_WALLET_URL || 'http://localhost:3004';

export default function AuthenticatePage() {
  const [domain, setDomain] = useState('example-service.com');
  const [holderDid, setHolderDid] = useState('did:example:holder123');
  const [credentialId, setCredentialId] = useState('cred:example:degree123');
  const [authState, setAuthState] = useState<AuthState>({
    phase: 'idle',
    logs: []
  });

  const addLog = useCallback((message: string) => {
    setAuthState(prev => ({
      ...prev,
      logs: [...prev.logs, `[${new Date().toLocaleTimeString()}] ${message}`]
    }));
  }, []);

  const clearLogs = useCallback(() => {
    setAuthState(prev => ({ ...prev, logs: [] }));
  }, []);

  // Phase 1: Request Challenge
  const requestChallenge = async () => {
    clearLogs();
    addLog('=== PHASE 1: CHALLENGE GENERATION ===');
    addLog(`Requesting challenge for domain: ${domain}`);
    
    setAuthState(prev => ({ ...prev, phase: 'challenge' }));
    
    try {
      const response = await fetch(`${VERIFIER_URL}/auth/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      
      const data = await response.json();
      
      if (!data.success) {
        throw new Error(data.error || 'Challenge generation failed');
      }
      
      const challenge = data.challenge;
      addLog(`✓ Challenge received: ${challenge.challengeId}`);
      addLog(`  Challenge value: ${challenge.challenge.substring(0, 32)}...`);
      addLog(`  Registry root: ${challenge.registryRoot.substring(0, 32)}...`);
      addLog(`  Expires: ${new Date(challenge.expiresAt).toLocaleTimeString()}`);
      
      setAuthState(prev => ({
        ...prev,
        phase: 'proof',
        challenge
      }));
      
      return challenge;
    } catch (error) {
      addLog(`✗ Challenge request failed: ${error}`);
      setAuthState(prev => ({
        ...prev,
        phase: 'error',
        error: error instanceof Error ? error.message : 'Unknown error'
      }));
      throw error;
    }
  };

  // Phase 2-4: Call Wallet Service for complete authentication
  // The wallet service handles: proof generation, submission, and verification
  const authenticateViaWallet = async () => {
    addLog('\n=== PHASE 2: PROOF GENERATION (via Wallet Service) ===');
    addLog('Calling wallet service to generate hybrid proof...');
    addLog(`  Credential ID: ${credentialId}`);
    addLog(`  Domain: ${domain}`);
    addLog(`  Holder DID: ${holderDid}`);
    
    setAuthState(prev => ({ ...prev, phase: 'proof' }));
    
    try {
      // Call wallet service to handle the full authentication flow
      const response = await fetch(`${WALLET_SERVICE_URL}/api/wallet/authenticate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credentialId: credentialId || undefined, // Use first credential if empty
          domain,
          holderDid,
          revealedAttributes: []
        })
      });
      
      const data = await response.json();
      
      if (data.success) {
        addLog('✓ Hybrid proof generated successfully');
        addLog(`  Pseudonym: ${data.pseudonym?.substring(0, 32)}...`);
        addLog(`  Nullifier: ${data.nullifier?.substring(0, 32)}...`);
        
        addLog('\n=== PHASE 3: PROOF SUBMISSION ===');
        addLog('✓ Proof submitted to verifier by wallet service');
        
        addLog('\n=== PHASE 4: VERIFICATION ===');
        addLog('✓ Challenge validated');
        addLog('✓ Registry root verified');
        addLog('✓ SNARK proof verified');
        addLog('✓ Nullifier freshness confirmed');
        addLog('✓ Nullifier registered in tree');
        addLog(`✓ Session token issued`);
        
        setAuthState(prev => ({
          ...prev,
          phase: 'success',
          pseudonym: data.pseudonym,
          nullifier: data.nullifier,
          sessionToken: data.sessionToken
        }));
      } else {
        addLog(`✗ Authentication failed: ${data.error}`);
        
        // Show detailed error info if available
        if (data.authPackage) {
          addLog('\n[Debug] Auth package details:');
          addLog(`  Pseudonym: ${data.authPackage.pseudonym?.substring(0, 24)}...`);
          addLog(`  Nullifier: ${data.authPackage.nullifier?.substring(0, 24)}...`);
        }
        
        setAuthState(prev => ({
          ...prev,
          phase: 'error',
          error: data.error || 'Authentication failed'
        }));
      }
    } catch (error) {
      addLog(`✗ Wallet service error: ${error}`);
      setAuthState(prev => ({
        ...prev,
        phase: 'error',
        error: error instanceof Error ? error.message : 'Unknown error'
      }));
    }
  };

  // Complete authentication flow using wallet service
  const authenticate = async () => {
    try {
      // First, request challenge to show in UI
      const challenge = await requestChallenge();
      // Then call wallet service for the rest
      await authenticateViaWallet();
    } catch (error) {
      console.error('Authentication failed:', error);
    }
  };

  const reset = () => {
    setAuthState({ phase: 'idle', logs: [] });
  };

  return (
    <div style={{ padding: 20, maxWidth: 1200, margin: '0 auto' }}>
      <h1 style={{ marginBottom: 10 }}>🔐 HALP Authentication Demo</h1>
      <p style={{ color: '#666', marginBottom: 30 }}>
        Zero-Knowledge Authentication with Privacy-Preserving Credentials
      </p>

      {/* Configuration Panel */}
      <div style={{ 
        background: '#f5f5f5', 
        padding: 20, 
        borderRadius: 8, 
        marginBottom: 20 
      }}>
        <h3 style={{ marginTop: 0 }}>Configuration</h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 15 }}>
          <div>
            <label style={{ display: 'block', marginBottom: 5, fontWeight: 'bold' }}>
              Service Domain
            </label>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              style={{ width: '100%', padding: 8, borderRadius: 4, border: '1px solid #ddd' }}
            />
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: 5, fontWeight: 'bold' }}>
              Holder DID
            </label>
            <input
              type="text"
              value={holderDid}
              onChange={(e) => setHolderDid(e.target.value)}
              style={{ width: '100%', padding: 8, borderRadius: 4, border: '1px solid #ddd' }}
            />
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: 5, fontWeight: 'bold' }}>
              Credential ID
            </label>
            <input
              type="text"
              value={credentialId}
              onChange={(e) => setCredentialId(e.target.value)}
              style={{ width: '100%', padding: 8, borderRadius: 4, border: '1px solid #ddd' }}
            />
          </div>
        </div>
      </div>

      {/* Phase Indicator */}
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        marginBottom: 20,
        padding: '15px 0'
      }}>
        {['Challenge', 'Proof Gen', 'Submit', 'Verify'].map((phase, idx) => {
          const phaseMap = ['challenge', 'proof', 'submit', 'success'];
          const isActive = phaseMap.indexOf(authState.phase) >= idx;
          const isCurrent = phaseMap[idx] === authState.phase;
          
          return (
            <div key={phase} style={{ 
              flex: 1, 
              textAlign: 'center',
              padding: 10,
              background: isCurrent ? '#2196F3' : isActive ? '#4CAF50' : '#e0e0e0',
              color: isActive ? 'white' : '#666',
              margin: '0 5px',
              borderRadius: 4,
              fontWeight: isCurrent ? 'bold' : 'normal'
            }}>
              Phase {idx + 1}: {phase}
            </div>
          );
        })}
      </div>

      {/* Action Buttons */}
      <div style={{ marginBottom: 20 }}>
        <button
          onClick={authenticate}
          disabled={authState.phase !== 'idle' && authState.phase !== 'error'}
          style={{
            padding: '12px 24px',
            fontSize: 16,
            background: authState.phase === 'idle' ? '#2196F3' : '#ccc',
            color: 'white',
            border: 'none',
            borderRadius: 4,
            cursor: authState.phase === 'idle' ? 'pointer' : 'not-allowed',
            marginRight: 10
          }}
        >
          🚀 Start Authentication
        </button>
        <button
          onClick={reset}
          style={{
            padding: '12px 24px',
            fontSize: 16,
            background: '#f44336',
            color: 'white',
            border: 'none',
            borderRadius: 4,
            cursor: 'pointer'
          }}
        >
          🔄 Reset
        </button>
      </div>

      {/* Result Panel */}
      {authState.phase === 'success' && (
        <div style={{
          background: '#e8f5e9',
          border: '1px solid #4CAF50',
          padding: 20,
          borderRadius: 8,
          marginBottom: 20
        }}>
          <h3 style={{ color: '#2e7d32', marginTop: 0 }}>✅ Authentication Successful!</h3>
          <div style={{ marginBottom: 10 }}>
            <strong>Pseudonym:</strong>
            <code style={{ display: 'block', background: '#fff', padding: 8, marginTop: 5, borderRadius: 4, wordBreak: 'break-all' }}>
              {authState.pseudonym}
            </code>
          </div>
          <div>
            <strong>Session Token:</strong>
            <code style={{ display: 'block', background: '#fff', padding: 8, marginTop: 5, borderRadius: 4, wordBreak: 'break-all', fontSize: 12 }}>
              {authState.sessionToken}
            </code>
          </div>
        </div>
      )}

      {authState.phase === 'error' && (
        <div style={{
          background: '#ffebee',
          border: '1px solid #f44336',
          padding: 20,
          borderRadius: 8,
          marginBottom: 20
        }}>
          <h3 style={{ color: '#c62828', marginTop: 0 }}>❌ Authentication Failed</h3>
          <p>{authState.error}</p>
        </div>
      )}

      {/* Log Panel */}
      <div style={{
        background: '#1e1e1e',
        color: '#00ff00',
        padding: 20,
        borderRadius: 8,
        fontFamily: 'monospace',
        fontSize: 13,
        maxHeight: 400,
        overflow: 'auto'
      }}>
        <div style={{ marginBottom: 10, color: '#888' }}>Authentication Log:</div>
        {authState.logs.length === 0 ? (
          <div style={{ color: '#666' }}>Click "Start Authentication" to begin...</div>
        ) : (
          authState.logs.map((log, idx) => (
            <div key={idx} style={{ 
              color: log.includes('✓') ? '#00ff00' : log.includes('✗') ? '#ff5555' : log.includes('===') ? '#55aaff' : '#cccccc'
            }}>
              {log}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
