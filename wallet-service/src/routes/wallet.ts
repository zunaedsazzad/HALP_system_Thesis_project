import { Router, Request, Response } from 'express';
import fetch from 'node-fetch';
import { randomBytes, createHash } from 'crypto';
import { AnonymousCredentialRequester } from '../services/anonymous-credential-requester';
import { HybridProofGeneratorClass as HybridProofGenerator, StoredCredential as SDKStoredCredential, MasterSecretManager } from 'wallet-sdk';

const router = Router();
const anonymousRequester = new AnonymousCredentialRequester();

// Initialize anonymous requester
anonymousRequester.initialize().then(() => {
  console.log('[Wallet] AnonymousCredentialRequester initialized');
}).catch((err: Error) => {
  console.error('[Wallet] Failed to init AnonymousCredentialRequester:', err);
});

// Initialize hybrid proof generator
const proofGenerator = new HybridProofGenerator();
let proofGeneratorReady = false;
proofGenerator.initialize().then(() => {
  proofGeneratorReady = true;
  console.log('[Wallet] HybridProofGenerator initialized');
}).catch((err: Error) => {
  console.error('[Wallet] Failed to init HybridProofGenerator:', err);
});

// In-memory storage for credentials (in production, use a database)
interface StoredCredential {
  id: string;
  credential: any;
  bbsSignature?: string;
  commitmentHash?: string;
  blindingFactor?: string;
  issuerPublicKey?: string;
  messageLabels?: string[];
  storedAt: string;
}

const credentialStore = new Map<string, StoredCredential>();

// Request credential from issuer (interactive approval flow)
router.post('/request-credential', async (req: Request, res: Response) => {
  try {
    const { credentialData, useDirectIssue } = req.body;
    // Use issuerUrl from body or default
    const issuerUrl = req.body.issuerUrl || 'http://localhost:3001/credentials/issue';
    
    if (!issuerUrl) {
      return res.status(400).json({ success: false, error: 'issuerUrl is required' });
    }
    
    console.log('\n╔══════════════════════════════════════════════════════════════════╗');
    console.log('║          API CALL: REQUEST CREDENTIAL (Wallet → Issuer)       ║');
    console.log('╚══════════════════════════════════════════════════════════════════╝');
    console.log('\n[Teacher Demo] Full API Request/Response Flow\n');
    console.log('📤 OUTGOING HTTP REQUEST');
    console.log('  Method: POST');
    console.log('  Target: Issuer Service');
    console.log('  URL:', issuerUrl);
    console.log('\n  Request Body:');
    console.log(JSON.stringify(credentialData || {}, null, 4).split('\n').map(l => '    ' + l).join('\n'));

    // Determine endpoint: /request (needs approval) or /issue (direct)
    const endpoint = useDirectIssue ? issuerUrl : issuerUrl.replace('/issue', '/request');
    console.log('\n  Final Endpoint:', endpoint);
    console.log('  Flow Type:', useDirectIssue ? 'Direct Issue' : 'Interactive Approval');

    console.log('\n📡 Sending HTTP request...');
    // Request credential from issuer
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentialData),
    });

    console.log('\n📥 RESPONSE RECEIVED');
    console.log('  HTTP Status:', response.status, response.statusText);
    console.log('  Headers:', JSON.stringify(Object.fromEntries(response.headers.entries()), null, 4).split('\n').map(l => '    ' + l).join('\n'));

    if (!response.ok) {
      throw new Error(`Issuer responded with status ${response.status}`);
    }

    const data = await response.json();
    console.log('\n  Response Body:');
    console.log(JSON.stringify(data, null, 4).split('\n').map(l => '    ' + l).join('\n'));
    
    // Check if this is a pending request or direct issuance
    if (data.status === 'pending' && data.requestId) {
      console.log('\n═══════════════════════════════════════════════════════════════════');
      console.log('✅ REQUEST SUBMITTED SUCCESSFULLY');
      console.log('   Request ID:', data.requestId);
      console.log('   Status: PENDING APPROVAL (waiting for issuer)');
      console.log('   Next: Wallet will poll for approval status');
      console.log('═══════════════════════════════════════════════════════════════════\n');
      
      return res.json({
        success: true,
        status: 'pending',
        requestId: data.requestId,
        message: 'Credential request submitted. Waiting for issuer approval.'
      });
    }
    
    // Direct issuance (legacy flow)
    console.log('\n═══════════════════════════════════════════════════════════════════');
    console.log('✅ CREDENTIAL RECEIVED (DIRECT ISSUANCE)');
    console.log('   Credential ID:', data.verifiableCredential?.id);
    console.log('   Type:', data.verifiableCredential?.type);
    console.log('   Format:', data.format);

    // Auto-store the credential
    if (data.verifiableCredential && data.verifiableCredential.id) {
      const stored: StoredCredential = {
        id: data.verifiableCredential.id,
        credential: data.verifiableCredential,
        storedAt: new Date().toISOString(),
      };
      credentialStore.set(stored.id, stored);
      console.log('   Storage: ✓ Auto-stored in wallet');
    }

    console.log('═══════════════════════════════════════════════════════════════════\n');

    res.json({
      success: true,
      credential: data.verifiableCredential,
      format: data.format,
    });
  } catch (error: any) {
    console.error('✗ Error requesting credential:', error.message);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// NEW ENDPOINT: Request credential anonymously with master secret binding
router.post('/request-credential-anonymous', async (req: Request, res: Response) => {
  try {
    const { holderDid, credentialType, claims, issuerUrl, issuerPublicKey } = req.body;

    if (!holderDid || !credentialType || !claims || !issuerUrl) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: holderDid, credentialType, claims, issuerUrl'
      });
    }

    console.log('\n╔══════════════════════════════════════════════════════════════════╗');
    console.log('║   INITIATING ANONYMOUS CREDENTIAL REQUEST (Wallet → Issuer)    ║');
    console.log('╚══════════════════════════════════════════════════════════════════╝');
    console.log('\n[Teacher Demo] Privacy-Preserving Credential Issuance\n');
    console.log('📋 Request Parameters:');
    console.log(`   Holder DID: ${holderDid} (local only, not sent to issuer)`);
    console.log(`   Credential Type: ${credentialType}`);
    console.log(`   Claims: ${JSON.stringify(claims)}`);
    console.log(`   Issuer URL: ${issuerUrl}\n`);

    // Create anonymous request with master secret, pseudonym, and commitment
    const anonymousRequest = await anonymousRequester.createAnonymousRequest(
      holderDid,
      credentialType,
      claims,
      issuerPublicKey || 'default-issuer-public-key'
    );

    console.log('📤 SENDING ANONYMOUS REQUEST TO ISSUER');
    console.log(`   Endpoint: ${issuerUrl}/credentials/request-anonymous`);
    console.log('   🔒 Privacy Features:');
    console.log('   ✓ Identity Hidden: Only pseudonym sent (not DID)');
    console.log('   ✓ Master Secret Protected: Via commitment + ZK proof');
    console.log('   ✓ Claims Encrypted: Only issuer can decrypt');
    console.log('   ✓ Unlinkable: Different pseudonym per credential type\n');

    // Send to issuer's anonymous endpoint
    const endpoint = issuerUrl.includes('/credentials')
      ? issuerUrl.replace(/\/credentials\/.*/, '/credentials/request-anonymous')
      : `${issuerUrl}/credentials/request-anonymous`;

    console.log('📡 Sending HTTP POST request...\n');
    
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(anonymousRequest)
    });

    console.log('📥 RESPONSE RECEIVED FROM ISSUER');
    console.log(`   HTTP Status: ${response.status} ${response.statusText}`);

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Issuer responded with ${response.status}: ${errorText}`);
    }

    const data = await response.json();
    console.log(`   Success: ${data.success}`);
    console.log(`   Request ID: ${data.requestId}`);
    console.log(`   Status: ${data.status}\n`);

    console.log('═══════════════════════════════════════════════════════════════════');
    console.log('✅ ANONYMOUS REQUEST SUBMITTED SUCCESSFULLY');
    console.log(`   Request ID: ${data.requestId}`);
    console.log('   Status: PENDING (waiting for issuer approval)');
    console.log('   Privacy: ✓ (holder identity protected)');
    console.log('   Next: Poll for approval using request ID');
    console.log('═══════════════════════════════════════════════════════════════════\n');

    res.json({
      success: true,
      status: 'pending',
      requestId: data.requestId,
      message: 'Anonymous credential request submitted. Waiting for issuer approval.',
      isAnonymous: true
    });
  } catch (error: any) {
    console.error('❌ Error in anonymous credential request:', error.message);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Check request status and retrieve credential if approved
router.get('/check-request/:requestId', async (req: Request, res: Response) => {
  try {
    const { requestId } = req.params;
    let issuerUrl = req.query.issuerUrl as string || 'http://localhost:3001';
    
    // Extract base URL (remove /credentials/issue or /credentials/request if present)
    issuerUrl = issuerUrl.replace(/\/credentials\/(issue|request)$/, '');
    
    console.log('\n╔══════════════════════════════════════════════════════════════════╗');
    console.log('║       API CALL: CHECK REQUEST STATUS (Wallet → Issuer)       ║');
    console.log('╚══════════════════════════════════════════════════════════════════╝');
    console.log('\n[Teacher Demo] Polling for Credential Approval\n');
    console.log('📤 OUTGOING HTTP REQUEST');
    console.log('  Method: GET');
    console.log('  Request ID:', requestId);
    console.log('  Issuer Base URL:', issuerUrl);
    
    const statusUrl = `${issuerUrl}/credentials/request-status/${requestId}`;
    console.log('  Full URL:', statusUrl);
    
    console.log('\n📡 Sending HTTP request...');
    const response = await fetch(statusUrl);
    
    console.log('\n📥 RESPONSE RECEIVED');
    console.log('  HTTP Status:', response.status, response.statusText);
    
    if (!response.ok) {
      throw new Error(`Issuer responded with status ${response.status}`);
    }
    
    const data = await response.json();
    console.log('\n  Response Body:');
    console.log(JSON.stringify(data, null, 4).split('\n').map(l => '    ' + l).join('\n'));
    console.log('\n  Status:', data.status);
    
    // If approved, auto-store the credential with BBS+ metadata
    if (data.status === 'approved' && data.verifiableCredential) {
      console.log('\n═══════════════════════════════════════════════════════════════════');
      console.log('✅ CREDENTIAL APPROVED AND RECEIVED!');
      console.log('   Credential ID:', data.verifiableCredential.id);
      console.log('   Credential Type:', data.verifiableCredential.type.join(', '));
      
      // Generate commitment hash and blinding factor if not provided by issuer
      // This binds the credential to a random factor for the ZKP circuit
      let commitmentHash = data.commitmentHash;
      let blindingFactor = data.blindingFactor;
      
      if (!commitmentHash || !blindingFactor) {
        // Generate a blinding factor (random scalar)
        blindingFactor = randomBytes(32).toString('hex');
        // Create commitment hash = SHA256(credentialId || blindingFactor)
        const hash = createHash('sha256');
        hash.update(data.verifiableCredential.id);
        hash.update(Buffer.from(blindingFactor, 'hex'));
        commitmentHash = hash.digest('hex');
        console.log('   Commitment: Generated locally (not from issuer)');
      }
      
      // Store with all BBS+ metadata for hybrid proof generation
      const stored: StoredCredential = {
        id: data.verifiableCredential.id,
        credential: data.verifiableCredential,
        bbsSignature: data.bbsSignature,
        commitmentHash: commitmentHash,
        blindingFactor: blindingFactor,
        issuerPublicKey: data.bbsPublicKey,
        messageLabels: data.messageLabels,
        storedAt: new Date().toISOString(),
      };
      credentialStore.set(stored.id, stored);
      console.log('   Storage: ✓ Auto-stored in wallet');
      console.log('   Total credentials:', credentialStore.size);
      console.log('═══════════════════════════════════════════════════════════════════\n');
      
      return res.json({
        success: true,
        status: 'approved',
        credential: data.verifiableCredential,
        stored: true
      });
    }
    
    console.log('\n═══════════════════════════════════════════════════════════════════');
    console.log(`   Status: ${data.status.toUpperCase()}`);
    if (data.status === 'pending') {
      console.log('   Action: Continue polling until approved');
    }
    console.log('═══════════════════════════════════════════════════════════════════\n');
    
    res.json({
      success: true,
      status: data.status,
      requestedAt: data.requestedAt
    });
  } catch (error: any) {
    console.error('✗ Error checking request status:', error.message);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Store credential manually
router.post('/store', async (req: Request, res: Response) => {
  try {
    const { credential } = req.body;

    if (!credential || !credential.id) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid credential: missing id' 
      });
    }

    console.log('\n========== STORING CREDENTIAL ==========');
    console.log('Credential ID:', credential.id);

    const stored: StoredCredential = {
      id: credential.id,
      credential,
      storedAt: new Date().toISOString(),
    };

    credentialStore.set(stored.id, stored);
    console.log('✓ Credential stored successfully');
    console.log('Total credentials in wallet:', credentialStore.size);
    console.log('========== STORE COMPLETE ==========\n');

    res.json({ 
      success: true, 
      id: stored.id,
      storedAt: stored.storedAt,
    });
  } catch (error: any) {
    console.error('✗ Error storing credential:', error.message);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Get all credentials
router.get('/credentials', async (req: Request, res: Response) => {
  try {
    console.log('\n========== RETRIEVING ALL CREDENTIALS ==========');
    const credentials = Array.from(credentialStore.values());
    console.log('Total credentials:', credentials.length);
    console.log('========== RETRIEVAL COMPLETE ==========\n');

    res.json({ 
      success: true, 
      count: credentials.length,
      credentials 
    });
  } catch (error: any) {
    console.error('✗ Error retrieving credentials:', error.message);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Get specific credential
router.get('/credentials/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const stored = credentialStore.get(id);

    if (!stored) {
      return res.status(404).json({ 
        success: false, 
        error: 'Credential not found' 
      });
    }

    console.log('\n========== RETRIEVING CREDENTIAL ==========');
    console.log('Credential ID:', id);
    console.log('✓ Credential found');
    console.log('========== RETRIEVAL COMPLETE ==========\n');

    res.json({ 
      success: true, 
      ...stored 
    });
  } catch (error: any) {
    console.error('✗ Error retrieving credential:', error.message);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Verify credential with verifier service
router.post('/verify', async (req: Request, res: Response) => {
  try {
    const { credentialId, verifierUrl } = req.body;

    if (!credentialId) {
      return res.status(400).json({ 
        success: false, 
        error: 'Credential ID required' 
      });
    }

    const stored = credentialStore.get(credentialId);
    if (!stored) {
      return res.status(404).json({ 
        success: false, 
        error: 'Credential not found' 
      });
    }

    const url = verifierUrl || 'http://localhost:3002/proofs/verify';

    console.log('\n========== VERIFYING CREDENTIAL ==========');
    console.log('Verifier URL:', url);
    console.log('Credential ID:', credentialId);

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verifiableCredential: stored.credential }),
    });

    if (!response.ok) {
      throw new Error(`Verifier responded with status ${response.status}`);
    }

    const data = await response.json();
    console.log('✓ Verification result:', data.verified ? 'VALID' : 'INVALID');
    console.log('========== VERIFICATION COMPLETE ==========\n');

    res.json({
      success: true,
      ...data,
    });
  } catch (error: any) {
    console.error('✗ Error verifying credential:', error.message);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Delete credential
router.delete('/credentials/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    
    if (!credentialStore.has(id)) {
      return res.status(404).json({ 
        success: false, 
        error: 'Credential not found' 
      });
    }

    console.log('\n========== DELETING CREDENTIAL ==========');
    console.log('Credential ID:', id);
    
    credentialStore.delete(id);
    console.log('✓ Credential deleted');
    console.log('Remaining credentials:', credentialStore.size);
    console.log('========== DELETION COMPLETE ==========\n');

    res.json({ 
      success: true, 
      message: 'Credential deleted successfully' 
    });
  } catch (error: any) {
    console.error('✗ Error deleting credential:', error.message);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// ============================================================
// HYBRID AUTHENTICATION ENDPOINTS
// ============================================================

// Generate hybrid authentication proof (SNARK + BBS+)
router.post('/authenticate', async (req: Request, res: Response) => {
  try {
    const { 
      credentialId, 
      domain = 'default',
      holderDid = 'did:example:holder',
      revealedAttributes = []
    } = req.body;

    console.log('\n╔══════════════════════════════════════════════════════════════════╗');
    console.log('║         HYBRID AUTHENTICATION (Wallet Service)                   ║');
    console.log('╚══════════════════════════════════════════════════════════════════╝\n');

    // Step 1: Get the credential
    if (!credentialId) {
      // Use first available credential
      if (credentialStore.size === 0) {
        return res.status(400).json({ 
          success: false, 
          error: 'No credentials in wallet' 
        });
      }
      // Get first credential
    }

    const stored = credentialId 
      ? credentialStore.get(credentialId)
      : credentialStore.values().next().value;

    if (!stored) {
      return res.status(404).json({ 
        success: false, 
        error: 'Credential not found' 
      });
    }

    console.log('Step 1: Credential loaded');
    console.log(`  ID: ${stored.id}`);
    console.log(`  Has BBS+ data: ${!!stored.bbsSignature}`);

    // Step 1.5: Ensure master secret exists for this holder
    console.log('\nStep 1.5: Checking master secret...');
    const hasMasterSecret = await MasterSecretManager.hasMasterSecret(holderDid);
    if (!hasMasterSecret) {
      console.log('  Generating new master secret for holder...');
      await MasterSecretManager.generateMasterSecret(holderDid);
      console.log('  ✓ Master secret generated');
    } else {
      console.log('  ✓ Master secret exists');
    }

    // Step 2: Get challenge from verifier
    console.log('\nStep 2: Requesting challenge from verifier...');
    const verifierUrl = 'http://localhost:3002';
    
    const challengeRes = await fetch(`${verifierUrl}/auth/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });

    if (!challengeRes.ok) {
      throw new Error(`Failed to get challenge: ${challengeRes.status}`);
    }

    const challengeData = await challengeRes.json();
    if (!challengeData.success) {
      throw new Error(challengeData.error || 'Challenge failed');
    }

    // The challenge data is nested under challengeData.challenge
    const challengeObj = challengeData.challenge;
    console.log(`  ✓ Challenge received: ${challengeObj.challengeId}`);

    // Prepare challenge in the format expected by HybridProofGenerator
    const challenge = {
      challengeId: challengeObj.challengeId,
      challenge: challengeObj.challenge,
      domain: challengeObj.domain,
      registryRoot: challengeObj.registryRoot,
      circuitId: challengeObj.circuitId || 'halp-auth-v1',
      expiresAt: challengeObj.expiresAt,
      createdAt: Date.now()
    };

    // Step 3: Prepare credential for proof generation
    // Ensure we have all required fields or generate placeholders
    const sdkCredential: SDKStoredCredential = {
      id: stored.id,
      credential: stored.credential,
      bbsSignature: stored.bbsSignature || '',
      commitmentHash: stored.commitmentHash || generatePlaceholderHash(),
      blindingFactor: stored.blindingFactor || generatePlaceholderHash(),
      issuerPublicKey: stored.issuerPublicKey || ''
    };

    console.log('\nStep 3: Generating hybrid proof...');
    console.log(`  Circuit ready: ${proofGeneratorReady}`);

    // Step 4: Generate the hybrid proof
    const authPackage = await proofGenerator.generateHybridProof(
      holderDid,
      sdkCredential,
      challenge,
      revealedAttributes
    );

    console.log('\n✅ Hybrid proof generated successfully');

    // Step 5: Submit to verifier
    console.log('\nStep 5: Submitting proof to verifier...');
    
    const verifyRes = await fetch(`${verifierUrl}/proof/verify/hybrid`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(authPackage)
    });

    const verifyData = await verifyRes.json();

    if (verifyData.success || verifyData.verified) {
      console.log('\n✅ AUTHENTICATION SUCCESSFUL');
      res.json({
        success: true,
        verified: true,
        pseudonym: authPackage.pseudonym,
        nullifier: authPackage.nullifier,
        sessionToken: verifyData.sessionToken,
        message: 'Hybrid authentication successful'
      });
    } else {
      console.log('\n❌ AUTHENTICATION FAILED');
      console.log(`  Reason: ${verifyData.error || verifyData.reason || 'Unknown'}`);
      res.json({
        success: false,
        verified: false,
        error: verifyData.error || verifyData.reason || 'Verification failed',
        authPackage // Include for debugging
      });
    }

  } catch (error: any) {
    console.error('✗ Authentication error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Helper to generate placeholder hash (for credentials without commitment)
function generatePlaceholderHash(): string {
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Get authentication status (circuit availability)
router.get('/authenticate/status', async (req: Request, res: Response) => {
  res.json({
    success: true,
    circuitReady: proofGeneratorReady,
    credentialsCount: credentialStore.size,
    mode: proofGeneratorReady ? 'production' : 'demo'
  });
});

export default router;
