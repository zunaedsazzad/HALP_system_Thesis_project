import { FastifyPluginAsync } from 'fastify';
import didManager from '../services/did-manager';
import bbsPlusSigner from '../services/bbs-plus-signer';
import commitmentVerifier from '../services/commitment-verifier';

// Initialize commitment verifier with public parameters
commitmentVerifier.initialize();

// In-memory storage for pending credential requests
interface PendingRequest {
  id: string;
  subject: string;
  type: string;
  claim: any;
  requestedAt: string;
  requesterInfo?: any;
  status: 'pending' | 'approved' | 'rejected';
  isAnonymous?: boolean;
  pseudonym?: string;
  commitment?: string;
}

const pendingRequests = new Map<string, PendingRequest>();
const processedRequests = new Map<string, any>(); // Stores approved credentials

const credentialRoutes: FastifyPluginAsync = async (fastify) => {
  // Submit a credential request (user wallet submits this)
  fastify.post('/request', async (request, reply) => {
    console.log('\n╔══════════════════════════════════════════════════════════════════╗');
    console.log('║     API CALL RECEIVED: CREDENTIAL REQUEST (Wallet → Issuer)     ║');
    console.log('╚══════════════════════════════════════════════════════════════════╝');
    console.log('\n[Teacher Demo] Issuer Receiving Credential Request\n');
    console.log('📥 INCOMING HTTP REQUEST');
    console.log('  Method: POST');
    console.log('  Endpoint: /credentials/request');
    console.log('  Timestamp:', new Date().toISOString());
    
    const body = request.body as any || {};
    console.log('\n  Request Body:');
    console.log(JSON.stringify(body, null, 4).split('\n').map(l => '    ' + l).join('\n'));
    
    const requestId = `req-${generateUUID()}`;
    
    const pendingRequest: PendingRequest = {
      id: requestId,
      subject: body.subject || 'did:example:unknown',
      type: body.type || 'ExampleCredential',
      claim: body.claim || {},
      requestedAt: new Date().toISOString(),
      requesterInfo: body.requesterInfo || {},
      status: 'pending'
    };
    
    pendingRequests.set(requestId, pendingRequest);
    
    console.log('\n═══════════════════════════════════════════════════════════════════');
    console.log('✅ REQUEST QUEUED FOR APPROVAL');
    console.log('   Request ID:', requestId);
    console.log('   Subject DID:', pendingRequest.subject);
    console.log('   Credential Type:', pendingRequest.type);
    console.log('   Status: PENDING (waiting for issuer approval)');
    console.log('   Queue Position:', pendingRequests.size);
    console.log('═══════════════════════════════════════════════════════════════════\n');
    
    return {
      success: true,
      requestId,
      message: 'Credential request submitted. Waiting for issuer approval.',
      status: 'pending'
    };
  });

  // NEW ENDPOINT: Handle anonymous credential requests with commitment proofs
  fastify.post('/request-anonymous', async (request, reply) => {
    console.log('\n╔══════════════════════════════════════════════════════════════════╗');
    console.log('║  ANONYMOUS CREDENTIAL REQUEST RECEIVED (Issuer Side)           ║');
    console.log('╚══════════════════════════════════════════════════════════════════╝');
    console.log('\n[Teacher Demo] Privacy-Preserving Request Verification\n');

    const body = request.body as any || {};
    const {
      pseudonym,
      commitment,
      commitmentProof,
      credentialType,
      encryptedClaims,
      claimsHash,
      nonce,
      timestamp
    } = body;

    console.log('📋 Anonymous Request Details:');
    console.log(`   Credential Type: ${credentialType}`);
    console.log(`   Pseudonym: ${pseudonym?.substring(0, 24)}... (unlinkable)`);
    console.log(`   Commitment: ${commitment?.substring(0, 24)}... (hides master secret)`);
    console.log(`   Timestamp: ${new Date(timestamp).toISOString()}`);
    console.log('   ⚠️  Holder Identity: UNKNOWN (privacy-preserving)\n');

    // Validate required fields
    if (!pseudonym || !commitment || !commitmentProof || !credentialType || !encryptedClaims || !claimsHash || !nonce) {
      console.log('❌ REQUEST REJECTED: Missing required fields\n');
      return reply.code(400).send({
        success: false,
        error: 'Missing required fields for anonymous request'
      });
    }

    // Get issuer's private key for decryption
    const issuerPrivateKey = process.env.ISSUER_PRIVATE_KEY || 'default-issuer-private-key';

    // Verify the anonymous request using commitment verifier
    console.log('🔍 VERIFYING ANONYMOUS REQUEST...\n');
    
    const verification = await commitmentVerifier.verifyAnonymousRequest(
      pseudonym,
      commitment,
      commitmentProof,
      encryptedClaims,
      claimsHash,
      credentialType,
      nonce,
      issuerPrivateKey
    );

    if (!verification.valid) {
      console.log('❌ REQUEST REJECTED: Verification failed');
      console.log(`   Reason: ${verification.errorMessage}\n`);
      return reply.code(400).send({
        success: false,
        error: verification.errorMessage || 'Invalid commitment proof or claims'
      });
    }

    console.log('✅ VERIFICATION SUCCESSFUL - Creating pending request\n');

    // Create pending request (with pseudonym instead of DID)
    const requestId = `req-anon-${generateUUID()}`;
    const pendingRequest: PendingRequest = {
      id: requestId,
      subject: `nym:${pseudonym.substring(0, 16)}`, // Pseudonymous subject
      type: credentialType,
      claim: verification.decryptedClaims!,
      requestedAt: new Date().toISOString(),
      status: 'pending',
      isAnonymous: true,
      pseudonym: pseudonym,
      commitment: commitment
    };

    pendingRequests.set(requestId, pendingRequest);

    console.log('═══════════════════════════════════════════════════════════════════');
    console.log('✅ ANONYMOUS REQUEST ACCEPTED AND QUEUED');
    console.log(`   Request ID: ${requestId}`);
    console.log(`   Status: PENDING (awaiting issuer approval)`);
    console.log(`   Type: Anonymous (master secret bound)`);
    console.log(`   Queue Position: ${pendingRequests.size}`);
    console.log('\n🔒 Privacy Properties:');
    console.log('   ✓ Holder identity: Protected (only pseudonym known)');
    console.log('   ✓ Master secret: Never revealed (verified via ZK proof)');
    console.log('   ✓ Unlinkability: Cannot link to other requests');
    console.log('   ✓ Binding: Credential will be bound to master secret commitment');
    console.log('═══════════════════════════════════════════════════════════════════\n');

    return {
      success: true,
      requestId,
      message: 'Anonymous credential request accepted. Waiting for issuer approval.',
      status: 'pending',
      isAnonymous: true
    };
  });
  
  // Get all pending requests (for issuer UI)
  fastify.get('/pending', async (request, reply) => {
    const pending = Array.from(pendingRequests.values())
      .filter(req => req.status === 'pending')
      .sort((a, b) => new Date(b.requestedAt).getTime() - new Date(a.requestedAt).getTime());
    
    console.log(`\n📋 Fetching pending requests: ${pending.length} found`);
    const anonymousCount = pending.filter(r => r.isAnonymous).length;
    if (anonymousCount > 0) {
      console.log(`   Anonymous requests: ${anonymousCount} (privacy-preserving)`);
    }
    console.log('');
    
    return {
      success: true,
      count: pending.length,
      requests: pending
    };
  });
  
  // Approve and sign a credential request (issuer action)
  fastify.post('/approve', async (request, reply) => {
    console.log('\n╔══════════════════════════════════════════════════════════════════╗');
    console.log('║    ISSUER ACTION: APPROVING & SIGNING CREDENTIAL REQUEST        ║');
    console.log('╚══════════════════════════════════════════════════════════════════╝');
    console.log('\n[Teacher Demo] Complete Credential Issuance Process\n');
    
    const body = request.body as any || {};
    const requestId = body.requestId;
    
    console.log('📋 Request Details:');
    console.log('  Request ID:', requestId);
    
    const pendingReq = pendingRequests.get(requestId);
    if (!pendingReq) {
      console.log('  ❌ Request not found:', requestId);
      return reply.code(404).send({ success: false, error: 'Request not found' });
    }
    
    if (pendingReq.status !== 'pending') {
      console.log('  ❌ Request already processed:', pendingReq.status);
      return reply.code(400).send({ success: false, error: 'Request already processed' });
    }
    
    // Check if this is an anonymous request
    const isAnonymous = pendingReq.isAnonymous === true;
    console.log('  Request Type:', isAnonymous ? '🔒 ANONYMOUS (Privacy-Preserving)' : '📝 Standard');
    
    if (isAnonymous) {
      console.log('  🎭 Pseudonym:', pendingReq.pseudonym);
      console.log('  🔐 Commitment (first 32 chars):', pendingReq.commitment?.substring(0, 32) + '...');
      console.log('  ℹ️  Issuer CANNOT identify the holder - only knows they control the master secret');
    } else {
      console.log('  Subject DID:', pendingReq.subject);
    }
    
    console.log('  Credential Type:', pendingReq.type);
    console.log('  Claims:', JSON.stringify(pendingReq.claim, null, 4).split('\n').map(l => '    ' + l).join('\n'));
    
    console.log('\n[Step 1] Resolving issuer DID...');
    const { did: issuerDid } = await didManager.getOrCreateDefaultDid();
    console.log('  ✓ Issuer DID:', issuerDid);

    console.log('\n[Step 2] Creating W3C Verifiable Credential...');
    const credentialId = `urn:uuid:${generateUUID()}`;
    
    // For anonymous requests, use pseudonym-based subject ID
    const subjectId = isAnonymous 
      ? `nym:${pendingReq.pseudonym}`  // Pseudonymous identifier
      : pendingReq.subject;             // Traditional DID
    
    const verifiableCredential = {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://www.w3.org/ns/credentials/examples/v2',
        'https://w3id.org/security/bbs/v1'
      ],
      id: credentialId,
      type: ['VerifiableCredential', pendingReq.type],
      issuer: {
        id: issuerDid,
        name: body.issuerName || 'HALP Issuer'
      },
      validFrom: new Date().toISOString(),
      credentialSubject: {
        id: subjectId,
        ...pendingReq.claim
      }
    };
    
    if (isAnonymous) {
      console.log('  ✓ Created ANONYMOUS VC ID:', credentialId);
      console.log('  ✓ Subject Type: Pseudonymous (nym:...)');
      console.log('  ✓ Subject Pseudonym:', pendingReq.pseudonym);
      console.log('  ℹ️  This credential is UNLINKABLE to holder identity');
    } else {
      console.log('  ✓ Created VC ID:', credentialId);
      console.log('  ✓ Subject:', verifiableCredential.credentialSubject.id);
    }
    
    console.log('  ✓ VC Type:', verifiableCredential.type.join(', '));
    console.log('  ✓ Issuer:', verifiableCredential.issuer.id);
    console.log('  ✓ Claims:', Object.keys(pendingReq.claim).join(', '));

    console.log('\n[Step 3] Signing credential with BBS+...');
    console.log('  Algorithm: BBS+ Signatures (BLS12-381)');
    console.log('  Purpose: Enable selective disclosure');
    
    if (isAnonymous) {
      console.log('  🔗 MASTER SECRET BINDING: Signature will be bound to commitment');
      console.log('  🔐 Privacy Property: Only holder with master secret can use credential');
    }
    // Initialize BBS+ key pair if not already done
    let bbsKeyPair = bbsPlusSigner.getKeyPair();
    if (!bbsKeyPair) {
      console.log('  ⚙️  Generating BBS+ key pair (first time)...');
      bbsKeyPair = await bbsPlusSigner.generateKeyPair();
      console.log('  ✓ Key pair generated');
    } else {
      console.log('  ✓ Using existing BBS+ key pair');
    }
    
    console.log('  🔐 Creating BBS+ signature...');
    
    let bbsSignature: string;
    let messageLabels: string[];
    
    if (isAnonymous && pendingReq.commitment) {
      // For anonymous credentials, bind signature to master secret commitment
      console.log('  🔗 Binding signature to master secret commitment...');
      console.log('  📝 Commitment will be message[0] in BBS+ signature');
      console.log('  ℹ️  This ensures credential can ONLY be used by holder with matching master secret');
      
      // Sign with commitment as the first message
      bbsSignature = await bbsPlusSigner.signCredentialWithCommitment(
        verifiableCredential,
        pendingReq.commitment
      );
      
      // Get message labels with commitment included
      messageLabels = ['commitment', ...bbsPlusSigner.getMessageLabels(verifiableCredential)];
      
      console.log('  ✓ BBS+ signature created WITH commitment binding');
      console.log('  ✓ Credential is now BOUND to holder\'s master secret');
    } else {
      // Standard BBS+ signature without commitment binding
      bbsSignature = await bbsPlusSigner.signCredential(verifiableCredential);
      messageLabels = bbsPlusSigner.getMessageLabels(verifiableCredential);
      console.log('  ✓ BBS+ signature created (standard mode)');
    }
    
    console.log('\n  Message structure (for selective disclosure):');
    messageLabels.forEach((label, idx) => {
      const prefix = (isAnonymous && idx === 0) ? '🔒 ' : '   ';
      console.log(`  ${prefix}[${idx.toString().padStart(2)}] ${label}`);
    });

    // Create credential with BBS+ proof
    const credentialWithProof = {
      ...verifiableCredential,
      proof: {
        type: 'BbsBlsSignature2020',
        created: new Date().toISOString(),
        proofPurpose: 'assertionMethod',
        verificationMethod: `${issuerDid}#bbs-key-1`,
        proofValue: bbsSignature,
        ...(isAnonymous && { 
          commitmentBinding: true,
          privacyEnhanced: true 
        })
      }
    };

    // Update request status
    pendingReq.status = 'approved';
    processedRequests.set(credentialId, {
      requestId,
      verifiableCredential: credentialWithProof,
      bbsSignature,
      bbsPublicKey: Buffer.from(bbsKeyPair.publicKey).toString('base64'),
      messageLabels,
      approvedAt: new Date().toISOString(),
      isAnonymous,
      ...(isAnonymous && { 
        pseudonym: pendingReq.pseudonym,
        commitment: pendingReq.commitment 
      })
    });

    console.log('\n═══════════════════════════════════════════════════════════════════');
    console.log('✅ CREDENTIAL APPROVED AND SIGNED SUCCESSFULLY');
    console.log('   Request ID:', requestId);
    console.log('   Credential ID:', credentialId);
    console.log('   Format: W3C Verifiable Credential v2.0');
    console.log('   Signature: BBS+ (selective disclosure enabled)');
    console.log('   Proof Type:', credentialWithProof.proof.type);
    console.log('   Verification Method:', credentialWithProof.proof.verificationMethod);
    console.log('   Message Fields:', messageLabels.length);
    
    if (isAnonymous) {
      console.log('   🔒 Privacy Mode: ANONYMOUS');
      console.log('   🔗 Master Secret: BOUND (via commitment)');
      console.log('   🎭 Subject Type: Pseudonymous');
      console.log('   ℹ️  Holder identity is UNLINKABLE');
      console.log('   ✓ Only holder with master secret can use this credential');
    }
    
    console.log('   Status: APPROVED (ready for wallet retrieval)');
    console.log('═══════════════════════════════════════════════════════════════════\n');
    
    const response = { 
      success: true,
      issued: true, 
      verifiableCredential: credentialWithProof, 
      bbsSignature,
      bbsPublicKey: Buffer.from(bbsKeyPair.publicKey).toString('base64'),
      messageLabels,
      format: 'W3C-VC-v2.0-BBS+',
      requestId,
      ...(isAnonymous && { 
        isAnonymous: true,
        commitment: pendingReq.commitment,
        privacyEnhanced: true 
      })
    };
    
    return response;
  });
  
  // Reject a credential request (issuer action)
  fastify.post('/reject', async (request, reply) => {
    console.log('\n========== REJECTING CREDENTIAL REQUEST ==========');
    const body = request.body as any || {};
    const requestId = body.requestId;
    const reason = body.reason || 'No reason provided';
    
    const pendingReq = pendingRequests.get(requestId);
    if (!pendingReq) {
      console.log('❌ Request not found:', requestId);
      return reply.code(404).send({ success: false, error: 'Request not found' });
    }
    
    if (pendingReq.status !== 'pending') {
      console.log('❌ Request already processed:', pendingReq.status);
      return reply.code(400).send({ success: false, error: 'Request already processed' });
    }
    
    pendingReq.status = 'rejected';
    
    console.log('Request ID:', requestId);
    console.log('Subject:', pendingReq.subject);
    console.log('Reason:', reason);
    console.log('❌ REQUEST REJECTED');
    console.log('========== REJECTION COMPLETE ==========\n');
    
    return {
      success: true,
      requestId,
      message: 'Request rejected',
      reason
    };
  });
  
  // Check request status (for wallet polling)
  fastify.get('/request-status/:id', async (request, reply) => {
    const { id } = (request.params as any);
    
    console.log('\n========== REQUEST STATUS CHECK ==========');
    console.log('Request ID:', id);
    console.log('Total pending requests:', pendingRequests.size);
    console.log('Total processed requests:', processedRequests.size);
    
    const pendingReq = pendingRequests.get(id);
    
    if (!pendingReq) {
      console.log('❌ Request not found');
      console.log('Available request IDs:', Array.from(pendingRequests.keys()));
      console.log('========== STATUS CHECK COMPLETE ==========\n');
      return reply.code(404).send({ success: false, error: 'Request not found' });
    }
    
    console.log('✓ Request found');
    console.log('Status:', pendingReq.status);
    
    const response: any = {
      success: true,
      requestId: id,
      status: pendingReq.status,
      requestedAt: pendingReq.requestedAt
    };
    
    // If approved, include the credential
    if (pendingReq.status === 'approved') {
      const processed = Array.from(processedRequests.values())
        .find(p => p.requestId === id);
      if (processed) {
        console.log('✓ Including approved credential');
        response.verifiableCredential = processed.verifiableCredential;
        response.bbsSignature = processed.bbsSignature;
        response.bbsPublicKey = processed.bbsPublicKey;
        response.messageLabels = processed.messageLabels;
        response.format = 'W3C-VC-v2.0-BBS+';
      }
    }
    
    console.log('========== STATUS CHECK COMPLETE ==========\n');
    return response;
  });

  // Legacy direct issue endpoint (for backward compatibility)
  fastify.post('/issue', async (request, reply) => {
    console.log('\n========== DIRECT CREDENTIAL ISSUANCE (LEGACY) ==========');
    console.log('⚠️  Using legacy direct issuance - consider using /request flow');
    console.log('Timestamp:', new Date().toISOString());
    console.log('Request body:', JSON.stringify(request.body, null, 2));
    
    const body = request.body as any || {};

    console.log('\n[Step 1] Resolving issuer DID...');
    const { did: issuerDid } = await didManager.getOrCreateDefaultDid();
    console.log('Issuer DID:', issuerDid);

    console.log('\n[Step 2] Creating W3C Verifiable Credential...');
    const credentialId = `urn:uuid:${generateUUID()}`;
    const verifiableCredential = {
      '@context': [
        'https://www.w3.org/ns/credentials/v2',
        'https://www.w3.org/ns/credentials/examples/v2',
        'https://w3id.org/security/bbs/v1'
      ],
      id: credentialId,
      type: ['VerifiableCredential', body.type || 'ExampleCredential'],
      issuer: {
        id: issuerDid,
        name: body.issuerName || 'HALP Issuer'
      },
      validFrom: new Date().toISOString(),
      credentialSubject: {
        id: body.subject || 'did:example:holder',
        ...(body.claim || {})
      }
    };
    console.log('Created VC ID:', credentialId);
    console.log('VC Type:', verifiableCredential.type);
    console.log('Subject:', verifiableCredential.credentialSubject.id);
    console.log('Valid From:', verifiableCredential.validFrom);

    console.log('\n[Step 3] Signing credential with BBS+...');
    // Initialize BBS+ key pair if not already done
    let bbsKeyPair = bbsPlusSigner.getKeyPair();
    if (!bbsKeyPair) {
      bbsKeyPair = await bbsPlusSigner.generateKeyPair();
    }
    
    // Create BBS+ signature
    const bbsSignature = await bbsPlusSigner.signCredential(verifiableCredential);
    const messageLabels = bbsPlusSigner.getMessageLabels(verifiableCredential);
    console.log('✓ BBS+ signature created');

    // Create credential with BBS+ proof
    const credentialWithProof = {
      ...verifiableCredential,
      proof: {
        type: 'BbsBlsSignature2020',
        created: new Date().toISOString(),
        proofPurpose: 'assertionMethod',
        verificationMethod: `${issuerDid}#bbs-key-1`,
        proofValue: bbsSignature
      }
    };

    console.log('\n[Step 4] Credential issued successfully!');
    console.log('Format: W3C-VC-v2.0 + BBS+');
    console.log('Signing: BBS+ (selective disclosure)');
    console.log('========== ISSUANCE COMPLETE ==========\n');
    
    return { 
      issued: true, 
      verifiableCredential: credentialWithProof, 
      bbsSignature,
      bbsPublicKey: Buffer.from(bbsKeyPair.publicKey).toString('base64'),
      messageLabels,
      format: 'W3C-VC-v2.0-BBS+'
    };
  });

  fastify.get('/status/:id', async (request, reply) => {
    const { id } = (request.params as any);
    console.log('\n========== CREDENTIAL STATUS CHECK ==========');
    console.log('Credential ID:', id);
    console.log('Status: stub (not implemented)');
    console.log('========== STATUS CHECK COMPLETE ==========\n');
    return { id, status: 'stub' };
  });
};

// Helper function to generate UUIDs for W3C VC IDs
function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

export default credentialRoutes;
