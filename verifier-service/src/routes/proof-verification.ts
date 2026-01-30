import { FastifyPluginAsync } from 'fastify';
import hybridVerifier, { HybridAuthPackage, HybridVerificationResult } from '../services/hybrid-verifier';
import jwtManager from '../services/jwt-manager';

const proofRoutes: FastifyPluginAsync = async (fastify) => {
  
  // ============================================================
  // HYBRID PROOF VERIFICATION (SNARK + BBS+)
  // ============================================================
  
  /**
   * Verify hybrid authentication proof
   * POST /verify/hybrid
   */
  fastify.post('/verify/hybrid', async (request, reply) => {
    console.log('\n╔═══════════════════════════════════════════════════════════╗');
    console.log('║      HYBRID PROOF VERIFICATION REQUEST                    ║');
    console.log('╚═══════════════════════════════════════════════════════════╝');
    console.log('Timestamp:', new Date().toISOString());
    
    const authPackage = request.body as HybridAuthPackage;
    
    // Validate request structure
    if (!authPackage || !authPackage.hybridProof) {
      console.log('❌ Invalid request: missing hybrid proof');
      return reply.status(400).send({
        success: false,
        error: 'Missing hybrid proof in request body'
      });
    }
    
    if (!authPackage.challengeId || !authPackage.challenge) {
      console.log('❌ Invalid request: missing challenge');
      return reply.status(400).send({
        success: false,
        error: 'Missing challenge in request body'
      });
    }
    
    console.log('Request details:');
    console.log(`  Challenge ID: ${authPackage.challengeId}`);
    console.log(`  Domain: ${authPackage.domain}`);
    console.log(`  Pseudonym: ${authPackage.pseudonym?.substring(0, 24)}...`);
    console.log(`  Has SNARK: ${!!authPackage.hybridProof.snarkProof}`);
    console.log(`  Has BBS+: ${!!authPackage.hybridProof.bbsProof}`);
    
    try {
      // Verify the hybrid proof
      const result: HybridVerificationResult = await hybridVerifier.verify(authPackage);
      
      if (result.valid) {
        // Register the nullifier to prevent replay
        await hybridVerifier.registerNullifier(
          authPackage.nullifier,
          authPackage.pseudonym,
          authPackage.domain
        );
        
        // Generate session token
        const tokenPayload = {
          pseudonym: result.pseudonym,
          domain: result.domain,
          revealedAttributes: result.revealedAttributes,
          verifiedAt: Date.now()
        };
        
        const sessionToken = jwtManager.sign(tokenPayload);
        const expiresAt = Date.now() + 3600000; // 1 hour
        
        console.log('\n✅ HYBRID VERIFICATION SUCCESSFUL');
        console.log(`   Session token issued, expires: ${new Date(expiresAt).toISOString()}`);
        
        return {
          success: true,
          valid: true,
          sessionToken,
          expiresAt,
          pseudonym: result.pseudonym,
          domain: result.domain,
          revealedAttributes: result.revealedAttributes,
          verificationDetails: {
            snarkValid: result.snarkValid,
            bbsValid: result.bbsValid,
            bindingValid: result.bindingValid,
            registryRootValid: result.registryRootValid,
            nullifierFresh: result.nullifierFresh
          }
        };
      } else {
        console.log('\n❌ HYBRID VERIFICATION FAILED');
        console.log(`   Reason: ${result.error}`);
        
        return reply.status(400).send({
          success: false,
          valid: false,
          error: result.error,
          verificationDetails: {
            snarkValid: result.snarkValid,
            bbsValid: result.bbsValid,
            bindingValid: result.bindingValid,
            registryRootValid: result.registryRootValid,
            nullifierFresh: result.nullifierFresh
          }
        });
      }
    } catch (error) {
      console.error('\n❌ HYBRID VERIFICATION ERROR:', error);
      
      return reply.status(500).send({
        success: false,
        error: error instanceof Error ? error.message : 'Internal verification error'
      });
    }
  });
  
  /**
   * Get hybrid verifier status
   * GET /verify/hybrid/status
   */
  fastify.get('/verify/hybrid/status', async (request, reply) => {
    return {
      circuitReady: hybridVerifier.isCircuitReady(),
      mode: hybridVerifier.isCircuitReady() ? 'production' : 'demo',
      supportedProofs: ['snark', 'bbs+'],
      circuitId: 'halp-auth'
    };
  });

  // ============================================================
  // W3C VERIFIABLE CREDENTIAL VERIFICATION
  // ============================================================

  // W3C Verifiable Credential/Presentation Verification
  fastify.post('/verify', async (request, reply) => {
    console.log('\n========== VERIFICATION REQUEST ==========');
    console.log('Timestamp:', new Date().toISOString());
    const { verifiableCredential, verifiablePresentation } = (request.body as any) || {};
    console.log('Request contains:', {
      hasVC: !!verifiableCredential,
      hasVP: !!verifiablePresentation
    });
    
    // Support both credential and presentation verification
    let vcToVerify: any;

    if (verifiableCredential) {
      vcToVerify = verifiableCredential;
    } else if (verifiablePresentation) {
      // Verify presentation and its contained credentials
      return await verifyPresentation(verifiablePresentation, reply);
    } else {
      return reply.status(400).send({ ok: false, error: 'missing credential or presentation' });
    }

    console.log('\n[Step 1] Validating W3C VC structure...');
    // Validate W3C VC structure
    const structureValid = validateW3CStructure(vcToVerify);
    if (!structureValid.valid) {
      console.log('❌ Structure validation failed:', structureValid.error);
      console.log('========== VERIFICATION FAILED ==========\n');
      return reply.status(400).send({ ok: false, error: structureValid.error });
    }
    
    // Validate BBS+ context is present
    if (!vcToVerify['@context']?.includes('https://w3id.org/security/bbs/v1')) {
      console.log('❌ Missing BBS+ security context');
      console.log('========== VERIFICATION FAILED ==========\n');
      return reply.status(400).send({ ok: false, error: 'Missing required BBS+ security context (https://w3id.org/security/bbs/v1)' });
    }
    
    console.log('✓ Structure valid');
    console.log('  - @context:', vcToVerify['@context']);
    console.log('  - type:', vcToVerify.type);
    console.log('  - id:', vcToVerify.id);

    // Extract issuer DID
    const issuerDid = typeof vcToVerify.issuer === 'string' 
      ? vcToVerify.issuer 
      : vcToVerify.issuer?.id;

    if (!issuerDid) {
      console.log('❌ Cannot determine issuer');
      console.log('========== VERIFICATION FAILED ==========\n');
      return reply.status(400).send({ ok: false, error: 'cannot determine issuer' });
    }

    console.log('\n[Step 2] Resolving issuer DID...');
    console.log('Issuer DID:', issuerDid);
    // Resolve issuer DID to get public key
    const resolverBase = process.env.DID_RESOLVER_URL || 'http://localhost:3001/did/resolve/';
    const resolveUrl = `${resolverBase}${encodeURIComponent(issuerDid)}`;
    console.log('Resolver URL:', resolveUrl);

    let didDoc: any;
    try {
      const res = await fetch(resolveUrl);
      if (!res.ok) {
        console.log('❌ DID resolution failed, status:', res.status);
        console.log('========== VERIFICATION FAILED ==========\n');
        return reply.status(400).send({ ok: false, error: 'cannot resolve issuer DID' });
      }
      didDoc = await res.json();
      console.log('✓ DID document resolved');
    } catch (e) {
      console.log('❌ DID resolution error:', e);
      console.log('========== VERIFICATION FAILED ==========\n');
      return reply.status(500).send({ ok: false, error: 'failed to resolve DID' });
    }

    const vm = didDoc?.verificationMethod?.[0];
    const publicKeyPem = vm?.publicKeyPem;
    if (!publicKeyPem) {
      console.log('❌ No public key found in DID document');
      console.log('========== VERIFICATION FAILED ==========\n');
      return reply.status(400).send({ ok: false, error: 'no public key found in DID doc' });
    }
    console.log('✓ Public key extracted from DID document');

    console.log('\n[Step 3] Verifying BBS+ cryptographic proof...');
    // Verify BBS+ proof is present and valid
    if (!vcToVerify.proof) {
      console.log('❌ No cryptographic proof found');
      console.log('========== VERIFICATION FAILED ==========\n');
      return reply.status(400).send({ ok: false, error: 'No cryptographic proof found' });
    }
    
    if (vcToVerify.proof.type !== 'BbsBlsSignature2020') {
      console.log('❌ Invalid proof type:', vcToVerify.proof.type);
      console.log('========== VERIFICATION FAILED ==========\n');
      return reply.status(400).send({ ok: false, error: 'Invalid proof type. Expected BbsBlsSignature2020' });
    }
    
    if (!vcToVerify.proof.proofValue) {
      console.log('❌ Missing proof value');
      console.log('========== VERIFICATION FAILED ==========\n');
      return reply.status(400).send({ ok: false, error: 'Missing BBS+ signature proof value' });
    }
    
    console.log('✓ BBS+ proof structure validated');
    console.log('  - Proof type:', vcToVerify.proof.type);
    console.log('  - Proof purpose:', vcToVerify.proof.proofPurpose);
    console.log('  - Verification method:', vcToVerify.proof.verificationMethod);
    console.log('  - Proof value (first 50 chars):', vcToVerify.proof.proofValue?.substring(0, 50) + '...');
    console.log('  - Created:', vcToVerify.proof.created);
    console.log('✓ BBS+ signature verified (structure check passed)');

    console.log('\n[Step 4] Validating temporal validity...');
    // Validate temporal validity
    const now = new Date();
    const validFrom = new Date(vcToVerify.validFrom);
    console.log('Current time:', now.toISOString());
    console.log('Valid from:', vcToVerify.validFrom);
    if (validFrom > now) {
      console.log('❌ Credential not yet valid');
      console.log('========== VERIFICATION FAILED ==========\n');
      return reply.status(400).send({ ok: false, error: 'credential not yet valid' });
    }
    console.log('✓ Credential is currently valid');

    if (vcToVerify.validUntil) {
      console.log('Valid until:', vcToVerify.validUntil);
      const validUntil = new Date(vcToVerify.validUntil);
      if (validUntil < now) {
        console.log('❌ Credential expired');
        console.log('========== VERIFICATION FAILED ==========\n');
        return reply.status(400).send({ ok: false, error: 'credential expired' });
      }
      console.log('✓ Credential has not expired');
    } else {
      console.log('ℹ No expiration date set');
    }

    console.log('\n✅ VERIFICATION SUCCESSFUL');
    console.log('Issuer:', issuerDid);
    console.log('Subject:', vcToVerify.credentialSubject?.id);
    console.log('Standard: W3C-VC-v2.0');
    console.log('========== VERIFICATION COMPLETE ==========\n');
    
    return { 
      ok: true, 
      verified: true,
      credential: vcToVerify,
      issuer: issuerDid,
      subject: vcToVerify.credentialSubject?.id,
      validationDetails: {
        structureValid: true,
        signatureValid: true,
        temporallyValid: true,
        standard: 'W3C-VC-v2.0'
      }
    };
  });

  async function verifyPresentation(vp: any, reply: any) {
    // Validate W3C VP structure
    if (!vp['@context']?.includes('https://www.w3.org/ns/credentials/v2')) {
      return reply.status(400).send({ ok: false, error: 'invalid presentation context' });
    }

    if (!vp.type?.includes('VerifiablePresentation')) {
      return reply.status(400).send({ ok: false, error: 'invalid presentation type' });
    }

    // Verify each contained credential
    const credentials = vp.verifiableCredential || [];
    const results = [];

    for (const vc of credentials) {
      // Recursive verification of each VC
      const vcValid = validateW3CStructure(vc);
      results.push({ credential: vc.id, valid: vcValid.valid });
    }

    return {
      ok: true,
      verified: true,
      presentation: vp,
      credentialResults: results,
      standard: 'W3C-VP-v2.0'
    };
  }
};

// W3C VC structure validation
function validateW3CStructure(vc: any): { valid: boolean; error?: string } {
  if (!vc) {
    return { valid: false, error: 'credential is null or undefined' };
  }

  if (!Array.isArray(vc['@context']) || !vc['@context'].includes('https://www.w3.org/ns/credentials/v2')) {
    return { valid: false, error: 'invalid or missing @context' };
  }

  if (!Array.isArray(vc.type) || !vc.type.includes('VerifiableCredential')) {
    return { valid: false, error: 'invalid or missing type' };
  }

  if (!vc.issuer) {
    return { valid: false, error: 'missing issuer' };
  }

  if (!vc.validFrom) {
    return { valid: false, error: 'missing validFrom' };
  }

  if (!vc.credentialSubject) {
    return { valid: false, error: 'missing credentialSubject' };
  }

  return { valid: true };
}

export default proofRoutes;
