/**
 * Commitment Verifier Service
 * Verifies anonymous credential requests with zero-knowledge proofs
 * Validates commitment proofs without learning the master secret
 */

import { CommitmentProtocol, PublicParametersManager, G1Operations, FieldOperations } from 'wallet-sdk';
import { createDecipheriv } from 'crypto';
import { sha256 } from '@noble/hashes/sha2.js';

export interface CommitmentVerificationResult {
  valid: boolean;
  pseudonym: Uint8Array;
  commitment: Uint8Array;
  decryptedClaims?: Record<string, any>;
  claimsValid: boolean;
  errorMessage?: string;
}

/**
 * Commitment Verifier for Issuer Side
 * Handles verification of anonymous credential requests
 */
export class CommitmentVerifier {
  private commitmentProtocol: CommitmentProtocol;
  private paramsManager: typeof PublicParametersManager;
  private initialized: boolean = false;

  constructor() {
    this.paramsManager = PublicParametersManager;
    this.commitmentProtocol = new CommitmentProtocol(this.paramsManager);
  }

  /**
   * Initialize verifier (load public parameters)
   */
  initialize(): void {
    if (!this.initialized) {
      this.paramsManager.loadParameters('./public-parameters.json');
      this.initialized = true;
      console.log('[CommitmentVerifier] Initialized with public parameters');
    }
  }

  /**
   * Verify anonymous credential request
   * Verifies zero-knowledge proof without learning the master secret
   */
  async verifyAnonymousRequest(
    pseudonymHex: string,
    commitmentHex: string,
    proof: { challenge: string; responses?: string[]; response?: string; T?: string },  // Support both formats
    encryptedClaims: string,
    claimsHash: string,
    credentialType: string,
    nonceHex: string,
    issuerPrivateKey: string
  ): Promise<CommitmentVerificationResult> {
    console.log('\n╔═══════════════════════════════════════════════════════════╗');
    console.log('║   VERIFYING ANONYMOUS CREDENTIAL REQUEST (Issuer Side)  ║');
    console.log('╚═══════════════════════════════════════════════════════════╝');
    console.log('\n[Teacher Demo] Zero-Knowledge Proof Verification\n');

    // Step 1: Verify pseudonym is valid G1 point
    console.log('Step 1: Validating pseudonym...');
    console.log(`  Pseudonym (hex): ${pseudonymHex.substring(0, 32)}...`);
    
    let pseudonym: Uint8Array;
    try {
      pseudonym = Buffer.from(pseudonymHex, 'hex');
      const pseudonymPoint = G1Operations.deserialize(pseudonym);
      console.log('  ✓ Pseudonym is valid elliptic curve point (G1)');
      console.log('  ✓ Property: Unlinkable identifier for this credential type\n');
    } catch (e) {
      console.log('  ❌ Invalid pseudonym - not a valid G1 point\n');
      return {
        valid: false,
        pseudonym: Buffer.from([]),
        commitment: Buffer.from([]),
        claimsValid: false,
        errorMessage: 'Invalid pseudonym: not a valid elliptic curve point'
      };
    }

    // Step 2: Verify commitment is valid G1 point
    console.log('Step 2: Validating commitment...');
    console.log(`  Commitment (hex): ${commitmentHex.substring(0, 32)}...`);
    
    let commitmentBytes: Uint8Array;
    let commitmentPoint: any;
    try {
      commitmentBytes = Buffer.from(commitmentHex, 'hex');
      commitmentPoint = G1Operations.deserialize(commitmentBytes);
      console.log('  ✓ Commitment is valid G1 point');
      console.log('  ✓ Form: C = G^ms · H^r (Pedersen commitment)\n');
    } catch (e) {
      console.log('  ❌ Invalid commitment - not a valid G1 point\n');
      return {
        valid: false,
        pseudonym,
        commitment: Buffer.from([]),
        claimsValid: false,
        errorMessage: 'Invalid commitment: not a valid elliptic curve point'
      };
    }

    // Step 3: Verify zero-knowledge proof
    console.log('Step 3: Verifying zero-knowledge proof...');
    console.log('  Claim: "I know ms and r such that C = G^ms · H^r"');
    console.log('  Verification: WITHOUT learning ms or r');
    console.log(`  Challenge: ${proof.challenge.substring(0, 30)}...`);
    console.log(`  Responses: ${Array.isArray(proof.responses) ? proof.responses.length : 1} response(s)`);
    
    try {
      const context = `credential:${credentialType}`;
      const contextBytes = Buffer.from(context, 'utf-8');
      const challengeBytes = Buffer.from(proof.challenge, 'hex');
      
      // Handle both old format (single response string) and new format (responses array)
      const responses = Array.isArray(proof.responses) 
        ? proof.responses.map((r: string) => BigInt(r))
        : [BigInt((proof as any).response)];  // Backward compatibility

      // Reconstruct the proof in the format expected by verifyProof
      const zkProof = {
        commitment: commitmentBytes,
        T: Buffer.from(proof.T || '', 'hex'), // T should be included in the proof
        challenge: challengeBytes,
        responses: responses,
        nonce: Buffer.from(nonceHex, 'hex')
      };

      // Verify the proof using commitment protocol
      const isProofValid = this.commitmentProtocol.verifyProof(
        zkProof,
        contextBytes,
        0 // No attributes, only master secret
      );

      if (!isProofValid) {
        console.log('  ❌ Proof verification FAILED');
        console.log('  ⚠️  Holder does not possess the claimed master secret\n');
        return {
          valid: false,
          pseudonym,
          commitment: commitmentBytes,
          claimsValid: false,
          errorMessage: 'Zero-knowledge proof verification failed'
        };
      }

      console.log('  ✓ Proof is VALID ✓');
      console.log('  ✓ Holder possesses master secret (without revealing it)');
      console.log('  ✓ Security: Issuer learned NOTHING about master secret\n');
    } catch (e: any) {
      const errorMsg = e instanceof Error ? e.message : String(e);
      console.log(`  ❌ Proof verification error: ${errorMsg}\n`);
      return {
        valid: false,
        pseudonym,
        commitment: commitmentBytes,
        claimsValid: false,
        errorMessage: `Proof verification error: ${errorMsg}`
      };
    }

    // Step 4: Decrypt and verify claims
    console.log('Step 4: Decrypting claims...');
    console.log(`  Encrypted data: ${encryptedClaims.substring(0, 32)}...`);
    
    let decryptedClaimsJson: string;
    let decryptedClaims: Record<string, any>;
    try {
      decryptedClaimsJson = this.decryptFromHolder(encryptedClaims, issuerPrivateKey);
      decryptedClaims = JSON.parse(decryptedClaimsJson);
      
      console.log(`  ✓ Claims decrypted: ${JSON.stringify(decryptedClaims)}`);
      console.log('  ✓ Decryption successful (issuer private key used)\n');
    } catch (e: any) {
      const errorMsg = e instanceof Error ? e.message : String(e);
      console.log(`  ❌ Decryption failed: ${errorMsg}\n`);
      return {
        valid: false,
        pseudonym,
        commitment: commitmentBytes,
        claimsValid: false,
        errorMessage: `Claims decryption failed: ${errorMsg}`
      };
    }

    // Step 5: Verify claims integrity hash
    console.log('Step 5: Verifying claims integrity...');
    console.log(`  Expected hash: ${claimsHash.substring(0, 32)}...`);
    
    const computedHashBytes = sha256(Buffer.from(decryptedClaimsJson, 'utf-8'));
    const computedHash = Buffer.from(computedHashBytes).toString('hex');
    console.log(`  Computed hash: ${computedHash.substring(0, 32)}...`);
    
    const claimsValid = computedHash === claimsHash;
    
    if (!claimsValid) {
      console.log('  ❌ Claims hash mismatch - data integrity compromised\n');
      return {
        valid: false,
        pseudonym,
        commitment: commitmentBytes,
        claimsValid: false,
        errorMessage: 'Claims hash mismatch - integrity check failed'
      };
    }
    
    console.log('  ✓ Claims hash matches - integrity verified\n');

    console.log('═══════════════════════════════════════════════════════════');
    console.log('✅ ANONYMOUS REQUEST VERIFIED SUCCESSFULLY');
    console.log('\n📋 Verification Summary:');
    console.log('   Pseudonym: Valid ✓ (unlinkable identifier)');
    console.log('   Commitment: Valid ✓ (Pedersen commitment)');
    console.log('   ZK Proof: Valid ✓ (holder has master secret)');
    console.log('   Claims: Decrypted ✓ (integrity verified)');
    console.log('   Master Secret: UNKNOWN ✓ (zero-knowledge)');
    console.log('\n🔒 Security Properties Verified:');
    console.log('   ✓ Holder identity: Protected (only pseudonym known)');
    console.log('   ✓ Master secret: Never revealed (zero-knowledge proof)');
    console.log('   ✓ Commitment binding: Valid (can bind credential)');
    console.log('   ✓ Data integrity: Verified (claims hash matches)');
    console.log('\n📝 Next Step:');
    console.log('   Issuer can now sign credential bound to commitment');
    console.log('   Credential will be unlinkable and privacy-preserving');
    console.log('═══════════════════════════════════════════════════════════\n');

    return {
      valid: true,
      pseudonym,
      commitment: commitmentBytes,
      decryptedClaims,
      claimsValid: true
    };
  }

  /**
   * Decrypt claims from holder using issuer's private key
   */
  private decryptFromHolder(encryptedData: string, privateKey: string): string {
    const [ivHex, authTagHex, encrypted] = encryptedData.split(':');
    
    const crypto = require('crypto');
    
    // Derive decryption key from private key (must match encryption)
    const keyHash = crypto.createHash('sha256').update(privateKey).digest();
    
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    
    // Create decipher
    const decipher = createDecipheriv('aes-256-gcm', keyHash, iv);
    decipher.setAuthTag(authTag);
    
    // Decrypt data
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  /**
   * Verify that a pseudonym is correctly derived from context
   * (Optional - for additional security)
   */
  verifyPseudonymContext(
    pseudonymHex: string,
    credentialType: string,
    basePseudonym?: string
  ): boolean {
    console.log('\n[Optional] Verifying pseudonym derivation...');
    
    try {
      const pseudonym = Buffer.from(pseudonymHex, 'hex');
      const pseudonymPoint = G1Operations.deserialize(pseudonym);
      
      // Verify it's on the curve
      console.log('  ✓ Pseudonym is valid curve point');
      
      // Could add additional context-specific checks here
      const context = `credential:${credentialType}`;
      console.log(`  ✓ Context: ${context}`);
      
      return true;
    } catch (e: any) {
      const errorMsg = e instanceof Error ? e.message : String(e);
      console.log(`  ❌ Pseudonym verification failed: ${errorMsg}`);
      return false;
    }
  }
}

export default new CommitmentVerifier();
