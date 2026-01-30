/**
 * Nullifier Manager for HALP Authentication
 * 
 * Nullifiers prevent double-spending/replay attacks by creating a unique,
 * deterministic identifier for each authentication session that can be
 * stored in the registry to prevent reuse.
 * 
 * Nullifier = Poseidon(credentialId, sessionNonce, domain)
 */

import { FieldOperations, CryptoUtils } from './crypto-utils';
import PoseidonHash from './poseidon-hash';

export interface NullifierData {
  /** The computed nullifier (hex encoded) */
  nullifier: string;
  /** Raw nullifier as bigint */
  nullifierRaw: bigint;
  /** Credential ID used */
  credentialId: string;
  /** Session nonce used */
  sessionNonce: bigint;
  /** Domain used */
  domain: string;
}

/**
 * Nullifier Manager
 * Handles nullifier derivation for authentication sessions
 */
export class NullifierManager {
  /**
   * Derive a nullifier for an authentication session
   * 
   * The nullifier is deterministically computed from:
   * - Credential ID: Unique identifier of the credential being used
   * - Session Nonce: Fresh random nonce for this session
   * - Domain: Service domain being authenticated to
   * 
   * Formula: Nf = Poseidon(H(credID), nonce, H(domain))
   * 
   * @param credentialId - Unique credential identifier
   * @param sessionNonce - Fresh session nonce
   * @param domain - Service domain identifier
   * @returns NullifierData containing the nullifier
   */
  static deriveNullifier(
    credentialId: string,
    sessionNonce: bigint,
    domain: string
  ): NullifierData {
    console.log('\n┌─────────────────────────────────────────────────────────┐');
    console.log('│         NULLIFIER DERIVATION (Demo)                     │');
    console.log('└─────────────────────────────────────────────────────────┘\n');
    
    console.log('Purpose: Create unique, unlinkable session identifier');
    console.log('Property: Prevents replay attacks (double-spending)\n');
    
    // Hash credential ID to field element
    console.log('Step 1: Encode credential ID to field element');
    console.log(`  Credential ID: ${credentialId}`);
    const credIdField = PoseidonHash.hashString(credentialId);
    console.log(`  H(credID): ${credIdField.toString().substring(0, 30)}...`);
    
    // Hash domain to field element
    console.log('\nStep 2: Encode domain to field element');
    console.log(`  Domain: ${domain}`);
    const domainField = PoseidonHash.hashString(domain);
    console.log(`  H(domain): ${domainField.toString().substring(0, 30)}...`);
    
    // Ensure nonce is in field
    console.log('\nStep 3: Session nonce (already in field)');
    const nonceField = sessionNonce % FieldOperations.FIELD_MODULUS;
    console.log(`  Nonce: ${nonceField.toString().substring(0, 30)}...`);
    
    // Compute nullifier using Poseidon hash
    console.log('\nStep 4: Compute nullifier');
    console.log('  Formula: Nf = Poseidon(H(credID), nonce, H(domain))');
    const nullifierRaw = PoseidonHash.hash3(credIdField, nonceField, domainField);
    const nullifier = PoseidonHash.toHex(nullifierRaw);
    
    console.log(`  ✓ Nullifier computed`);
    console.log(`  Nullifier (hex): ${nullifier.substring(0, 32)}...`);
    
    console.log('\n─────────────────────────────────────────────────────────');
    console.log('✅ NULLIFIER DERIVED');
    console.log(`   Length: 32 bytes (256 bits)`);
    console.log(`   Uniqueness: Guaranteed per (cred, nonce, domain) tuple`);
    console.log('─────────────────────────────────────────────────────────\n');
    
    return {
      nullifier,
      nullifierRaw,
      credentialId,
      sessionNonce,
      domain
    };
  }
  
  /**
   * Generate a fresh session nonce
   * 
   * @returns Random session nonce in BLS12-381 scalar field
   */
  static generateSessionNonce(): bigint {
    console.log('\n[Nullifier] Generating fresh session nonce...');
    const nonce = FieldOperations.randomScalar();
    console.log(`  ✓ Nonce generated: ${nonce.toString().substring(0, 25)}...`);
    return nonce;
  }
  
  /**
   * Verify nullifier computation (for testing)
   * 
   * @param credentialId - Credential ID
   * @param sessionNonce - Session nonce
   * @param domain - Domain
   * @param expectedNullifier - Expected nullifier hex
   * @returns True if nullifier matches
   */
  static verifyNullifier(
    credentialId: string,
    sessionNonce: bigint,
    domain: string,
    expectedNullifier: string
  ): boolean {
    const computed = this.deriveNullifier(credentialId, sessionNonce, domain);
    return computed.nullifier === expectedNullifier;
  }
}

export default NullifierManager;
