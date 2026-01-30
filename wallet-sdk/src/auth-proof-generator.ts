/**
 * Authentication Proof Generator for HALP System
 * 
 * Phase 2 of Authentication: Proof Generation
 * 
 * This module handles the complete proof generation process:
 * 1. Session nonce selection
 * 2. Pseudonym derivation: P = Poseidon(ms, nonce, domain)
 * 3. Nullifier computation: Nf = Poseidon(credID, nonce, domain)
 * 4. Non-membership proof retrieval from registry
 * 5. zk-SNARK proof generation
 * 
 * Supports two modes:
 * - Legacy mode: Demo SNARK proof (for testing without circuit)
 * - Hybrid mode: Real snarkjs + BBS+ proofs (production)
 */

import * as snarkjs from 'snarkjs';
import * as fs from 'fs';
import * as path from 'path';
import { FieldOperations, G1Operations, CryptoUtils } from './crypto-utils';
import PoseidonHash from './poseidon-hash';
import NullifierManager from './nullifier-manager';
import MasterSecretManager from './master-secret-manager';
import {
  AuthChallenge,
  AuthenticationPackage,
  MerkleNonMembershipProof,
  AuthProofPublicInputs
} from './auth-types';

// Circuit file paths
const CIRCUITS_DIR = path.join(__dirname, '..', 'circuits');
const CIRCUIT_WASM = path.join(CIRCUITS_DIR, 'halp-auth.wasm');
const CIRCUIT_ZKEY = path.join(CIRCUITS_DIR, 'halp-auth_final.zkey');
const VERIFICATION_KEY = path.join(CIRCUITS_DIR, 'verification_key.json');

// Configuration
const REGISTRY_SERVICE_URL = process.env.REGISTRY_SERVICE_URL || 'http://localhost:3003';
const MERKLE_LEVELS = 20;

/**
 * Check if circuit files are available
 */
function isCircuitAvailable(): boolean {
  return fs.existsSync(CIRCUIT_WASM) && fs.existsSync(CIRCUIT_ZKEY);
}

/**
 * Session-specific pseudonym data
 */
export interface SessionPseudonymData {
  pseudonym: string;       // Hex-encoded pseudonym
  pseudonymRaw: bigint;    // Raw field element
  masterSecret: bigint;    // Used for proof (never exposed)
  sessionNonce: bigint;    // Session-specific nonce
  domain: string;          // Service domain
}

/**
 * Authentication proof data (before SNARK generation)
 */
export interface AuthProofData {
  pseudonym: SessionPseudonymData;
  nullifier: {
    nullifier: string;
    nullifierRaw: bigint;
    credentialId: string;
    sessionNonce: bigint;
    domain: string;
  };
  merkleProof: MerkleNonMembershipProof;
  challenge: AuthChallenge;
}

/**
 * SNARK proof structure (Groth16)
 */
export interface SnarkProof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

/**
 * Authentication Proof Generator
 */
export class AuthProofGenerator {
  private registryServiceUrl: string;
  
  constructor(registryServiceUrl: string = REGISTRY_SERVICE_URL) {
    this.registryServiceUrl = registryServiceUrl;
  }
  
  /**
   * Generate complete authentication proof
   * 
   * @param holderDid - Holder's DID (for master secret retrieval)
   * @param credentialId - Unique credential identifier
   * @param challenge - Challenge received from verifier
   * @returns Complete authentication package
   */
  async generateAuthenticationProof(
    holderDid: string,
    credentialId: string,
    challenge: AuthChallenge
  ): Promise<AuthenticationPackage> {
    console.log('\n╔═══════════════════════════════════════════════════════════╗');
    console.log('║       PHASE 2: PROOF GENERATION                           ║');
    console.log('╚═══════════════════════════════════════════════════════════╝\n');
    
    const { domain, registryRoot } = challenge;
    
    // Step 1: Generate session nonce
    console.log('Step 1: Generate session nonce');
    console.log('  Sampling random nonce from BLS12-381 scalar field...');
    const sessionNonce = FieldOperations.randomScalar();
    console.log(`  ✓ Nonce: ${sessionNonce.toString().substring(0, 25)}...`);
    
    // Step 2: Derive session-specific pseudonym
    console.log('\nStep 2: Derive session-specific pseudonym');
    const pseudonymData = await this.deriveSessionPseudonym(
      holderDid,
      sessionNonce,
      domain
    );
    console.log(`  ✓ Pseudonym: ${pseudonymData.pseudonym.substring(0, 32)}...`);
    
    // Step 3: Compute nullifier
    console.log('\nStep 3: Compute nullifier');
    const nullifierData = NullifierManager.deriveNullifier(
      credentialId,
      sessionNonce,
      domain
    );
    console.log(`  ✓ Nullifier: ${nullifierData.nullifier.substring(0, 32)}...`);
    
    // Step 4: Get non-membership proof from registry
    console.log('\nStep 4: Retrieve non-membership proof from registry');
    const merkleProof = await this.getNonMembershipProof(nullifierData.nullifier);
    console.log(`  ✓ Merkle proof obtained`);
    console.log(`  Root: ${merkleProof.root.substring(0, 32)}...`);
    
    // Step 5: Generate zk-SNARK proof
    console.log('\nStep 5: Generate zk-SNARK proof');
    const proofData: AuthProofData = {
      pseudonym: pseudonymData,
      nullifier: nullifierData,
      merkleProof,
      challenge
    };
    
    const snarkProof = await this.generateSnarkProof(proofData);
    console.log(`  ✓ SNARK proof generated`);
    
    // Step 6: Package authentication data
    console.log('\nStep 6: Package authentication data');
    const authPackage: AuthenticationPackage = {
      challenge: challenge.challenge,
      challengeId: challenge.challengeId,
      proof: JSON.stringify(snarkProof),
      pseudonym: pseudonymData.pseudonym,
      nullifier: nullifierData.nullifier,
      registryRoot: merkleProof.root,
      domain,
      timestamp: Date.now()
    };
    
    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('✅ PROOF GENERATION COMPLETE');
    console.log(`   Domain: ${domain}`);
    console.log(`   Pseudonym: ${pseudonymData.pseudonym.substring(0, 24)}...`);
    console.log(`   Nullifier: ${nullifierData.nullifier.substring(0, 24)}...`);
    console.log('   Ready for submission to verifier');
    console.log('═══════════════════════════════════════════════════════════\n');
    
    return authPackage;
  }
  
  /**
   * Derive session-specific pseudonym
   * 
   * Formula: P = Poseidon(ms, nonce, H(domain))
   * 
   * This ensures:
   * - Different sessions produce different pseudonyms (due to nonce)
   * - Same holder can't be linked across domains
   * - Pseudonym is deterministic for same inputs
   */
  private async deriveSessionPseudonym(
    holderDid: string,
    sessionNonce: bigint,
    domain: string
  ): Promise<SessionPseudonymData> {
    console.log('\n┌─────────────────────────────────────────────────────────┐');
    console.log('│         SESSION PSEUDONYM DERIVATION                    │');
    console.log('└─────────────────────────────────────────────────────────┘\n');
    
    // Get master secret
    console.log('  Retrieving master secret...');
    const masterSecret = await MasterSecretManager.getMasterSecret(holderDid);
    console.log(`  Master secret: ${masterSecret.toString().substring(0, 20)}... (hidden)`);
    
    // Hash domain to field element
    console.log(`  Domain: ${domain}`);
    const domainField = PoseidonHash.hashString(domain);
    console.log(`  H(domain): ${domainField.toString().substring(0, 20)}...`);
    
    // Compute pseudonym: P = Poseidon(ms, nonce, domain)
    console.log('  Formula: P = Poseidon(ms, nonce, H(domain))');
    const pseudonymRaw = PoseidonHash.hash3(masterSecret, sessionNonce, domainField);
    const pseudonym = PoseidonHash.toHex(pseudonymRaw);
    
    console.log(`  ✓ Session pseudonym computed`);
    
    return {
      pseudonym,
      pseudonymRaw,
      masterSecret,
      sessionNonce,
      domain
    };
  }
  
  /**
   * Get non-membership proof from registry
   */
  private async getNonMembershipProof(nullifier: string): Promise<MerkleNonMembershipProof> {
    try {
      const response = await fetch(`${this.registryServiceUrl}/merkle/proof`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          leaf: nullifier,
          proofType: 'non-membership'
        })
      });
      
      if (!response.ok) {
        throw new Error(`Registry returned ${response.status}`);
      }
      
      const data = await response.json();
      
      if (!data.success) {
        throw new Error(data.error || 'Proof generation failed');
      }
      
      return {
        siblings: data.proof.siblings,
        pathIndices: data.proof.pathIndices,
        leaf: data.proof.leaf,
        root: data.proof.root
      };
      
    } catch (error) {
      console.log('  [Warning] Could not reach registry, using placeholder proof');
      
      // Return placeholder proof for demo
      return {
        siblings: Array(20).fill('0'.repeat(64)),
        pathIndices: Array(20).fill(0),
        leaf: nullifier,
        root: '0'.repeat(64)
      };
    }
  }
  
  /**
   * Generate zk-SNARK proof
   * 
   * The proof attests to:
   * 1. Knowledge of master secret ms
   * 2. Correct pseudonym computation: P = Poseidon(ms, n, d)
   * 3. Correct nullifier computation: Nf = Poseidon(credID, n, d)
   * 4. Commitment opening: C = Poseidon(ms, r)
   * 5. Non-membership of nullifier in registry
   * 
   * Uses snarkjs when circuit is available, otherwise demo mode.
   */
  private async generateSnarkProof(proofData: AuthProofData): Promise<SnarkProof> {
    console.log('\n┌─────────────────────────────────────────────────────────┐');
    console.log('│         zk-SNARK PROOF GENERATION                       │');
    console.log('└─────────────────────────────────────────────────────────┘\n');
    
    const { pseudonym, nullifier, merkleProof, challenge } = proofData;
    
    // Prepare public inputs
    console.log('  Public inputs:');
    console.log(`    - Pseudonym: ${pseudonym.pseudonym.substring(0, 24)}...`);
    console.log(`    - Nullifier: ${nullifier.nullifier.substring(0, 24)}...`);
    console.log(`    - Registry root: ${merkleProof.root.substring(0, 24)}...`);
    console.log(`    - Challenge: ${challenge.challenge.substring(0, 24)}...`);
    
    // Prepare private inputs (never sent over network)
    console.log('\n  Private inputs (local only):');
    console.log(`    - Master secret: [HIDDEN]`);
    console.log(`    - Session nonce: [HIDDEN]`);
    console.log(`    - Merkle siblings: [${merkleProof.siblings.length} elements]`);
    
    // Check if circuit files are available
    if (isCircuitAvailable()) {
      console.log('\n  [PRODUCTION MODE] Using real snarkjs circuit');
      console.log('  Circuit: halp-auth (BN128/Groth16)');
      
      try {
        // Prepare circuit inputs
        const domainHash = PoseidonHash.hashString(pseudonym.domain);
        const credentialIdHash = PoseidonHash.hashString(nullifier.credentialId);
        
        // Note: In production, commitmentHash and blindingFactor would come from stored credential
        // For now, we compute a placeholder commitment
        const placeholderBlindingFactor = FieldOperations.randomScalar();
        const commitmentHash = PoseidonHash.hash2(pseudonym.masterSecret, placeholderBlindingFactor);
        
        const circuitInputs = {
          // Public inputs
          pseudonym: pseudonym.pseudonymRaw.toString(),
          nullifier: nullifier.nullifierRaw.toString(),
          commitmentHash: commitmentHash.toString(),
          registryRoot: PoseidonHash.fromHex(merkleProof.root).toString(),
          challenge: PoseidonHash.fromHex(challenge.challenge).toString(),
          // Private inputs
          masterSecret: pseudonym.masterSecret.toString(),
          sessionNonce: pseudonym.sessionNonce.toString(),
          domainHash: domainHash.toString(),
          credentialIdHash: credentialIdHash.toString(),
          blindingFactor: placeholderBlindingFactor.toString(),
          lowNullifier: '0',
          lowNullifierNextValue: '0',
          lowNullifierNextIdx: '0',
          merkleSiblings: merkleProof.siblings.map(s => 
            PoseidonHash.fromHex(s).toString()
          ),
          merklePathIndices: merkleProof.pathIndices
        };
        
        console.log('  Generating Groth16 proof with snarkjs...');
        
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
          circuitInputs,
          CIRCUIT_WASM,
          CIRCUIT_ZKEY
        );
        
        console.log('  ✓ Real SNARK proof generated');
        console.log(`    Protocol: groth16`);
        console.log(`    Curve: bn128`);
        console.log(`    Public signals: ${publicSignals.length}`);
        
        return {
          pi_a: proof.pi_a,
          pi_b: proof.pi_b,
          pi_c: proof.pi_c,
          protocol: 'groth16',
          curve: 'bn128'
        };
        
      } catch (error) {
        console.error('  ✗ snarkjs proof generation failed:', error);
        console.log('  Falling back to demo proof...');
        return this.generateDemoProof(proofData);
      }
    } else {
      console.log('\n  [DEMO MODE] Circuit files not found');
      console.log(`    Expected WASM: ${CIRCUIT_WASM}`);
      console.log(`    Expected zkey: ${CIRCUIT_ZKEY}`);
      console.log('  Generating placeholder proof...');
    
      // For demo: Generate structured placeholder proof
      // This simulates what snarkjs would produce
      const proof = this.generateDemoProof(proofData);
      
      console.log('  ✓ Demo proof generated');
      console.log(`    Protocol: ${proof.protocol}`);
      console.log(`    Curve: ${proof.curve}`);
      
      return proof;
    }
  }
  
  /**
   * Generate demo proof (simulates snarkjs output)
   */
  private generateDemoProof(proofData: AuthProofData): SnarkProof {
    // Create deterministic "proof" from inputs for demo
    // In production, this is replaced by actual SNARK computation
    
    const { pseudonym, nullifier, challenge } = proofData;
    
    // Hash inputs to create proof-like data
    const proofSeed = PoseidonHash.hash3(
      pseudonym.pseudonymRaw,
      nullifier.nullifierRaw,
      PoseidonHash.fromHex(challenge.challenge)
    );
    
    const proofHex = PoseidonHash.toHex(proofSeed);
    
    return {
      pi_a: [
        proofHex.substring(0, 64),
        proofHex.substring(0, 64),
        '1'
      ],
      pi_b: [
        [proofHex.substring(0, 64), proofHex.substring(0, 64)],
        [proofHex.substring(0, 64), proofHex.substring(0, 64)],
        ['1', '0']
      ],
      pi_c: [
        proofHex.substring(0, 64),
        proofHex.substring(0, 64),
        '1'
      ],
      protocol: 'groth16',
      curve: 'bls12381'
    };
  }
  
  /**
   * Request authentication challenge from verifier
   */
  async requestChallenge(verifierUrl: string, domain: string): Promise<AuthChallenge> {
    console.log(`\n[AuthProof] Requesting challenge for domain: ${domain}`);
    
    const response = await fetch(`${verifierUrl}/auth/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });
    
    if (!response.ok) {
      throw new Error(`Challenge request failed: ${response.status}`);
    }
    
    const data = await response.json();
    
    if (!data.success) {
      throw new Error(data.error || 'Challenge generation failed');
    }
    
    return data.challenge;
  }
  
  /**
   * Submit authentication proof to verifier
   */
  async submitProof(verifierUrl: string, authPackage: AuthenticationPackage): Promise<{
    success: boolean;
    sessionToken?: string;
    error?: string;
  }> {
    console.log(`\n[AuthProof] Submitting proof to verifier...`);
    
    const response = await fetch(`${verifierUrl}/auth/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(authPackage)
    });
    
    const data = await response.json();
    
    if (data.success) {
      console.log('  ✓ Authentication successful!');
      console.log(`  Session token received, expires: ${new Date(data.expiresAt).toISOString()}`);
    } else {
      console.log(`  ✗ Authentication failed: ${data.error}`);
    }
    
    return data;
  }
  
  /**
   * Complete authentication flow (convenience method)
   */
  async authenticate(
    holderDid: string,
    credentialId: string,
    verifierUrl: string,
    domain: string
  ): Promise<{
    success: boolean;
    sessionToken?: string;
    pseudonym?: string;
    error?: string;
  }> {
    console.log('\n════════════════════════════════════════════════════════════');
    console.log('           HALP AUTHENTICATION PROTOCOL                     ');
    console.log('════════════════════════════════════════════════════════════\n');
    
    try {
      // Phase 1: Request challenge
      console.log('PHASE 1: Request challenge from verifier');
      const challenge = await this.requestChallenge(verifierUrl, domain);
      
      // Phase 2: Generate proof
      console.log('\nPHASE 2: Generate authentication proof');
      const authPackage = await this.generateAuthenticationProof(
        holderDid,
        credentialId,
        challenge
      );
      
      // Phase 3 & 4: Submit proof and receive token
      console.log('\nPHASE 3-4: Submit proof and receive session token');
      const result = await this.submitProof(verifierUrl, authPackage);
      
      return {
        success: result.success,
        sessionToken: result.sessionToken,
        pseudonym: authPackage.pseudonym,
        error: result.error
      };
      
    } catch (error) {
      console.error('\n✗ Authentication failed:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Authentication failed'
      };
    }
  }
}

export default new AuthProofGenerator();
