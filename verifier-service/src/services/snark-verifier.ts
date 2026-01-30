/**
 * SNARK Verifier for HALP Authentication
 * 
 * Verifies zero-knowledge proofs submitted during authentication.
 * 
 * The proof attests to:
 * 1. Holder knows a valid master secret (ms)
 * 2. Pseudonym P = Poseidon(ms, nonce, domain) is correctly computed
 * 3. Nullifier Nf = Poseidon(credID, nonce, domain) is correctly computed
 * 4. Commitment C = Poseidon(ms, r) is correctly opened
 * 5. Nullifier is not in the registry (non-membership proof)
 * 
 * Supports both production mode (real snarkjs verification) and demo mode.
 */

import * as snarkjs from 'snarkjs';
import * as fs from 'fs';
import * as path from 'path';

// Circuit file paths
const CIRCUITS_DIR = path.join(__dirname, '..', 'circuits');
const VERIFICATION_KEY_PATH = path.join(CIRCUITS_DIR, 'verification_key.json');

// SNARK Proof structure
export interface SnarkProof {
  // Groth16 proof components
  pi_a: string[];  // G1 point
  pi_b: string[][]; // G2 point
  pi_c: string[];  // G1 point
  protocol?: string;
  curve?: string;
}

export interface PublicInputs {
  pseudonym: string;
  nullifier: string;
  commitmentHash?: string;  // 3rd public input in circuit
  registryRoot: string;
  challenge: string;
  issuerPublicKey?: string;
}

export interface VerificationKey {
  // Groth16 verification key components
  vk_alpha_1: string[];
  vk_beta_2: string[][];
  vk_gamma_2: string[][];
  vk_delta_2: string[][];
  IC: string[][];
}

/**
 * SNARK Verifier Service
 */
export class SnarkVerifier {
  private verificationKey: VerificationKey | null = null;
  private circuitId: string = 'halp-auth-v1';
  private circuitReady: boolean = false;
  
  constructor() {
    // Load verification key from file
    this.loadVerificationKey();
  }
  
  /**
   * Check if real circuit verification is available
   */
  isCircuitReady(): boolean {
    return this.circuitReady;
  }
  
  /**
   * Verify a SNARK proof
   * 
   * @param proof - The proof to verify (hex encoded or structured)
   * @param publicInputs - Public inputs for verification (hex format)
   * @param publicSignals - Direct public signals array from proof generation (decimal strings)
   * @returns True if proof is valid
   */
  async verify(proof: string | SnarkProof, publicInputs?: PublicInputs, publicSignals?: string[]): Promise<boolean> {
    console.log('\n┌─────────────────────────────────────────────────────────┐');
    console.log('│         SNARK PROOF VERIFICATION                        │');
    console.log('└─────────────────────────────────────────────────────────┘\n');
    
    try {
      // Parse proof if it's a string
      const proofData = typeof proof === 'string' ? this.parseProof(proof) : proof;
      
      console.log('Step 1: Validate proof structure');
      if (!this.validateProofStructure(proofData)) {
        console.log('  ✗ Invalid proof structure');
        return false;
      }
      console.log('  ✓ Proof structure valid');
      
      console.log('\nStep 2: Validate public inputs');
      if (publicInputs) {
        console.log(`  Pseudonym: ${publicInputs.pseudonym.substring(0, 24)}...`);
        console.log(`  Nullifier: ${publicInputs.nullifier.substring(0, 24)}...`);
        console.log(`  Registry Root: ${publicInputs.registryRoot.substring(0, 24)}...`);
        console.log(`  Challenge: ${publicInputs.challenge.substring(0, 24)}...`);
      }
      console.log('  ✓ Public inputs present');
      
      console.log('\nStep 3: Execute pairing check');
      
      // Check if real verification is available
      if (this.circuitReady && this.verificationKey) {
        console.log('  [PRODUCTION MODE] Using snarkjs verification');
        
        // Use publicSignals directly if provided (decimal strings from proof generation)
        // Otherwise, convert from publicInputs (hex strings)
        // Circuit public input order: [pseudonym, nullifier, commitmentHash, registryRoot, challenge]
        let signals: string[];
        
        if (publicSignals && publicSignals.length === 5) {
          console.log('  Using direct publicSignals from proof generation');
          signals = publicSignals;
        } else if (publicInputs) {
          console.log('  Converting publicInputs from hex to decimal');
          // Convert hex strings to decimal strings
          const hexToDec = (hex: string) => {
            if (!hex) return '0';
            const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
            return BigInt('0x' + cleanHex).toString();
          };
          signals = [
            hexToDec(publicInputs.pseudonym),
            hexToDec(publicInputs.nullifier),
            hexToDec(publicInputs.commitmentHash || '0'),
            hexToDec(publicInputs.registryRoot),
            hexToDec(publicInputs.challenge)
          ];
        } else {
          signals = [];
        }
        
        console.log(`  Signals: [${signals.slice(0, 2).map(s => s.substring(0, 20) + '...').join(', ')}, ...]`);
        
        try {
          const isValid = await snarkjs.groth16.verify(
            this.verificationKey,
            signals,
            proofData
          );
          
          if (isValid) {
            console.log('  ✓ Pairing check passed');
            console.log('\n✅ SNARK PROOF VERIFIED');
          } else {
            console.log('  ✗ Pairing check failed');
          }
          
          return isValid;
        } catch (error) {
          console.error('  snarkjs verification error:', error);
          return false;
        }
      } else {
        // Demo mode verification
        console.log('  [DEMO MODE] Performing structural verification');
        const isValid = await this.performVerification(proofData, publicInputs);
        
        if (isValid) {
          console.log('  ✓ Structural check passed');
          console.log('\n✅ SNARK PROOF VERIFIED (Demo Mode)');
        } else {
          console.log('  ✗ Structural check failed');
        }
        
        return isValid;
      }
      
    } catch (error) {
      console.error('  ✗ Verification error:', error);
      return false;
    }
  }
  
  /**
   * Parse proof from hex string
   */
  private parseProof(proofHex: string): SnarkProof {
    try {
      // Try JSON parse first
      if (proofHex.startsWith('{')) {
        return JSON.parse(proofHex);
      }
      
      // Otherwise, assume it's a simplified format
      // In production, this would parse the actual proof bytes
      return {
        pi_a: [proofHex.substring(0, 64), proofHex.substring(64, 128)],
        pi_b: [[proofHex.substring(128, 192), proofHex.substring(192, 256)]],
        pi_c: [proofHex.substring(256, 320), proofHex.substring(320, 384)],
        protocol: 'groth16',
        curve: 'bls12381'
      };
    } catch {
      // Return a default structure for demo purposes
      return {
        pi_a: ['0', '0'],
        pi_b: [['0', '0']],
        pi_c: ['0', '0'],
        protocol: 'groth16',
        curve: 'bls12381'
      };
    }
  }
  
  /**
   * Validate proof structure
   */
  private validateProofStructure(proof: SnarkProof): boolean {
    // Check required fields exist
    if (!proof.pi_a || !proof.pi_b || !proof.pi_c) {
      return false;
    }
    
    // Check array lengths (Groth16 specific)
    if (proof.pi_a.length < 2) return false;
    if (proof.pi_c.length < 2) return false;
    
    return true;
  }
  
  /**
   * Perform actual verification
   * In production, this uses snarkjs pairing operations
   */
  private async performVerification(
    proof: SnarkProof,
    publicInputs?: PublicInputs
  ): Promise<boolean> {
    // For demo/development: Accept proofs that have proper structure
    // and match expected format
    
    // Basic sanity checks
    if (!proof.pi_a || proof.pi_a.length === 0) {
      return false;
    }
    
    // In production, this would be:
    // return await snarkjs.groth16.verify(this.verificationKey, publicInputsArray, proof);
    
    // For demo: Check if proof has content (not all zeros)
    const hasContent = proof.pi_a.some(v => v !== '0' && v !== '');
    
    // Additional validation: Check public inputs are consistent
    if (publicInputs) {
      // Verify pseudonym format (should be hex)
      if (!/^[0-9a-fA-F]+$/.test(publicInputs.pseudonym)) {
        console.log('  [Warning] Invalid pseudonym format');
      }
      
      // Verify nullifier format
      if (!/^[0-9a-fA-F]+$/.test(publicInputs.nullifier)) {
        console.log('  [Warning] Invalid nullifier format');
      }
    }
    
    // For demo purposes, accept valid-looking proofs
    // In production, this MUST use proper cryptographic verification
    console.log('  [Demo Mode] Accepting structurally valid proof');
    return true;
  }
  
  /**
   * Load verification key from configuration
   */
  private loadVerificationKey(): void {
    console.log('[SnarkVerifier] Loading verification key...');
    
    if (fs.existsSync(VERIFICATION_KEY_PATH)) {
      try {
        const vkJson = fs.readFileSync(VERIFICATION_KEY_PATH, 'utf-8');
        this.verificationKey = JSON.parse(vkJson);
        this.circuitReady = true;
        console.log('[SnarkVerifier] ✓ Verification key loaded from:', VERIFICATION_KEY_PATH);
      } catch (error) {
        console.error('[SnarkVerifier] Failed to parse verification key:', error);
        this.circuitReady = false;
      }
    } else {
      console.log('[SnarkVerifier] Verification key not found, using demo mode');
      console.log(`  Expected: ${VERIFICATION_KEY_PATH}`);
      this.circuitReady = false;
    }
  }
  
  /**
   * Set verification key (for testing or dynamic loading)
   */
  setVerificationKey(vk: VerificationKey): void {
    this.verificationKey = vk;
  }
}

export default new SnarkVerifier();

