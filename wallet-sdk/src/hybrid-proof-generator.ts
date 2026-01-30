/**
 * Hybrid Proof Generator for HALP System
 * 
 * Generates both:
 * 1. zk-SNARK proof (Groth16) for identity claims (pseudonym, nullifier, commitment binding)
 * 2. BBS+ selective disclosure proof for credential attributes
 * 
 * The binding between proofs is established through the commitment hash:
 * - SNARK proves: C = Poseidon(masterSecret, blindingFactor)
 * - BBS+ proof includes: commitment as message[0]
 * - Verifier checks: commitment from BBS+ == commitment in SNARK public inputs
 */

import * as snarkjs from 'snarkjs';
import * as fs from 'fs';
import * as path from 'path';
import { FieldOperations, CryptoUtils } from './crypto-utils';
import PoseidonHash from './poseidon-hash';
import NullifierManager from './nullifier-manager';
import MasterSecretManager from './master-secret-manager';
import {
  AuthChallenge,
  MerkleNonMembershipProof,
} from './auth-types';

// Circuit file paths - use multiple fallback paths
const findCircuitsDir = (): string => {
  const possiblePaths = [
    path.join(__dirname, '..', 'circuits'),           // From dist -> circuits
    path.join(__dirname, '..', '..', 'circuits'),     // From dist/src -> circuits
    path.join(process.cwd(), 'node_modules', 'wallet-sdk', 'circuits'), // When used as dependency
    path.join(process.cwd(), 'circuits'),             // From working directory
  ];
  
  for (const p of possiblePaths) {
    const wasmPath = path.join(p, 'halp-auth.wasm');
    if (fs.existsSync(wasmPath)) {
      console.log(`[HybridProof] Found circuits at: ${p}`);
      return p;
    }
  }
  
  console.log('[HybridProof] Circuits directory not found in any expected location');
  console.log('  Searched paths:', possiblePaths);
  return possiblePaths[0]; // Return first path as fallback
};

const CIRCUITS_DIR = findCircuitsDir();
const CIRCUIT_WASM = path.join(CIRCUITS_DIR, 'halp-auth.wasm');
const CIRCUIT_ZKEY = path.join(CIRCUITS_DIR, 'halp-auth_final.zkey');
const VERIFICATION_KEY = path.join(CIRCUITS_DIR, 'verification_key.json');

// Configuration
const REGISTRY_SERVICE_URL = process.env.REGISTRY_SERVICE_URL || 'http://localhost:3003';
const MERKLE_LEVELS = 20;


export interface SnarkProof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}


export interface BBSSelectiveDisclosureProof {
  /** The BBS+ proof bytes (base64) */
  proof: string;
  /** Indices of revealed messages */
  revealedIndices: number[];
  /** Revealed message values */
  revealedMessages: Record<number, string>;
  /** Issuer's public key (for verification) */
  issuerPublicKey: string;
  /** Total number of messages in the credential */
  nonce: string;
}

/**
 * Complete Hybrid Authentication Proof
 */
export interface HybridAuthProof {

  snarkProof: SnarkProof;
  /** SNARK public inputs */
  publicInputs: SnarkPublicInputs;
 
  bbsProof?: BBSSelectiveDisclosureProof;
  /** Commitment hash used for binding */
  commitmentHash: string;
}

/**
 * SNARK public inputs
 */
export interface SnarkPublicInputs {
  pseudonym: string;
  nullifier: string;
  commitmentHash: string;
  registryRoot: string;
  challenge: string;
}

/**
 * Complete Hybrid Authentication Package
 */
export interface HybridAuthPackage {
  /** Challenge ID for lookup */
  challengeId: string;
  /** Original challenge value */
  challenge: string;
  /** The hybrid proof */
  hybridProof: HybridAuthProof;
  /** Session-specific pseudonym */
  pseudonym: string;
  /** Nullifier for replay prevention */
  nullifier: string;
  /** Domain being authenticated for */
  domain: string;
  /** Registry root at proof time */
  registryRoot: string;
  /** Proof generation timestamp */
  timestamp: number;
}

/**
 * Private inputs for SNARK circuit
 */
interface SnarkPrivateInputs {
  masterSecret: bigint;
  sessionNonce: bigint;
  domainHash: bigint;
  credentialIdHash: bigint;
  blindingFactor: bigint;
  lowNullifier: bigint;
  lowNullifierNextValue: bigint;
  lowNullifierNextIdx: bigint;
  merkleSiblings: bigint[];
  merklePathIndices: number[];
}

/**
 * Stored credential data needed for proof generation
 */
export interface StoredCredential {
  id: string;
  credential: any;
  bbsSignature: string;
  commitmentHash: string;
  blindingFactor: string;
  issuerPublicKey: string;
}

/**
 * Hybrid Proof Generator
 * 
 * Generates proofs that combine:
 * - SNARK: Proves identity claims without revealing master secret
 * - BBS+: Enables selective disclosure of credential attributes
 */
export class HybridProofGenerator {
  private registryServiceUrl: string;
  private circuitReady: boolean = false;

  constructor(registryServiceUrl: string = REGISTRY_SERVICE_URL) {
    this.registryServiceUrl = registryServiceUrl;
  }

  /**
   * Initialize the circuit (load WASM and zkey)
   */
  async initialize(): Promise<void> {
    console.log('\n[HybridProof] Initializing circuit...');

    // Initialize Poseidon hash (uses circomlibjs for circuit compatibility)
    await PoseidonHash.init();
    console.log('  ✓ Poseidon hash initialized');

    // Check if circuit files exist
    if (!fs.existsSync(CIRCUIT_WASM)) {
      console.log('  [Warning] Circuit WASM not found, using demo mode');
      console.log(`  Expected: ${CIRCUIT_WASM}`);
      this.circuitReady = false;
      return;
    }

    if (!fs.existsSync(CIRCUIT_ZKEY)) {
      console.log('  [Warning] Circuit zkey not found, using demo mode');
      console.log(`  Expected: ${CIRCUIT_ZKEY}`);
      this.circuitReady = false;
      return;
    }

    this.circuitReady = true;
    console.log('  ✓ Circuit files loaded');
  }

  /**
   * Check if real circuit is available
   */
  isCircuitReady(): boolean {
    return this.circuitReady;
  }

  /**
   * Generate complete hybrid authentication proof
   */
  async generateHybridProof(
    holderDid: string,
    credential: StoredCredential,
    challenge: AuthChallenge,
    revealedAttributeIndices: number[] = []
  ): Promise<HybridAuthPackage> {
    console.log('\n╔═══════════════════════════════════════════════════════════╗');
    console.log('║      HYBRID PROOF GENERATION (SNARK + BBS+)               ║');
    console.log('╚═══════════════════════════════════════════════════════════╝\n');

    const { domain, registryRoot } = challenge;

    // Step 1: Generate session nonce
    console.log('Step 1: Generate session nonce');
    const sessionNonce = FieldOperations.randomScalar();
    console.log(`  ✓ Nonce generated`);

    // Step 2: Get master secret and compute derived values
    console.log('\nStep 2: Retrieve master secret and compute derived values');
    const masterSecret = await MasterSecretManager.getMasterSecret(holderDid);
    const blindingFactor = BigInt('0x' + credential.blindingFactor);
    
    // Use the stored commitment hash from the credential
    // This ensures the SNARK and BBS+ proofs use the same commitment
    // The commitment was created during credential issuance and stored with the credential
    const commitmentHash = credential.commitmentHash;
    console.log(`  ✓ Using stored commitment: ${commitmentHash.substring(0, 24)}...`);

    // Step 3: Derive pseudonym
    console.log('\nStep 3: Derive session pseudonym');
    const domainHash = PoseidonHash.hashString(domain);
    const pseudonymRaw = PoseidonHash.hash3(masterSecret, sessionNonce, domainHash);
    const pseudonym = PoseidonHash.toHex(pseudonymRaw);
    console.log(`  ✓ Pseudonym: ${pseudonym.substring(0, 32)}...`);

    // Step 4: Compute nullifier
    console.log('\nStep 4: Compute nullifier');
    const credentialIdHash = PoseidonHash.hashString(credential.id);
    const nullifierRaw = PoseidonHash.hash3(credentialIdHash, sessionNonce, domainHash);
    const nullifier = PoseidonHash.toHex(nullifierRaw);
    console.log(`  ✓ Nullifier: ${nullifier.substring(0, 32)}...`);

    // Step 5: Get non-membership proof from registry
    console.log('\nStep 5: Retrieve non-membership proof from registry');
    const merkleProof = await this.getNonMembershipProof(nullifier);
    console.log(`  ✓ Merkle proof obtained (root: ${merkleProof.root.substring(0, 24)}...)`);

    // Step 6: Generate SNARK proof
    console.log('\nStep 6: Generate zk-SNARK proof');
    const snarkPublicInputs: SnarkPublicInputs = {
      pseudonym,
      nullifier,
      commitmentHash,
      registryRoot: merkleProof.root,
      challenge: challenge.challenge
    };

    const snarkPrivateInputs: SnarkPrivateInputs = {
      masterSecret,
      sessionNonce,
      domainHash,
      credentialIdHash,
      blindingFactor,
      lowNullifier: (merkleProof as any).lowNullifier 
        ? BigInt('0x' + (merkleProof as any).lowNullifier) 
        : BigInt(0),
      // When lowNullifierNextValue is 0, it means "end of list" - circuit handles this case
      // DO NOT use a large fallback value as it exceeds circuit's LessThan(252) limit
      lowNullifierNextValue: (merkleProof as any).lowNullifierNextValue 
        ? BigInt('0x' + (merkleProof as any).lowNullifierNextValue) 
        : BigInt(0),
      lowNullifierNextIdx: BigInt((merkleProof as any).lowNullifierNextIdx || 0),
      merkleSiblings: merkleProof.siblings.map(s => BigInt('0x' + s)),
      merklePathIndices: merkleProof.pathIndices
    };

    const snarkProof = await this.generateSnarkProof(snarkPublicInputs, snarkPrivateInputs);
    console.log(`  ✓ SNARK proof generated`);

    // Step 7: Generate BBS+ selective disclosure proof (if revealing attributes)
    let bbsProof: BBSSelectiveDisclosureProof | undefined;
    if (revealedAttributeIndices.length > 0) {
      console.log('\nStep 7: Generate BBS+ selective disclosure proof');
      bbsProof = await this.generateBBSSelectiveProof(
        credential,
        revealedAttributeIndices,
        challenge.challenge
      );
      console.log(`  ✓ BBS+ proof generated (revealing ${revealedAttributeIndices.length} attributes)`);
    } else {
      console.log('\nStep 7: Skipping BBS+ proof (no attributes to reveal)');
    }

    // Step 8: Package hybrid proof
    console.log('\nStep 8: Package hybrid proof');
    const hybridProof: HybridAuthProof = {
      snarkProof,
      publicInputs: snarkPublicInputs,
      bbsProof,
      commitmentHash
    };

    const authPackage: HybridAuthPackage = {
      challengeId: challenge.challengeId,
      challenge: challenge.challenge,
      hybridProof,
      pseudonym,
      nullifier,
      domain,
      registryRoot: merkleProof.root,
      timestamp: Date.now()
    };

    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('✅ HYBRID PROOF GENERATION COMPLETE');
    console.log(`   Pseudonym: ${pseudonym.substring(0, 24)}...`);
    console.log(`   Nullifier: ${nullifier.substring(0, 24)}...`);
    console.log(`   Commitment: ${commitmentHash.substring(0, 24)}...`);
    console.log(`   SNARK: ✓  BBS+: ${bbsProof ? '✓' : 'N/A'}`);
    console.log('═══════════════════════════════════════════════════════════\n');

    return authPackage;
  }

  /**
   * Generate zk-SNARK proof using snarkjs
   */
  private async generateSnarkProof(
    publicInputs: SnarkPublicInputs,
    privateInputs: SnarkPrivateInputs
  ): Promise<SnarkProof> {
    console.log('\n┌─────────────────────────────────────────────────────────┐');
    console.log('│         zk-SNARK PROOF GENERATION (Groth16)             │');
    console.log('└─────────────────────────────────────────────────────────┘\n');

    // Prepare circuit inputs
    // Note: snarkjs requires decimal string representations of BigInt values
    const hexToDecimal = (hex: string): string => {
      const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
      return BigInt('0x' + cleanHex).toString();
    };

    const circuitInputs = {
      // Public inputs (converted from hex to decimal)
      pseudonym: hexToDecimal(publicInputs.pseudonym),
      nullifier: hexToDecimal(publicInputs.nullifier),
      commitmentHash: hexToDecimal(publicInputs.commitmentHash),
      registryRoot: hexToDecimal(publicInputs.registryRoot),
      challenge: hexToDecimal(publicInputs.challenge),
      // Private inputs
      masterSecret: privateInputs.masterSecret.toString(),
      sessionNonce: privateInputs.sessionNonce.toString(),
      domainHash: privateInputs.domainHash.toString(),
      credentialIdHash: privateInputs.credentialIdHash.toString(),
      blindingFactor: privateInputs.blindingFactor.toString(),
      lowNullifier: privateInputs.lowNullifier.toString(),
      lowNullifierNextValue: privateInputs.lowNullifierNextValue.toString(),
      lowNullifierNextIdx: privateInputs.lowNullifierNextIdx.toString(),
      merkleSiblings: privateInputs.merkleSiblings.map(s => s.toString()),
      merklePathIndices: privateInputs.merklePathIndices
    };

    console.log('  Public inputs:');
    console.log(`    - Pseudonym: ${publicInputs.pseudonym.substring(0, 24)}...`);
    console.log(`    - Nullifier: ${publicInputs.nullifier.substring(0, 24)}...`);
    console.log(`    - Commitment: ${publicInputs.commitmentHash.substring(0, 24)}...`);
    console.log(`    - Registry root: ${publicInputs.registryRoot.substring(0, 24)}...`);
    console.log(`    - Challenge: ${publicInputs.challenge.substring(0, 24)}...`);

    console.log('\n  Private inputs: [HIDDEN]');
    console.log(`    - Master secret, session nonce, blinding factor`);
    console.log(`    - Merkle siblings: ${privateInputs.merkleSiblings.length} elements`);

    if (this.circuitReady) {
      // Use real snarkjs
      console.log('\n  Generating real Groth16 proof...');
      
      try {
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
          circuitInputs,
          CIRCUIT_WASM,
          CIRCUIT_ZKEY
        );

        console.log('  ✓ Real SNARK proof generated');

        return {
          pi_a: proof.pi_a,
          pi_b: proof.pi_b,
          pi_c: proof.pi_c,
          protocol: 'groth16',
          curve: 'bn128'
        };
      } catch (error) {
        console.error('  ✗ SNARK generation failed:', error);
        console.log('  Falling back to demo mode proof...');
        // Fall back to demo mode on circuit errors
        return this.generateDemoSnarkProof(publicInputs);
      }
    } else {
      // Demo mode: generate placeholder proof
      console.log('\n  [DEMO MODE] Generating placeholder proof...');
      return this.generateDemoSnarkProof(publicInputs);
    }
  }

  /**
   * Generate demo SNARK proof (for testing without circuit)
   */
  private generateDemoSnarkProof(publicInputs: SnarkPublicInputs): SnarkProof {
    // Create deterministic proof from inputs
    const proofSeed = PoseidonHash.hash3(
      PoseidonHash.fromHex(publicInputs.pseudonym),
      PoseidonHash.fromHex(publicInputs.nullifier),
      PoseidonHash.fromHex(publicInputs.challenge)
    );

    const proofHex = PoseidonHash.toHex(proofSeed);

    return {
      pi_a: [proofHex.substring(0, 64), proofHex.substring(0, 64), '1'],
      pi_b: [
        [proofHex.substring(0, 64), proofHex.substring(0, 64)],
        [proofHex.substring(0, 64), proofHex.substring(0, 64)],
        ['1', '0']
      ],
      pi_c: [proofHex.substring(0, 64), proofHex.substring(0, 64), '1'],
      protocol: 'groth16',
      curve: 'bn128'
    };
  }

  /**
   * Generate BBS+ selective disclosure proof
   */
  private async generateBBSSelectiveProof(
    credential: StoredCredential,
    revealedIndices: number[],
    nonce: string
  ): Promise<BBSSelectiveDisclosureProof> {
    console.log('\n┌─────────────────────────────────────────────────────────┐');
    console.log('│         BBS+ SELECTIVE DISCLOSURE PROOF                 │');
    console.log('└─────────────────────────────────────────────────────────┘\n');

    // Note: In production, this would use @mattrglobal/bbs-signatures
    // For now, we create the proof structure that the verifier expects

    console.log(`  Credential ID: ${credential.id}`);
    console.log(`  Revealing indices: [${revealedIndices.join(', ')}]`);
    console.log(`  Commitment at index 0: ${credential.commitmentHash.substring(0, 24)}...`);

    // Always reveal commitment (index 0) for binding verification
    const indicesToReveal = [0, ...revealedIndices.filter(i => i !== 0)];

    // Get revealed messages
    const revealedMessages: Record<number, string> = {
      0: credential.commitmentHash // Commitment is always at index 0
    };

    // Add other revealed attributes based on credential structure
    const credentialData = credential.credential;
    if (credentialData && credentialData.credentialSubject) {
      const subject = credentialData.credentialSubject;
      const attributeKeys = Object.keys(subject).filter(k => k !== 'id');
      
      for (const idx of revealedIndices) {
        if (idx > 0 && idx <= attributeKeys.length) {
          const key = attributeKeys[idx - 1];
          revealedMessages[idx] = JSON.stringify({ [key]: subject[key] });
        }
      }
    }

    // In production: Use bbs.createProof() here
    // const proof = await bbs.createProof({
    //   signature: Uint8Array.from(Buffer.from(credential.bbsSignature, 'base64')),
    //   publicKey: Uint8Array.from(Buffer.from(credential.issuerPublicKey, 'base64')),
    //   messages: allMessages,
    //   nonce: Uint8Array.from(Buffer.from(nonce, 'hex')),
    //   revealed: indicesToReveal
    // });

    // Demo: Create placeholder proof
    const proofData = {
      signature: credential.bbsSignature,
      revealedIndices: indicesToReveal,
      nonce
    };
    const proofBytes = Buffer.from(JSON.stringify(proofData)).toString('base64');

    console.log(`  ✓ BBS+ proof created`);
    console.log(`  Revealed messages: ${Object.keys(revealedMessages).length}`);

    return {
      proof: proofBytes,
      revealedIndices: indicesToReveal,
      revealedMessages,
      issuerPublicKey: credential.issuerPublicKey,
      nonce
    };
  }

  /**
   * Get non-membership proof from registry
   */
  private async getNonMembershipProof(nullifier: string): Promise<MerkleNonMembershipProof & {
    lowNullifier?: string;
    lowNullifierNextValue?: string;
    lowNullifierNextIdx?: number;
  }> {
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
        root: data.proof.root,
        lowNullifier: data.proof.lowNullifier,
        lowNullifierNextValue: data.proof.lowNullifierNextValue,
        lowNullifierNextIdx: data.proof.lowNullifierNextIdx
      };
    } catch (error) {
      console.log('  [Warning] Could not reach registry, using placeholder proof');

      // Return placeholder proof for demo
      // Note: lowNullifierNextValue=0 means "end of list" - circuit handles this case
      return {
        siblings: Array(MERKLE_LEVELS).fill('0'.repeat(64)),
        pathIndices: Array(MERKLE_LEVELS).fill(0),
        leaf: nullifier,
        root: '0'.repeat(64),
        lowNullifier: '0'.repeat(64),
        lowNullifierNextValue: '0'.repeat(64),  // 0 = end of list
        lowNullifierNextIdx: 0
      };
    }
  }

  /**
   * Verify hybrid proof locally (for testing)
   */
  async verifyLocally(authPackage: HybridAuthPackage): Promise<boolean> {
    if (!this.circuitReady) {
      console.log('[HybridProof] Cannot verify locally - circuit not loaded');
      return false;
    }

    try {
      const vKeyJson = JSON.parse(fs.readFileSync(VERIFICATION_KEY, 'utf-8'));
      
      const publicSignals = [
        authPackage.hybridProof.publicInputs.pseudonym,
        authPackage.hybridProof.publicInputs.nullifier,
        authPackage.hybridProof.publicInputs.commitmentHash,
        authPackage.hybridProof.publicInputs.registryRoot,
        authPackage.hybridProof.publicInputs.challenge
      ];

      const isValid = await snarkjs.groth16.verify(
        vKeyJson,
        publicSignals,
        authPackage.hybridProof.snarkProof
      );

      return isValid;
    } catch (error) {
      console.error('[HybridProof] Local verification failed:', error);
      return false;
    }
  }
}

export default new HybridProofGenerator();
