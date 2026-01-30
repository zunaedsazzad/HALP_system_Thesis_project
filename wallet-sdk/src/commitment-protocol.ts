/**
 * Pedersen Commitment Protocol
 * Implements cryptographic commitments and zero-knowledge proofs
 * for privacy-preserving credential issuance
 */

import { FieldOperations, G1Operations, HashOperations, CryptoUtils, G1Point } from './crypto-utils';
import { PublicParametersManager } from './public-parameters';
import { bls12_381 } from '@noble/curves/bls12-381.js';

export interface CommitmentData {
  commitment: Uint8Array; // C = Com(ms, attrs; r)
  blindingFactor: bigint; // r (kept private)
}

export interface ZeroKnowledgeProof {
  commitment: Uint8Array; // C
  T: Uint8Array; // Commitment in proof
  challenge: Uint8Array; // Fiat-Shamir challenge
  responses: bigint[]; // [s_ms, s_attr1, ..., s_attrk, s_r]
  nonce: Uint8Array; // Replay protection
}

export interface CommitmentRequest {
  holderDid: string;
  pseudonym: Uint8Array;
  commitment: Uint8Array;
  proof: ZeroKnowledgeProof;
  revealedAttributes: Record<string, any>;
  credentialSchema: string;
  timestamp: number;
  nonce: Uint8Array;
}

/**
 * Pedersen Commitment Protocol Implementation
 */
export class CommitmentProtocol {
  private paramsManager: PublicParametersManager;

  constructor(paramsManager: PublicParametersManager) {
    this.paramsManager = paramsManager;
  }

  /**
   * Create Pedersen commitment: C = G^ms · H1^a1 · ... · Hk^ak · Hr^r
   * 
   * @param masterSecret - Holder's master secret
   * @param attributes - Array of encoded attribute values
   * @param blindingFactor - Optional blinding factor (generated if not provided)
   * @returns Commitment data with commitment point and blinding factor
   */
  createCommitment(
    masterSecret: bigint,
    attributes: bigint[],
    blindingFactor?: bigint
  ): CommitmentData {
    const generators = this.paramsManager.getGenerators();
    const maxAttrs = this.paramsManager.getMaxAttributes();

    if (attributes.length > maxAttrs) {
      throw new Error(`Too many attributes: ${attributes.length} (max: ${maxAttrs})`);
    }

    // Generate blinding factor if not provided
    const r = blindingFactor || FieldOperations.randomScalar();

    console.log('\n[Creating Pedersen Commitment]');
    console.log(`  Master secret: <hidden>`);
    console.log(`  Number of attributes: ${attributes.length}`);
    console.log(`  Blinding factor: <hidden>`);

    // Start with master secret: C = G^ms
    let C = G1Operations.multiply(generators.G, masterSecret);

    // Add attribute commitments: C = C · H1^a1 · ... · Hk^ak
    for (let i = 0; i < attributes.length; i++) {
      const attrCommit = G1Operations.multiply(generators.attributeGenerators[i], attributes[i]);
      C = G1Operations.add(C, attrCommit);
    }

    // Add blinding: C = C · Hr^r
    const blindingCommit = G1Operations.multiply(generators.blindingGenerator, r);
    C = G1Operations.add(C, blindingCommit);

    const commitmentBytes = G1Operations.serialize(C);
    console.log(`✓ Commitment created: ${CryptoUtils.bytesToHex(commitmentBytes).substring(0, 16)}...`);

    return {
      commitment: commitmentBytes,
      blindingFactor: r
    };
  }

  /**
   * Generate zero-knowledge proof of commitment opening
   * Proves knowledge of (ms, a1, ..., ak, r) such that C = Com(ms, a1, ..., ak; r)
   * Uses Schnorr-based sigma protocol with Fiat-Shamir transform
   */
  generateProof(
    masterSecret: bigint,
    attributes: bigint[],
    blindingFactor: bigint,
    commitmentBytes: Uint8Array,
    context: Uint8Array
  ): ZeroKnowledgeProof {
    const generators = this.paramsManager.getGenerators();

    console.log('\n[Generating Zero-Knowledge Proof]');
    console.log(`  Proving knowledge of ${attributes.length + 2} secret values`);

    // Step 1: Commitment phase - generate random nonces
    const r_ms = FieldOperations.randomScalar();
    const r_attrs = attributes.map(() => FieldOperations.randomScalar());
    const r_blind = FieldOperations.randomScalar();

    // Step 2: Compute commitment T = G^r_ms · H1^r_a1 · ... · Hr^r_blind
    let T = G1Operations.multiply(generators.G, r_ms);
    
    for (let i = 0; i < r_attrs.length; i++) {
      const attrT = G1Operations.multiply(generators.attributeGenerators[i], r_attrs[i]);
      T = G1Operations.add(T, attrT);
    }
    
    const blindingT = G1Operations.multiply(generators.blindingGenerator, r_blind);
    T = G1Operations.add(T, blindingT);

    const T_bytes = G1Operations.serialize(T);

    // Step 3: Challenge phase (Fiat-Shamir)
    const nonce = CryptoUtils.randomBytes(32);
    const challenge = HashOperations.computeChallenge(
      commitmentBytes,
      T_bytes,
      context,
      nonce
    );
    const challengeBytes = FieldOperations.scalarToBytes(challenge);

    console.log(`  Challenge: ${CryptoUtils.bytesToHex(challengeBytes).substring(0, 16)}...`);

    // Step 4: Response phase
    // s_ms = r_ms + c * ms
    const s_ms = FieldOperations.addMod(
      r_ms,
      FieldOperations.mulMod(challenge, masterSecret)
    );

    // s_attrs[i] = r_attrs[i] + c * attrs[i]
    const s_attrs = attributes.map((attr, i) =>
      FieldOperations.addMod(
        r_attrs[i],
        FieldOperations.mulMod(challenge, attr)
      )
    );

    // s_blind = r_blind + c * r
    const s_blind = FieldOperations.addMod(
      r_blind,
      FieldOperations.mulMod(challenge, blindingFactor)
    );

    // Combine all responses
    const responses = [s_ms, ...s_attrs, s_blind];

    console.log(`✓ Proof generated with ${responses.length} responses`);

    return {
      commitment: commitmentBytes,
      T: T_bytes,
      challenge: challengeBytes,
      responses,
      nonce
    };
  }

  /**
   * Verify zero-knowledge proof
   * Verifies that prover knows opening of commitment without learning the values
   */
  verifyProof(
    proof: ZeroKnowledgeProof,
    context: Uint8Array,
    numAttributes: number
  ): boolean {
    try {
      const generators = this.paramsManager.getGenerators();

      console.log('\n[Verifying Zero-Knowledge Proof]');
      console.log(`  Expected attributes: ${numAttributes}`);
      console.log(`  Responses: ${proof.responses.length}`);

      // Validate response count: [s_ms, s_attr1, ..., s_attrk, s_blind]
      const expectedResponses = 1 + numAttributes + 1;
      if (proof.responses.length !== expectedResponses) {
        console.error(`❌ Invalid response count: ${proof.responses.length} (expected: ${expectedResponses})`);
        return false;
      }

      // Parse responses
      const s_ms = proof.responses[0];
      const s_attrs = proof.responses.slice(1, 1 + numAttributes);
      const s_blind = proof.responses[proof.responses.length - 1];

      // Parse challenge
      const challenge = FieldOperations.bytesToScalar(proof.challenge);

      // Step 1: Recompute T' = G^s_ms · H1^s_a1 · ... · Hr^s_blind · C^(-c)
      let T_prime = G1Operations.multiply(generators.G, s_ms);

      for (let i = 0; i < s_attrs.length; i++) {
        const attrT = G1Operations.multiply(generators.attributeGenerators[i], s_attrs[i]);
        T_prime = G1Operations.add(T_prime, attrT);
      }

      const blindingT = G1Operations.multiply(generators.blindingGenerator, s_blind);
      T_prime = G1Operations.add(T_prime, blindingT);

      // Subtract C^c
      const C = G1Operations.deserialize(proof.commitment);
      const C_c = G1Operations.multiply(C, challenge);
      T_prime = G1Operations.add(T_prime, G1Operations.negate(C_c));

      const T_prime_bytes = G1Operations.serialize(T_prime);

      // Step 2: Recompute challenge
      const challenge_prime = HashOperations.computeChallenge(
        proof.commitment,
        T_prime_bytes,
        context,
        proof.nonce
      );
      const challenge_prime_bytes = FieldOperations.scalarToBytes(challenge_prime);

      // Step 3: Compare challenges
      const isValid = CryptoUtils.constantTimeEqual(proof.challenge, challenge_prime_bytes);

      if (isValid) {
        console.log('✓ Zero-knowledge proof is VALID');
      } else {
        console.log('❌ Zero-knowledge proof is INVALID');
      }

      return isValid;

    } catch (error) {
      console.error('❌ Proof verification error:', error);
      return false;
    }
  }

  /**
   * Encode attributes to field elements
   */
  encodeAttributes(
    attributes: Record<string, any>,
    excludeKeys: string[] = []
  ): { encoded: bigint[]; keys: string[] } {
    const encoded: bigint[] = [];
    const keys: string[] = [];

    for (const [key, value] of Object.entries(attributes)) {
      if (!excludeKeys.includes(key)) {
        encoded.push(HashOperations.encodeAttribute(value));
        keys.push(key);
      }
    }

    return { encoded, keys };
  }

  /**
   * Create complete commitment request for credential issuance
   */
  createCommitmentRequest(
    holderDid: string,
    pseudonym: Uint8Array,
    masterSecret: bigint,
    allAttributes: Record<string, any>,
    revealedAttributeKeys: string[],
    credentialSchema: string
  ): { request: CommitmentRequest; blindingFactor: bigint; attributeKeys: string[] } {
    console.log('\n========== CREATING COMMITMENT REQUEST ==========');
    console.log(`Holder DID: ${holderDid}`);
    console.log(`Credential Schema: ${credentialSchema}`);
    console.log(`Total attributes: ${Object.keys(allAttributes).length}`);
    console.log(`Revealed attributes: ${revealedAttributeKeys.length}`);

    // Encode hidden attributes only
    const { encoded: hiddenAttrs, keys: hiddenKeys } = this.encodeAttributes(
      allAttributes,
      revealedAttributeKeys
    );

    console.log(`Hidden attributes: ${hiddenKeys.length}`);

    // Create commitment
    const commitmentData = this.createCommitment(masterSecret, hiddenAttrs);

    // Generate context
    const nonce = CryptoUtils.randomBytes(32);
    const context = HashOperations.createContext(holderDid, credentialSchema, nonce);

    // Generate proof
    const proof = this.generateProof(
      masterSecret,
      hiddenAttrs,
      commitmentData.blindingFactor,
      commitmentData.commitment,
      context
    );

    // Extract revealed attributes
    const revealedAttributes: Record<string, any> = {};
    for (const key of revealedAttributeKeys) {
      if (key in allAttributes) {
        revealedAttributes[key] = allAttributes[key];
      }
    }

    const request: CommitmentRequest = {
      holderDid,
      pseudonym,
      commitment: commitmentData.commitment,
      proof,
      revealedAttributes,
      credentialSchema,
      timestamp: Date.now(),
      nonce
    };

    console.log('✅ Commitment request created');
    console.log('========== REQUEST CREATION COMPLETE ==========\n');

    return {
      request,
      blindingFactor: commitmentData.blindingFactor,
      attributeKeys: hiddenKeys
    };
  }
}

export default CommitmentProtocol;
