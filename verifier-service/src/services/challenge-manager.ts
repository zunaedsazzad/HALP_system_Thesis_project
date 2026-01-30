/**
 * Challenge Manager for HALP Verifier Service
 * 
 * Phase 1 of Authentication: Challenge Generation
 * 
 * The verifier generates a cryptographic challenge that:
 * 1. Is randomly sampled from BLS12-381 scalar field (256-bit, 128-bit security)
 * 2. Includes the current registry Merkle root for state binding
 * 3. Has a TTL to prevent stale challenge attacks
 * 4. Is bound to a specific service domain
 */

import { randomBytes } from 'crypto';
import { createHash } from 'crypto';

// SHA-256 hash function
function sha256(data: Buffer): Uint8Array {
  return createHash('sha256').update(data).digest();
}

// BLS12-381 scalar field modulus
const FIELD_MODULUS = BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001');

// Configuration
const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const CIRCUIT_ID = 'halp-auth-v1'; // SNARK circuit identifier

export interface AuthChallenge {
  challengeId: string;
  challenge: string;
  domain: string;
  registryRoot: string;
  circuitId: string;
  createdAt: number;
  expiresAt: number;
}

export interface ChallengeRequest {
  domain: string;
  credentialType?: string;
}

/**
 * In-memory challenge storage
 * In production, use Redis or similar for distributed systems
 */
class ChallengeStore {
  private challenges: Map<string, AuthChallenge> = new Map();
  private cleanupInterval: NodeJS.Timeout | null = null;
  
  constructor() {
    // Periodic cleanup of expired challenges
    this.cleanupInterval = setInterval(() => this.cleanup(), 60 * 1000);
  }
  
  store(challenge: AuthChallenge): void {
    this.challenges.set(challenge.challengeId, challenge);
  }
  
  get(challengeId: string): AuthChallenge | undefined {
    return this.challenges.get(challengeId);
  }
  
  delete(challengeId: string): boolean {
    return this.challenges.delete(challengeId);
  }
  
  private cleanup(): void {
    const now = Date.now();
    for (const [id, challenge] of this.challenges) {
      if (challenge.expiresAt < now) {
        this.challenges.delete(id);
      }
    }
  }
  
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
  }
}

/**
 * Challenge Manager
 */
export class ChallengeManager {
  private store: ChallengeStore;
  private registryServiceUrl: string;
  
  constructor(registryServiceUrl: string = 'http://localhost:3003') {
    this.store = new ChallengeStore();
    this.registryServiceUrl = registryServiceUrl;
  }
  
  /**
   * Generate a new authentication challenge
   * 
   * @param request - Challenge request with domain
   * @returns Generated challenge with all parameters
   */
  async generateChallenge(request: ChallengeRequest): Promise<AuthChallenge> {
    console.log('\n╔═══════════════════════════════════════════════════════════╗');
    console.log('║       PHASE 1: CHALLENGE GENERATION                       ║');
    console.log('╚═══════════════════════════════════════════════════════════╝\n');
    
    const { domain } = request;
    
    // Step 1: Generate challenge ID
    console.log('Step 1: Generate unique challenge ID');
    const challengeId = this.generateChallengeId();
    console.log(`  Challenge ID: ${challengeId}`);
    
    // Step 2: Sample random challenge from BLS12-381 scalar field
    console.log('\nStep 2: Sample cryptographic challenge');
    console.log('  Field: BLS12-381 scalar field Fr');
    console.log('  Security: 256-bit entropy → 128-bit security');
    const challengeBytes = randomBytes(32);
    const challengeBigInt = BigInt('0x' + challengeBytes.toString('hex')) % FIELD_MODULUS;
    const challenge = challengeBigInt.toString(16).padStart(64, '0');
    console.log(`  Challenge: ${challenge.substring(0, 32)}...`);
    
    // Step 3: Query registry for current Merkle root
    console.log('\nStep 3: Query nullifier registry for current Merkle root');
    const registryRoot = await this.getRegistryRoot();
    console.log(`  Registry root: ${registryRoot.substring(0, 32)}...`);
    
    // Step 4: Set timestamps
    console.log('\nStep 4: Set challenge expiration');
    const createdAt = Date.now();
    const expiresAt = createdAt + CHALLENGE_TTL_MS;
    console.log(`  Created: ${new Date(createdAt).toISOString()}`);
    console.log(`  Expires: ${new Date(expiresAt).toISOString()}`);
    console.log(`  TTL: ${CHALLENGE_TTL_MS / 1000} seconds`);
    
    // Create challenge object
    const authChallenge: AuthChallenge = {
      challengeId,
      challenge,
      domain,
      registryRoot,
      circuitId: CIRCUIT_ID,
      createdAt,
      expiresAt
    };
    
    // Step 5: Store challenge
    console.log('\nStep 5: Store challenge for verification');
    this.store.store(authChallenge);
    console.log('  ✓ Challenge stored');
    
    console.log('\n═══════════════════════════════════════════════════════════');
    console.log('✅ CHALLENGE GENERATION COMPLETE');
    console.log(`   Domain: ${domain}`);
    console.log(`   Circuit: ${CIRCUIT_ID}`);
    console.log('   Ready for holder to generate proof');
    console.log('═══════════════════════════════════════════════════════════\n');
    
    return authChallenge;
  }
  
  /**
   * Validate a challenge exists and hasn't expired
   * 
   * @param challengeId - Challenge ID to validate
   * @param expectedChallenge - Expected challenge value
   * @returns Validation result
   */
  validateChallenge(
    challengeId: string,
    expectedChallenge: string
  ): { valid: boolean; challenge?: AuthChallenge; error?: string } {
    console.log(`\n[Challenge] Validating challenge: ${challengeId}`);
    
    const challenge = this.store.get(challengeId);
    
    if (!challenge) {
      console.log('  ✗ Challenge not found');
      return { valid: false, error: 'Challenge not found or already used' };
    }
    
    if (Date.now() > challenge.expiresAt) {
      console.log('  ✗ Challenge expired');
      this.store.delete(challengeId);
      return { valid: false, error: 'Challenge has expired' };
    }
    
    if (challenge.challenge !== expectedChallenge) {
      console.log('  ✗ Challenge mismatch');
      return { valid: false, error: 'Challenge value mismatch' };
    }
    
    console.log('  ✓ Challenge valid');
    return { valid: true, challenge };
  }
  
  /**
   * Consume a challenge (mark as used)
   * 
   * @param challengeId - Challenge ID to consume
   */
  consumeChallenge(challengeId: string): void {
    this.store.delete(challengeId);
    console.log(`[Challenge] Challenge ${challengeId} consumed`);
  }
  
  /**
   * Get current Merkle root from registry service
   */
  private async getRegistryRoot(): Promise<string> {
    try {
      const response = await fetch(`${this.registryServiceUrl}/merkle/root`);
      if (response.ok) {
        const data = await response.json();
        return data.root;
      }
    } catch (error) {
      console.log('  [Warning] Could not reach registry, using placeholder root');
    }
    
    // Fallback: Generate deterministic placeholder root
    // In production, this should fail if registry is unavailable
    const placeholderRoot = sha256(Buffer.from('HALP_EMPTY_TREE_ROOT_V1'));
    return Buffer.from(placeholderRoot).toString('hex');
  }
  
  /**
   * Generate unique challenge ID
   */
  private generateChallengeId(): string {
    const timestamp = Date.now().toString(36);
    const random = randomBytes(8).toString('hex');
    return `ch_${timestamp}_${random}`;
  }
}

export default ChallengeManager;
