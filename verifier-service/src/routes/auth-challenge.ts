import { FastifyPluginAsync } from 'fastify';
import ChallengeManager, { ChallengeRequest, AuthChallenge } from '../services/challenge-manager';
import { AuthVerifier } from '../services/auth-verifier';

// Singleton instances - IMPORTANT: Use the SAME challengeManager for both generation and verification
const challengeManager = new ChallengeManager(
  process.env.REGISTRY_SERVICE_URL || 'http://localhost:3003'
);
const authVerifier = new AuthVerifier(
  process.env.REGISTRY_SERVICE_URL || 'http://localhost:3003',
  challengeManager  // Pass the same challenge manager instance
);

// Request/Response schemas for validation
interface ChallengeRequestBody {
  domain: string;
  credentialType?: string;
}

interface VerifyResponseBody {
  challengeId: string;
  challenge: string;
  proof: string;
  publicSignals?: string[];
  pseudonym: string;
  nullifier: string;
  commitmentHash?: string;
  registryRoot: string;
  domain: string;
  timestamp: number;
}

const authRoutes: FastifyPluginAsync = async (fastify) => {
  /**
   * POST /auth/challenge
   * Phase 1: Generate authentication challenge
   * 
   * The holder requests a challenge for a specific domain.
   * Verifier responds with:
   * - Random challenge from BLS12-381 scalar field
   * - Current registry Merkle root
   * - Circuit identifier
   * - Expiration time
   */
  fastify.post<{ Body: ChallengeRequestBody }>('/challenge', async (request, reply) => {
    const { domain, credentialType } = request.body || {};
    
    if (!domain) {
      return reply.status(400).send({
        error: 'Missing required field: domain'
      });
    }
    
    console.log(`\n[Auth] Challenge requested for domain: ${domain}`);
    
    try {
      const challenge = await challengeManager.generateChallenge({
        domain,
        credentialType
      });
      
      return {
        success: true,
        challenge: {
          challengeId: challenge.challengeId,
          challenge: challenge.challenge,
          domain: challenge.domain,
          registryRoot: challenge.registryRoot,
          circuitId: challenge.circuitId,
          expiresAt: challenge.expiresAt
        }
      };
    } catch (error) {
      console.error('[Auth] Challenge generation failed:', error);
      return reply.status(500).send({
        error: 'Challenge generation failed',
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  /**
   * POST /auth/verify
   * Phase 4: Verify authentication proof and issue token
   * 
   * The holder submits their authentication package containing:
   * - The original challenge
   * - zk-SNARK proof
   * - Pseudonym and nullifier
   * - Registry root used
   * 
   * Verifier performs:
   * 1. Challenge validation
   * 2. SNARK proof verification
   * 3. Nullifier freshness check
   * 4. JWT token issuance
   */
  fastify.post<{ Body: VerifyResponseBody }>('/verify', async (request, reply) => {
    const {
      challengeId,
      challenge,
      proof,
      publicSignals,
      pseudonym,
      nullifier,
      commitmentHash,
      registryRoot,
      domain,
      timestamp
    } = request.body || {};
    
    // Validate required fields
    if (!challengeId || !challenge || !proof || !pseudonym || !nullifier || !domain) {
      return reply.status(400).send({
        error: 'Missing required fields',
        required: ['challengeId', 'challenge', 'proof', 'pseudonym', 'nullifier', 'domain']
      });
    }
    
    console.log(`\n[Auth] Verification request for challenge: ${challengeId}`);
    
    try {
      const result = await authVerifier.verifyAuthentication({
        challengeId,
        challenge,
        proof,
        publicSignals,
        pseudonym,
        nullifier,
        commitmentHash,
        registryRoot,
        domain,
        timestamp
      });
      
      if (result.valid) {
        // Consume the challenge to prevent replay
        challengeManager.consumeChallenge(challengeId);
        
        return {
          success: true,
          pseudonym: result.pseudonym,
          domain: result.domain,
          sessionToken: result.sessionToken,
          expiresAt: result.tokenExpiresAt
        };
      } else {
        return reply.status(401).send({
          success: false,
          error: result.error,
          errorCode: result.errorCode
        });
      }
    } catch (error) {
      console.error('[Auth] Verification failed:', error);
      return reply.status(500).send({
        error: 'Verification failed',
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  /**
   * GET /auth/challenge (legacy compatibility)
   * Simple challenge generation with default domain
   */
  fastify.get('/challenge', async (request, reply) => {
    const domain = 'default';
    
    try {
      const challenge = await challengeManager.generateChallenge({ domain });
      return {
        success: true,
        challenge: challenge.challenge,
        challengeId: challenge.challengeId,
        registryRoot: challenge.registryRoot,
        expiresAt: challenge.expiresAt
      };
    } catch (error) {
      return reply.status(500).send({
        error: 'Challenge generation failed'
      });
    }
  });
};

export default authRoutes;
