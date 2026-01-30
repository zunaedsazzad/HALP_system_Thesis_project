/**
 * Merkle Proof Routes for HALP Registry Service
 * 
 * Provides endpoints for:
 * - Getting current Merkle root
 * - Generating membership proofs
 * - Generating non-membership proofs (for authentication)
 * - Verifying proofs
 */

import { FastifyPluginAsync } from 'fastify';
import merkleTree from '../services/indexed-merkle-tree';

// Request body types
interface ProofRequest {
  leaf: string;
  proofType?: 'membership' | 'non-membership';
}

interface VerifyRequest {
  leaf: string;
  proof: {
    root: string;
    siblings: string[];
    pathIndices: number[];
    leafIndex: number;
  };
}

const merkleRoutes: FastifyPluginAsync = async (fastify) => {
  /**
   * GET /merkle/root
   * Get current Merkle tree root
   * Used by verifier during challenge generation
   */
  fastify.get('/root', async (request, reply) => {
    const stats = merkleTree.getStats();
    
    console.log(`\n[Merkle] Root requested: ${stats.root.substring(0, 24)}...`);
    
    return {
      root: stats.root,
      height: stats.height,
      leafCount: stats.leafCount,
      updatedAt: stats.updatedAt
    };
  });
  
  /**
   * POST /merkle/proof
   * Generate a Merkle proof for a nullifier
   * 
   * For authentication, the holder requests a NON-membership proof
   * to prove their nullifier hasn't been used before.
   */
  fastify.post<{ Body: ProofRequest }>('/proof', async (request, reply) => {
    const { leaf, proofType = 'non-membership' } = request.body || {};
    
    if (!leaf) {
      return reply.status(400).send({
        error: 'Missing required field: leaf'
      });
    }
    
    console.log(`\n[Merkle] Proof request for: ${leaf.substring(0, 24)}...`);
    console.log(`  Type: ${proofType}`);
    
    try {
      if (proofType === 'membership') {
        const proof = await merkleTree.getMembershipProof(leaf);
        
        if (!proof) {
          return reply.status(404).send({
            success: false,
            error: 'Leaf not found in tree'
          });
        }
        
        return {
          success: true,
          proofType: 'membership',
          proof
        };
      } else {
        // Non-membership proof
        const proof = await merkleTree.getNonMembershipProof(leaf);
        
        return {
          success: true,
          proofType: 'non-membership',
          proof
        };
      }
    } catch (error) {
      console.error('  Proof generation failed:', error);
      return reply.status(400).send({
        success: false,
        error: error instanceof Error ? error.message : 'Proof generation failed'
      });
    }
  });
  
  /**
   * POST /merkle/verify
   * Verify a Merkle proof
   */
  fastify.post<{ Body: VerifyRequest }>('/verify', async (request, reply) => {
    const { leaf, proof } = request.body || {};
    
    if (!leaf || !proof) {
      return reply.status(400).send({
        error: 'Missing required fields: leaf, proof'
      });
    }
    
    console.log(`\n[Merkle] Verifying proof for: ${leaf.substring(0, 24)}...`);
    
    try {
      const isValid = await merkleTree.verifyProof(leaf, {
        leaf,
        root: proof.root,
        siblings: proof.siblings,
        pathIndices: proof.pathIndices,
        leafIndex: proof.leafIndex
      });
      
      return {
        valid: isValid,
        leaf: leaf.substring(0, 32) + '...',
        expectedRoot: proof.root.substring(0, 32) + '...'
      };
    } catch (error) {
      console.error('  Verification failed:', error);
      return reply.status(400).send({
        valid: false,
        error: error instanceof Error ? error.message : 'Verification failed'
      });
    }
  });
  
  /**
   * GET /merkle/stats
   * Get Merkle tree statistics
   */
  fastify.get('/stats', async (request, reply) => {
    const stats = merkleTree.getStats();
    
    return {
      height: stats.height,
      leafCount: stats.leafCount,
      root: stats.root,
      maxCapacity: Math.pow(2, stats.height),
      utilizationPercent: (stats.leafCount / Math.pow(2, stats.height) * 100).toFixed(4)
    };
  });
};

export default merkleRoutes;
