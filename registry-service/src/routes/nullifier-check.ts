/**
 * Nullifier Registry Routes
 * 
 * Provides endpoints for:
 * - Checking if a nullifier has been used
 * - Registering new nullifiers
 * - Getting registry statistics
 */

import { FastifyPluginAsync } from 'fastify';
import merkleTree from '../services/indexed-merkle-tree';

// In-memory nullifier metadata storage
interface NullifierRecord {
  nullifier: string;
  domain: string;
  pseudonym: string;
  timestamp: number;
  treeIndex: number;
}

const nullifierRecords: Map<string, NullifierRecord> = new Map();

// Request body types
interface CheckNullifierBody {
  nullifier: string;
}

interface RegisterNullifierBody {
  nullifier: string;
  domain: string;
  pseudonym: string;
  timestamp?: number;
}

const nullifierRoutes: FastifyPluginAsync = async (fastify) => {
  /**
   * POST /nullifiers/check
   * Check if a nullifier has been used before
   */
  fastify.post<{ Body: CheckNullifierBody }>('/check', async (request, reply) => {
    const { nullifier } = request.body || {};
    
    if (!nullifier) {
      return reply.status(400).send({
        error: 'Missing required field: nullifier'
      });
    }
    
    console.log(`\n[Nullifier] Checking: ${nullifier.substring(0, 24)}...`);
    
    const used = merkleTree.hasNullifier(nullifier);
    const record = nullifierRecords.get(nullifier);
    
    console.log(`  Result: ${used ? 'USED' : 'NOT USED'}`);
    
    return {
      nullifier: nullifier.substring(0, 32) + '...',
      used,
      usedAt: record?.timestamp,
      domain: record?.domain
    };
  });
  
  /**
   * POST /nullifiers/register
   * Register a new nullifier (called after successful authentication)
   */
  fastify.post<{ Body: RegisterNullifierBody }>('/register', async (request, reply) => {
    const { nullifier, domain, pseudonym, timestamp } = request.body || {};
    
    if (!nullifier || !domain || !pseudonym) {
      return reply.status(400).send({
        error: 'Missing required fields',
        required: ['nullifier', 'domain', 'pseudonym']
      });
    }
    
    console.log(`\n[Nullifier] Registering: ${nullifier.substring(0, 24)}...`);
    
    // Check if already registered
    if (merkleTree.hasNullifier(nullifier)) {
      console.log('  Already registered');
      return reply.status(409).send({
        error: 'Nullifier already registered',
        used: true
      });
    }
    
    // Add to Merkle tree
    const treeIndex = await merkleTree.addLeaf(nullifier);
    
    // Store metadata
    const record: NullifierRecord = {
      nullifier,
      domain,
      pseudonym,
      timestamp: timestamp || Date.now(),
      treeIndex
    };
    nullifierRecords.set(nullifier, record);
    
    console.log(`  Registered at index: ${treeIndex}`);
    console.log(`  New tree root: ${merkleTree.getRoot().substring(0, 24)}...`);
    
    return {
      success: true,
      nullifier: nullifier.substring(0, 32) + '...',
      treeIndex,
      newRoot: merkleTree.getRoot()
    };
  });
  
  /**
   * GET /nullifiers/stats
   * Get nullifier registry statistics
   */
  fastify.get('/stats', async (request, reply) => {
    const stats = merkleTree.getStats();
    
    return {
      totalNullifiers: stats.leafCount,
      treeHeight: stats.height,
      currentRoot: stats.root,
      lastUpdated: stats.updatedAt
    };
  });
};

export default nullifierRoutes;
