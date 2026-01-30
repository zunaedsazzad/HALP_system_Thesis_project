/**
 * Indexed Merkle Tree for HALP Nullifier Registry
 * 
 * This implementation provides:
 * - Efficient membership proofs for nullifiers
 * - Non-membership proofs for authentication
 * - Poseidon-based hashing for ZK-friendliness
 * 
 * The tree stores nullifiers that have been used, allowing verification
 * that a new nullifier hasn't been seen before (preventing replay attacks).
 */

// @ts-ignore - circomlibjs doesn't have proper TypeScript types
import { buildPoseidon } from 'circomlibjs';

// Tree configuration
const TREE_HEIGHT = 20; // Supports 2^20 = ~1M nullifiers

// Circomlibjs Poseidon instance
let poseidonInstance: any = null;
let F: any = null;

/**
 * Initialize Poseidon hash function (must be called before using the tree)
 */
export async function initPoseidon(): Promise<void> {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
    F = poseidonInstance.F;
    console.log('[MerkleTree] Poseidon hash initialized with circomlibjs');
  }
}

/**
 * Poseidon hash of 2 elements - circuit compatible
 */
function poseidonHash2(a: bigint, b: bigint): bigint {
  if (!poseidonInstance) {
    throw new Error('Poseidon not initialized - call initPoseidon() first');
  }
  const result = poseidonInstance([F.e(a), F.e(b)]);
  return F.toObject(result);
}

/**
 * Poseidon hash of 3 elements - circuit compatible
 */
function poseidonHash3(a: bigint, b: bigint, c: bigint): bigint {
  if (!poseidonInstance) {
    throw new Error('Poseidon not initialized - call initPoseidon() first');
  }
  const result = poseidonInstance([F.e(a), F.e(b), F.e(c)]);
  return F.toObject(result);
}

// Empty leaf value: Poseidon(0, 0, 0) - computed at init time
let EMPTY_LEAF_HASH: bigint = BigInt(0);

/**
 * Compute the empty leaf hash once Poseidon is initialized
 */
function getEmptyLeafHash(): bigint {
  if (EMPTY_LEAF_HASH === BigInt(0) && poseidonInstance) {
    // Empty leaf: nullifier=0, nextValue=0, nextIdx=0
    EMPTY_LEAF_HASH = poseidonHash3(BigInt(0), BigInt(0), BigInt(0));
  }
  return EMPTY_LEAF_HASH;
}

/**
 * Convert hex string to bigint
 */
function hexToBigInt(hex: string): bigint {
  if (!hex || hex === '0' || hex === '0x0') return BigInt(0);
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (cleanHex.length === 0) return BigInt(0);
  return BigInt('0x' + cleanHex);
}

/**
 * Convert bigint to hex string (64 chars, no 0x prefix)
 */
function bigIntToHex(n: bigint): string {
  const hex = n.toString(16);
  return hex.padStart(64, '0');
}

/**
 * Merkle Proof structure
 * Uses hex strings for external API, bigints internally
 */
export interface MerkleProof {
  leaf: string;
  root: string;
  siblings: string[];
  pathIndices: number[]; // 0 = left, 1 = right
  leafIndex: number;
  // Indexed Merkle tree fields for non-membership proof
  lowNullifier?: string;
  lowNullifierNextValue?: string;
  lowNullifierNextIdx?: number;
}

/**
 * Internal leaf structure for indexed Merkle tree
 */
interface IndexedLeaf {
  value: bigint;       // The nullifier value
  nextValue: bigint;   // Next nullifier in sorted order (0 if none)
  nextIdx: number;     // Index of next leaf
}

/**
 * Indexed Merkle Tree Implementation
 * Uses real Poseidon for circuit compatibility
 */
export class IndexedMerkleTree {
  private leaves: IndexedLeaf[] = [];
  private tree: bigint[][] = [];
  private height: number;
  private nullifierIndex: Map<string, number> = new Map();
  private initialized: boolean = false;
  
  constructor(height: number = TREE_HEIGHT) {
    this.height = height;
    console.log(`[MerkleTree] Created with height ${height}`);
  }
  
  /**
   * Initialize the tree (must be called before use)
   */
  async initialize(): Promise<void> {
    await initPoseidon();
    this.initializeEmptyTree();
    this.initialized = true;
    console.log(`[MerkleTree] Initialized with Poseidon hash`);
  }
  
  /**
   * Initialize tree with empty leaves
   */
  private initializeEmptyTree(): void {
    // Start with a single "zero" leaf that acts as the head of the sorted list
    this.leaves = [{
      value: BigInt(0),
      nextValue: BigInt(0),  // No next yet
      nextIdx: 0             // Points to itself initially
    }];
    
    this.rebuildTree();
  }
  
  /**
 * Compute leaf hash: Poseidon(value, nextValue, nextIdx)
 */
  private leafHash(leaf: IndexedLeaf): bigint {
    return poseidonHash3(leaf.value, leaf.nextValue, BigInt(leaf.nextIdx));
  }
  
  // Pre-computed empty subtree hashes at each level
  private emptySubtreeHashes: bigint[] = [];
  
  /**
   * Compute empty subtree hashes for each level (lazy computation)
   */
  private computeEmptySubtreeHashes(): void {
    if (this.emptySubtreeHashes.length > 0) return;
    
    const emptyLeaf = getEmptyLeafHash();
    this.emptySubtreeHashes = [emptyLeaf];
    
    let currentHash = emptyLeaf;
    for (let level = 0; level < this.height; level++) {
      currentHash = poseidonHash2(currentHash, currentHash);
      this.emptySubtreeHashes.push(currentHash);
    }
    console.log('[MerkleTree] Empty subtree hashes computed');
  }
  
  /**
   * Rebuild tree from current leaves (sparse computation)
   * Only computes hashes for actual leaves, uses empty subtree hashes for rest
   */
  private rebuildTree(): void {
    this.computeEmptySubtreeHashes();
    
    // Compute leaf hashes only for existing leaves
    const leafHashes: bigint[] = this.leaves.map(l => this.leafHash(l));
    
    // Build tree levels using sparse computation
    this.tree = [leafHashes];
    
    let currentLevel = leafHashes;
    for (let level = 0; level < this.height; level++) {
      const nextLevel: bigint[] = [];
      const emptySubtree = this.emptySubtreeHashes[level];
      
      // For each pair in current level
      const levelSize = Math.ceil(currentLevel.length / 2);
      for (let i = 0; i < levelSize; i++) {
        const leftIdx = i * 2;
        const rightIdx = i * 2 + 1;
        const left = leftIdx < currentLevel.length ? currentLevel[leftIdx] : emptySubtree;
        const right = rightIdx < currentLevel.length ? currentLevel[rightIdx] : emptySubtree;
        nextLevel.push(poseidonHash2(left, right));
      }
      
      // If odd number and more levels to go, the next level needs at least one node
      if (nextLevel.length === 0) {
        nextLevel.push(poseidonHash2(emptySubtree, emptySubtree));
      }
      
      this.tree.push(nextLevel);
      currentLevel = nextLevel;
    }
  }
  
  /**
   * Get current Merkle root as hex string
   */
  getRoot(): string {
    if (this.tree.length === 0 || this.tree[this.tree.length - 1].length === 0) {
      return bigIntToHex(getEmptyLeafHash());
    }
    return bigIntToHex(this.tree[this.tree.length - 1][0]);
  }
  
  /**
   * Get current Merkle root as bigint
   */
  getRootBigInt(): bigint {
    if (this.tree.length === 0 || this.tree[this.tree.length - 1].length === 0) {
      return getEmptyLeafHash();
    }
    return this.tree[this.tree.length - 1][0];
  }
  
  /**
   * Add a nullifier to the indexed Merkle tree
   * Maintains sorted order for efficient non-membership proofs
   * 
   * @param nullifier - Nullifier to add (hex string)
   * @returns Index of the added leaf
   */
  async addLeaf(nullifier: string): Promise<number> {
    const nullifierBigInt = hexToBigInt(nullifier);
    console.log(`\n[MerkleTree] Adding nullifier: ${nullifier.substring(0, 24)}...`);
    
    // Check if already exists
    if (this.nullifierIndex.has(nullifier)) {
      console.log('  Already exists at index:', this.nullifierIndex.get(nullifier));
      return this.nullifierIndex.get(nullifier)!;
    }
    
    // Find the predecessor (largest value smaller than new nullifier)
    let predecessorIdx = 0;
    for (let i = 0; i < this.leaves.length; i++) {
      if (this.leaves[i].value < nullifierBigInt && this.leaves[i].value > this.leaves[predecessorIdx].value) {
        predecessorIdx = i;
      }
    }
    
    // Create new leaf pointing to predecessor's next
    const newIdx = this.leaves.length;
    const newLeaf: IndexedLeaf = {
      value: nullifierBigInt,
      nextValue: this.leaves[predecessorIdx].nextValue,
      nextIdx: this.leaves[predecessorIdx].nextIdx
    };
    
    // Update predecessor to point to new leaf
    this.leaves[predecessorIdx].nextValue = nullifierBigInt;
    this.leaves[predecessorIdx].nextIdx = newIdx;
    
    // Add new leaf
    this.leaves.push(newLeaf);
    this.nullifierIndex.set(nullifier, newIdx);
    
    // Rebuild tree
    this.rebuildTree();
    
    console.log(`  Added at index: ${newIdx}`);
    console.log(`  New root: ${this.getRoot().substring(0, 24)}...`);
    
    return newIdx;
  }
  
  /**
   * Check if nullifier exists in tree
   * 
   * @param nullifier - Nullifier to check
   * @returns True if nullifier exists
   */
  hasNullifier(nullifier: string): boolean {
    return this.nullifierIndex.has(nullifier);
  }
  
  /**
   * Generate membership proof for a nullifier
   * 
   * @param nullifier - Nullifier to prove membership for
   * @returns Merkle proof or null if not found
   */
  async getMembershipProof(nullifier: string): Promise<MerkleProof | null> {
    const leafIndex = this.nullifierIndex.get(nullifier);
    
    if (leafIndex === undefined) {
      return null;
    }
    
    return this.getProofByIndex(leafIndex, nullifier);
  }
  
  /**
   * Generate non-membership proof
   * For a nullifier that should NOT be in the tree
   * 
   * Uses indexed Merkle tree: finds the "low nullifier" such that
   * lowNullifier < nullifier < lowNullifier.nextValue
   * 
   * @param nullifier - Nullifier to prove non-membership for
   * @returns Proof of non-membership with low nullifier info
   */
  async getNonMembershipProof(nullifier: string): Promise<MerkleProof> {
    const nullifierBigInt = hexToBigInt(nullifier);
    console.log(`\n[MerkleTree] Generating non-membership proof for: ${nullifier.substring(0, 24)}...`);
    
    // If nullifier exists, throw error
    if (this.hasNullifier(nullifier)) {
      throw new Error('Nullifier exists in tree - cannot generate non-membership proof');
    }
    
    // Find the "low nullifier": the largest value smaller than our nullifier
    // This is the leaf where lowNullifier < nullifier < lowNullifier.nextValue
    let lowNullifierIdx = 0;
    for (let i = 0; i < this.leaves.length; i++) {
      const leafValue = this.leaves[i].value;
      if (leafValue < nullifierBigInt && leafValue > this.leaves[lowNullifierIdx].value) {
        lowNullifierIdx = i;
      }
    }
    
    const lowLeaf = this.leaves[lowNullifierIdx];
    console.log(`  Low nullifier index: ${lowNullifierIdx}`);
    console.log(`  Low nullifier value: ${bigIntToHex(lowLeaf.value).substring(0, 24)}...`);
    console.log(`  Low nullifier next: ${bigIntToHex(lowLeaf.nextValue).substring(0, 24)}...`);
    
    return {
      leaf: nullifier,
      root: this.getRoot(),
      siblings: this.getSiblings(lowNullifierIdx),
      pathIndices: this.getPathIndices(lowNullifierIdx),
      leafIndex: lowNullifierIdx,
      // Indexed Merkle tree specific fields
      lowNullifier: bigIntToHex(lowLeaf.value),
      lowNullifierNextValue: bigIntToHex(lowLeaf.nextValue),
      lowNullifierNextIdx: lowLeaf.nextIdx
    };
  }
  
  /**
   * Get proof for a specific leaf index
   */
  private getProofByIndex(index: number, leaf: string): MerkleProof {
    const leafData = this.leaves[index];
    return {
      leaf,
      root: this.getRoot(),
      siblings: this.getSiblings(index),
      pathIndices: this.getPathIndices(index),
      leafIndex: index,
      lowNullifier: bigIntToHex(leafData.value),
      lowNullifierNextValue: bigIntToHex(leafData.nextValue),
      lowNullifierNextIdx: leafData.nextIdx
    };
  }
  
  /**
   * Get siblings for a leaf at given index (returns hex strings)
   * Uses empty subtree hashes for sparse regions
   */
  private getSiblings(index: number): string[] {
    const siblings: string[] = [];
    let currentIndex = index;
    
    for (let level = 0; level < this.height; level++) {
      const levelNodes = this.tree[level];
      const siblingIndex = currentIndex % 2 === 0 ? currentIndex + 1 : currentIndex - 1;
      
      if (siblingIndex >= 0 && siblingIndex < levelNodes.length) {
        siblings.push(bigIntToHex(levelNodes[siblingIndex]));
      } else {
        // Use pre-computed empty subtree hash for this level
        siblings.push(bigIntToHex(this.emptySubtreeHashes[level]));
      }
      
      currentIndex = Math.floor(currentIndex / 2);
    }
    
    return siblings;
  }
  
  /**
   * Get path indices (0 = left, 1 = right)
   */
  private getPathIndices(index: number): number[] {
    const indices: number[] = [];
    let currentIndex = index;
    
    for (let level = 0; level < this.height; level++) {
      indices.push(currentIndex % 2);
      currentIndex = Math.floor(currentIndex / 2);
    }
    
    return indices;
  }
  
  /**
   * Verify a Merkle proof
   * 
   * @param proof - The proof to verify
   * @returns True if proof is valid
   */
  async verifyProof(leaf: string, proof: MerkleProof): Promise<boolean> {
    console.log(`\n[MerkleTree] Verifying proof for: ${leaf.substring(0, 24)}...`);
    
    let currentHash = hexToBigInt(leaf);
    
    for (let i = 0; i < proof.siblings.length; i++) {
      const sibling = hexToBigInt(proof.siblings[i]);
      const pathIndex = proof.pathIndices[i];
      
      if (pathIndex === 0) {
        // Current node is left child
        currentHash = poseidonHash2(currentHash, sibling);
      } else {
        // Current node is right child
        currentHash = poseidonHash2(sibling, currentHash);
      }
    }
    
    const expectedRoot = hexToBigInt(proof.root);
    const isValid = currentHash === expectedRoot;
    console.log(`  Computed root: ${bigIntToHex(currentHash).substring(0, 24)}...`);
    console.log(`  Expected root: ${proof.root.substring(0, 24)}...`);
    console.log(`  Valid: ${isValid}`);
    
    return isValid;
  }
  
  /**
   * Get tree statistics
   */
  getStats(): { height: number; leafCount: number; root: string; updatedAt: number } {
    return {
      height: this.height,
      leafCount: this.leaves.length,
      root: this.getRoot(),
      updatedAt: Date.now()
    };
  }
}

// Create instance but don't initialize yet (must call initialize() first)
const merkleTree = new IndexedMerkleTree();
export default merkleTree;

