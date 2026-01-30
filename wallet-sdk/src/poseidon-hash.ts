/**
 * Poseidon Hash Implementation for HALP Authentication
 * 
 * Uses circomlibjs to ensure exact compatibility with circomlib circuits.
 * This is critical for ZK-SNARK proof generation.
 */

import { FieldOperations, CryptoUtils } from './crypto-utils';
// @ts-ignore - circomlibjs has no type declarations
import { buildPoseidon } from 'circomlibjs';

// Cached Poseidon instance
let poseidonInstance: any = null;

/**
 * Initialize Poseidon hash function from circomlibjs
 */
async function getPoseidon(): Promise<any> {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
  }
  return poseidonInstance;
}

/**
 * Poseidon Hash Functions
 * Uses circomlibjs for exact circuit compatibility
 */
export class PoseidonHash {
  private static poseidon: any = null;
  private static initialized = false;
  private static initPromise: Promise<void> | null = null;

  /**
   * Ensure Poseidon is initialized (call this before using hash functions)
   */
  static async init(): Promise<void> {
    if (this.initialized) return;
    
    if (!this.initPromise) {
      this.initPromise = (async () => {
        this.poseidon = await buildPoseidon();
        this.initialized = true;
      })();
    }
    
    await this.initPromise;
  }

  /**
   * Get or initialize Poseidon
   */
  private static async getPoseidon(): Promise<any> {
    if (!this.initialized) {
      await this.init();
    }
    return this.poseidon;
  }

  /**
   * Hash two field elements (synchronous - requires prior init)
   * H(a, b) - most common usage
   */
  static hash2(a: bigint, b: bigint): bigint {
    if (!this.poseidon) {
      throw new Error('PoseidonHash not initialized. Call PoseidonHash.init() first.');
    }
    const F = this.poseidon.F;
    const result = this.poseidon([F.e(a), F.e(b)]);
    return F.toObject(result);
  }
  
  /**
   * Hash three field elements (synchronous - requires prior init)
   * H(a, b, c)
   */
  static hash3(a: bigint, b: bigint, c: bigint): bigint {
    if (!this.poseidon) {
      throw new Error('PoseidonHash not initialized. Call PoseidonHash.init() first.');
    }
    const F = this.poseidon.F;
    const result = this.poseidon([F.e(a), F.e(b), F.e(c)]);
    return F.toObject(result);
  }

  /**
   * Async version of hash2 (auto-initializes)
   */
  static async hash2Async(a: bigint, b: bigint): Promise<bigint> {
    const poseidon = await this.getPoseidon();
    const F = poseidon.F;
    const result = poseidon([F.e(a), F.e(b)]);
    return F.toObject(result);
  }

  /**
   * Async version of hash3 (auto-initializes)
   */
  static async hash3Async(a: bigint, b: bigint, c: bigint): Promise<bigint> {
    const poseidon = await this.getPoseidon();
    const F = poseidon.F;
    const result = poseidon([F.e(a), F.e(b), F.e(c)]);
    return F.toObject(result);
  }

  /**
   * Hash variable number of field elements
   */
  static hashMany(inputs: bigint[]): bigint {
    if (!this.poseidon) {
      throw new Error('PoseidonHash not initialized. Call PoseidonHash.init() first.');
    }
    if (inputs.length === 0) {
      return 0n;
    }
    const F = this.poseidon.F;
    const result = this.poseidon(inputs.map(i => F.e(i)));
    return F.toObject(result);
  }

  /**
   * Async version of hashMany (auto-initializes)
   */
  static async hashManyAsync(inputs: bigint[]): Promise<bigint> {
    const poseidon = await this.getPoseidon();
    if (inputs.length === 0) {
      return 0n;
    }
    const F = poseidon.F;
    const result = poseidon(inputs.map(i => F.e(i)));
    return F.toObject(result);
  }
  
  /**
   * Hash bytes to a field element
   */
  static hashBytes(data: Uint8Array): bigint {
    // Split bytes into 31-byte chunks (to fit in field)
    const chunks: bigint[] = [];
    for (let i = 0; i < data.length; i += 31) {
      const chunk = data.slice(i, Math.min(i + 31, data.length));
      const padded = new Uint8Array(32);
      padded.set(chunk, 0);
      chunks.push(FieldOperations.bytesToScalar(padded));
    }
    
    return this.hashMany(chunks);
  }
  
  /**
   * Hash a string to a field element
   */
  static hashString(str: string): bigint {
    const bytes = Buffer.from(str, 'utf-8');
    return this.hashBytes(bytes);
  }

  /**
   * Async version of hashString
   */
  static async hashStringAsync(str: string): Promise<bigint> {
    await this.init();
    return this.hashString(str);
  }
  
  /**
   * Convert field element to hex string
   */
  static toHex(value: bigint): string {
    return CryptoUtils.bytesToHex(FieldOperations.scalarToBytes(value));
  }
  
  /**
   * Convert hex string to field element
   */
  static fromHex(hex: string): bigint {
    return FieldOperations.bytesToScalar(CryptoUtils.hexToBytes(hex));
  }
}

export default PoseidonHash;
