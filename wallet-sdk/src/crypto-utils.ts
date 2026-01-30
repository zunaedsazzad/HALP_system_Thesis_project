/**
 * Cryptographic Utilities for BLS12-381 Operations
 * Provides low-level cryptographic primitives for commitment schemes
 */

import { bls12_381 } from '@noble/curves/bls12-381.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from 'crypto';

// BLS12-381 G1 point operations
const G1 = bls12_381.G1;
const G1Point = G1.Point;

// Type for G1 points
type G1PointType = typeof G1Point.BASE;

/**
 * BLS12-381 Field Operations
 */
export class FieldOperations {
  // Field modulus for BLS12-381 Fr (scalar field)
  static readonly FIELD_MODULUS = BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001');

  /**
   * Generate a random scalar in the field Fr
   */
  static randomScalar(): bigint {
    const bytes = randomBytes(32);
    const scalar = BigInt('0x' + bytes.toString('hex'));
    return scalar % this.FIELD_MODULUS;
  }

  /**
   * Convert bigint to bytes (big-endian, 32 bytes)
   */
  static scalarToBytes(scalar: bigint): Uint8Array {
    const hex = scalar.toString(16).padStart(64, '0');
    return Uint8Array.from(Buffer.from(hex, 'hex'));
  }

  /**
   * Convert bytes to bigint
   */
  static bytesToScalar(bytes: Uint8Array): bigint {
    return BigInt('0x' + Buffer.from(bytes).toString('hex')) % this.FIELD_MODULUS;
  }

  /**
   * Modular addition
   */
  static addMod(a: bigint, b: bigint): bigint {
    return (a + b) % this.FIELD_MODULUS;
  }

  /**
   * Modular multiplication
   */
  static mulMod(a: bigint, b: bigint): bigint {
    return (a * b) % this.FIELD_MODULUS;
  }
}

/**
 * G1 Point Operations (BLS12-381)
 */
export class G1Operations {
  /**
   * Get the G1 generator point
   */
  static getGenerator(): G1PointType {
    return G1Point.BASE;
  }

  /**
   * Scalar multiplication: point * scalar
   */
  static multiply(
    point: G1PointType,
    scalar: bigint
  ): G1PointType {
    return point.multiply(scalar);
  }

  /**
   * Point addition
   */
  static add(
    point1: G1PointType,
    point2: G1PointType
  ): G1PointType {
    return point1.add(point2);
  }

  /**
   * Point negation
   */
  static negate(
    point: G1PointType
  ): G1PointType {
    return point.negate();
  }

  /**
   * Serialize G1 point to hex string
   */
  static serialize(point: G1PointType): Uint8Array {
    const hex = point.toHex(true); // Compressed
    return Uint8Array.from(Buffer.from(hex, 'hex'));
  }

  /**
   * Deserialize G1 point from bytes or hex string
   */
  static deserialize(bytes: Uint8Array | string): G1PointType {
    const hex = typeof bytes === 'string' ? bytes : Buffer.from(bytes).toString('hex');
    return G1Point.fromHex(hex);
  }

  /**
   * Hash arbitrary data to a G1 point (hash-to-curve)
   */
  static hashToCurve(data: string | Uint8Array): G1PointType {
    const dataBytes = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
    return bls12_381.G1.hashToCurve(dataBytes, {
      DST: 'BBS_COMMITMENT_HALP_V1',
    });
  }
}

// Export G1PointType type
export type { G1PointType as G1Point };

/**
 * Hash Functions for Fiat-Shamir Transform
 */
export class HashOperations {
  /**
   * Compute challenge for zero-knowledge proofs using Fiat-Shamir
   */
  static computeChallenge(
    commitment: Uint8Array,
    T: Uint8Array,
    context: Uint8Array,
    nonce: Uint8Array
  ): bigint {
    const parts = [
      Buffer.from('BBS_COMMITMENT_CHALLENGE_V1', 'utf-8'),
      Buffer.from(commitment),
      Buffer.from(T),
      Buffer.from(context),
      Buffer.from(nonce)
    ];
    const combined = Buffer.concat(parts);
    const digest = sha256(combined);
    return FieldOperations.bytesToScalar(digest);
  }

  /**
   * Hash data to create context string
   */
  static createContext(did: string, schemaId: string, nonce: Uint8Array): Uint8Array {
    const parts = [
      Buffer.from(did, 'utf-8'),
      Buffer.from(schemaId, 'utf-8'),
      Buffer.from(nonce)
    ];
    const combined = Buffer.concat(parts);
    return sha256(combined);
  }

  /**
   * Encode attribute to field element
   */
  static encodeAttribute(value: string | number | boolean): bigint {
    let dataBytes: Uint8Array;

    if (typeof value === 'string') {
      // Hash string to field element
      const hash = sha256(Buffer.from(value, 'utf-8'));
      dataBytes = hash;
    } else if (typeof value === 'number') {
      // Convert number to bigint
      return BigInt(Math.floor(value)) % FieldOperations.FIELD_MODULUS;
    } else if (typeof value === 'boolean') {
      // Boolean: 1 for true, 0 for false
      return BigInt(value ? 1 : 0);
    } else {
      throw new Error(`Unsupported attribute type: ${typeof value}`);
    }

    return FieldOperations.bytesToScalar(dataBytes);
  }
}

/**
 * Utility functions
 */
export class CryptoUtils {
  /**
   * Generate cryptographically secure random bytes
   */
  static randomBytes(length: number): Uint8Array {
    return randomBytes(length);
  }

  /**
   * Convert hex string to Uint8Array
   */
  static hexToBytes(hex: string): Uint8Array {
    return Uint8Array.from(Buffer.from(hex, 'hex'));
  }

  /**
   * Convert Uint8Array to hex string
   */
  static bytesToHex(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('hex');
  }

  /**
   * Constant-time comparison
   */
  static constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  }
}
