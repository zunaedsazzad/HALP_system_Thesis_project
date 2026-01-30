/**
 * Master Secret Manager
 * Manages generation, storage, and retrieval of master secrets
 * Provides pseudonym derivation for privacy-preserving credential issuance
 */

import { FieldOperations, G1Operations, HashOperations, CryptoUtils } from './crypto-utils';
import * as keytar from 'keytar';
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

const SERVICE_NAME = 'halp-credential-system';
const STORAGE_VERSION = 1;

export interface MasterSecretMetadata {
  pseudonym: string; // Hex-encoded public pseudonym
  createdAt: number;
  version: number;
}

export interface PseudonymData {
  pseudonym: Uint8Array;
  context: string;
}

/**
 * Secure storage backend using OS keychain
 */
class SecureStorage {
  private encryptionKey: Buffer;

  constructor() {
    // In production, derive this from hardware-backed key or use HSM
    this.encryptionKey = this.getOrCreateEncryptionKey();
  }

  /**
   * Store master secret securely in OS keychain
   */
  async storeMasterSecret(
    holderDid: string,
    masterSecret: bigint,
    metadata: MasterSecretMetadata
  ): Promise<void> {
    const msBytes = FieldOperations.scalarToBytes(masterSecret);
    
    // Encrypt master secret with AES-256-GCM
    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(msBytes),
      cipher.final()
    ]);
    const authTag = cipher.getAuthTag();
    
    // Store encrypted data
    const storedData = JSON.stringify({
      version: STORAGE_VERSION,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      ciphertext: encrypted.toString('hex'),
      metadata
    });
    
    await keytar.setPassword(SERVICE_NAME, `ms:${holderDid}`, storedData);
  }

  /**
   * Retrieve master secret from OS keychain
   */
  async getMasterSecret(holderDid: string): Promise<bigint | null> {
    const storedData = await keytar.getPassword(SERVICE_NAME, `ms:${holderDid}`);
    
    if (!storedData) {
      return null;
    }
    
    const data = JSON.parse(storedData);
    
    // Decrypt master secret
    const iv = Buffer.from(data.iv, 'hex');
    const authTag = Buffer.from(data.authTag, 'hex');
    const ciphertext = Buffer.from(data.ciphertext, 'hex');
    
    const decipher = createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
    decipher.setAuthTag(authTag);
    
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]);
    
    return FieldOperations.bytesToScalar(decrypted);
  }

  /**
   * Get metadata for master secret
   */
  async getMetadata(holderDid: string): Promise<MasterSecretMetadata | null> {
    const storedData = await keytar.getPassword(SERVICE_NAME, `ms:${holderDid}`);
    
    if (!storedData) {
      return null;
    }
    
    const data = JSON.parse(storedData);
    return data.metadata;
  }

  /**
   * Delete master secret (use with caution!)
   */
  async deleteMasterSecret(holderDid: string): Promise<boolean> {
    return await keytar.deletePassword(SERVICE_NAME, `ms:${holderDid}`);
  }

  /**
   * Get or create encryption key for storage
   */
  private getOrCreateEncryptionKey(): Buffer {
    // In development: Use a derived key
    // In production: Use HSM-backed key or hardware-bound key
    const keyMaterial = 'halp-master-secret-encryption-key-v1';
    const hash = require('crypto').createHash('sha256');
    hash.update(keyMaterial);
    return hash.digest();
  }
}

/**
 * Master Secret Manager
 */
export class MasterSecretManager {
  private storage: SecureStorage;

  constructor() {
    this.storage = new SecureStorage();
  }

  /**
   * Generate a new master secret for holder
   * Returns metadata only (never exposes the actual secret)
   */
  async generateMasterSecret(holderDid: string): Promise<MasterSecretMetadata> {
    console.log('\n╔═══════════════════════════════════════════════════════════╗');
    console.log('║       MASTER SECRET GENERATION (Demonstration)           ║');
    console.log('╚═══════════════════════════════════════════════════════════╝');
    console.log('\n[Teacher Demo] Cryptographic Master Secret Generation Process\n');
    
    // Check if master secret already exists
    const existing = await this.storage.getMetadata(holderDid);
    if (existing) {
      throw new Error('Master secret already exists for this DID');
    }

    console.log('Step 1: Generating cryptographically secure random scalar');
    console.log('  Algorithm: Random field element from BLS12-381 scalar field Fr');
    console.log('  Security: 256-bit entropy from crypto.randomBytes()');
    // Generate cryptographically secure master secret
    const masterSecret = FieldOperations.randomScalar();
    console.log('  ✓ Master secret generated (never exposed, only shown for demo)');
    console.log(`  Master Secret (bigint): ${masterSecret.toString().substring(0, 30)}...`);
    console.log(`  Bit length: ${masterSecret.toString(2).length} bits\n`);
    
    console.log('Step 2: Deriving base pseudonym using elliptic curve');
    console.log('  Formula: Nym = G1^ms (where G1 is generator on BLS12-381)');
    console.log('  Purpose: Public commitment to secret, enables unlinkable pseudonyms');
    // Derive base pseudonym: Nym = G1^ms
    const G = G1Operations.getGenerator();
    const pseudonymPoint = G1Operations.multiply(G, masterSecret);
    const pseudonymBytes = G1Operations.serialize(pseudonymPoint);
    const pseudonymHex = CryptoUtils.bytesToHex(pseudonymBytes);
    console.log(`  ✓ Base pseudonym computed`);
    console.log(`  Pseudonym (hex): ${pseudonymHex.substring(0, 32)}...`);
    console.log(`  Length: ${pseudonymBytes.length} bytes\n`);
    
    const metadata: MasterSecretMetadata = {
      pseudonym: pseudonymHex,
      createdAt: Date.now(),
      version: STORAGE_VERSION
    };
    
    console.log('Step 3: Encrypting and storing in OS keychain');
    console.log('  Encryption: AES-256-GCM');
    console.log('  Storage: System keychain (keytar)');
    console.log(`  Account: ${holderDid}`);
    // Store master secret securely
    await this.storage.storeMasterSecret(holderDid, masterSecret, metadata);
    console.log('  ✓ Master secret encrypted and stored securely\n');
    
    console.log('═══════════════════════════════════════════════════════════');
    console.log('✅ MASTER SECRET GENERATION COMPLETE');
    console.log(`   Holder DID: ${holderDid}`);
    console.log(`   Base Pseudonym: ${metadata.pseudonym.substring(0, 16)}...`);
    console.log(`   Created: ${new Date(metadata.createdAt).toISOString()}`);
    console.log('═══════════════════════════════════════════════════════════\n');
    
    return metadata;
  }

  /**
   * Derive context-specific pseudonym for unlinkability
   * Different contexts produce unlinkable pseudonyms
   * 
   * @param holderDid - Holder's DID
   * @param context - Context string (e.g., "credential:UniversityDegree")
   * @returns Context-specific pseudonym
   */
  async deriveContextPseudonym(holderDid: string, context: string): Promise<PseudonymData> {
    console.log('\n╔═══════════════════════════════════════════════════════════╗');
    console.log('║     CONTEXT-SPECIFIC PSEUDONYM DERIVATION (Demo)        ║');
    console.log('╚═══════════════════════════════════════════════════════════╝');
    console.log('\n[Teacher Demo] Unlinkable Pseudonym Generation\n');
    
    console.log('Step 1: Retrieving master secret from secure storage');
    console.log(`  Holder DID: ${holderDid}`);
    const masterSecret = await this.storage.getMasterSecret(holderDid);
    
    if (!masterSecret) {
      throw new Error('Master secret not found for this DID. Generate one first.');
    }
    console.log('  ✓ Master secret retrieved (encrypted in keychain)');
    console.log(`  Secret value: ${masterSecret.toString().substring(0, 25)}... (demo only)\n`);
    
    console.log('Step 2: Generating context-specific curve generator');
    console.log(`  Context: "${context}"`);
    console.log('  Algorithm: Hash-to-Curve (BLS12-381 G1)');
    // Generate context-specific generator: G_context = H(context)
    const contextData = `BBS_PSEUDONYM_${context}`;
    console.log(`  Hash input: "${contextData}"`);
    const G_context = G1Operations.hashToCurve(contextData);
    console.log('  ✓ Context generator computed\n');
    
    console.log('Step 3: Computing context-specific pseudonym');
    console.log('  Formula: Nym_context = G_context^ms');
    console.log('  Property: Different contexts yield unlinkable pseudonyms');
    // Derive pseudonym: Nym_context = G_context^ms
    const pseudonymPoint = G1Operations.multiply(G_context, masterSecret);
    const pseudonym = G1Operations.serialize(pseudonymPoint);
    const pseudonymHex = CryptoUtils.bytesToHex(pseudonym);
    console.log('  ✓ Pseudonym computed\n');
    
    console.log('═══════════════════════════════════════════════════════════');
    console.log('✅ CONTEXT PSEUDONYM DERIVED');
    console.log(`   Context: ${context}`);
    console.log(`   Pseudonym (hex): ${pseudonymHex.substring(0, 32)}...`);
    console.log(`   Full length: ${pseudonym.length} bytes`);
    console.log('   Unlinkability: ✓ (cannot link to other contexts)');
    console.log('═══════════════════════════════════════════════════════════\n');
    
    return {
      pseudonym,
      context
    };
  }

  /**
   * Get base pseudonym (derived from master secret)
   */
  async getBasePseudonym(holderDid: string): Promise<Uint8Array> {
    const metadata = await this.storage.getMetadata(holderDid);
    
    if (!metadata) {
      throw new Error('Master secret not found for this DID');
    }
    
    return CryptoUtils.hexToBytes(metadata.pseudonym);
  }

  /**
   * Get master secret (internal use only - use carefully!)
   */
  async getMasterSecret(holderDid: string): Promise<bigint> {
    const ms = await this.storage.getMasterSecret(holderDid);
    
    if (ms === null) {
      throw new Error('Master secret not found for this DID');
    }
    
    return ms;
  }

  /**
   * Check if master secret exists for DID
   */
  async hasMasterSecret(holderDid: string): Promise<boolean> {
    const metadata = await this.storage.getMetadata(holderDid);
    return metadata !== null;
  }

  /**
   * Get metadata for master secret
   */
  async getMetadata(holderDid: string): Promise<MasterSecretMetadata | null> {
    return await this.storage.getMetadata(holderDid);
  }

  /**
   * Delete master secret (WARNING: This will invalidate all credentials!)
   */
  async deleteMasterSecret(holderDid: string): Promise<boolean> {
    console.warn('⚠️  Deleting master secret - all credentials will be invalidated!');
    return await this.storage.deleteMasterSecret(holderDid);
  }
}

export default new MasterSecretManager();
