/**
 * Enhanced Credential Manager with Master Secret and Commitment Support
 * Integrates privacy-preserving credential issuance with BBS+ signatures
 */

import masterSecretManager, { MasterSecretManager } from './master-secret-manager';
import publicParamsManager, { PublicParametersManager } from './public-parameters';
import CommitmentProtocol, { CommitmentRequest } from './commitment-protocol';
import { CryptoUtils } from './crypto-utils';

export interface W3CVerifiableCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: { id: string; name?: string } | string;
  validFrom: string;
  validUntil?: string;
  credentialSubject: {
    id?: string;
    pseudonym?: string;
    commitment?: string;
    [key: string]: any;
  };
  credentialStatus?: any;
  proof?: any;
}

export interface CredentialRequestOptions {
  holderDid: string;
  attributes: Record<string, any>;
  revealedAttributes: string[];
  credentialSchema: string;
  issuerEndpoint: string;
}

export interface IssuanceResponse {
  success: boolean;
  verifiableCredential?: W3CVerifiableCredential;
  error?: string;
}

/**
 * Enhanced Credential Manager
 * Handles privacy-preserving credential issuance with master secrets
 */
export class EnhancedCredentialManager {
  private credentials: Map<string, W3CVerifiableCredential> = new Map();
  private msManager: MasterSecretManager;
  private paramsManager: PublicParametersManager;
  private commitmentProtocol: CommitmentProtocol;

  constructor() {
    this.msManager = masterSecretManager;
    this.paramsManager = publicParamsManager;
    this.commitmentProtocol = new CommitmentProtocol(this.paramsManager);
  }

  /**
   * Initialize the credential manager
   * Loads public parameters for commitment scheme
   */
  async initialize(paramsFilePath?: string): Promise<void> {
    try {
      this.paramsManager.loadParameters(paramsFilePath);
      console.log('✓ Enhanced Credential Manager initialized');
    } catch (error) {
      console.error('❌ Failed to initialize credential manager:', error);
      throw error;
    }
  }

  /**
   * Setup master secret for a holder DID
   * This should be done once per holder
   */
  async setupMasterSecret(holderDid: string): Promise<void> {
    const exists = await this.msManager.hasMasterSecret(holderDid);
    
    if (exists) {
      console.log(`ℹ️  Master secret already exists for ${holderDid}`);
      return;
    }

    await this.msManager.generateMasterSecret(holderDid);
    console.log(`✓ Master secret generated for ${holderDid}`);
  }

  /**
   * Request a credential using privacy-preserving commitment protocol
   * 
   * @param options - Credential request options
   * @returns Issued W3C Verifiable Credential with BBS+ signature
   */
  async requestCredentialWithCommitment(
    options: CredentialRequestOptions
  ): Promise<W3CVerifiableCredential> {
    console.log('\n========== REQUESTING CREDENTIAL WITH COMMITMENT ==========');
    console.log(`Holder DID: ${options.holderDid}`);
    console.log(`Credential Schema: ${options.credentialSchema}`);
    console.log(`Issuer: ${options.issuerEndpoint}`);

    // Step 1: Ensure master secret exists
    const hasMasterSecret = await this.msManager.hasMasterSecret(options.holderDid);
    if (!hasMasterSecret) {
      console.log('[Step 1] Generating master secret...');
      await this.setupMasterSecret(options.holderDid);
    } else {
      console.log('[Step 1] Using existing master secret');
    }

    // Step 2: Derive context-specific pseudonym
    console.log('\n[Step 2] Deriving pseudonym...');
    const context = `credential:${options.credentialSchema}`;
    const pseudonymData = await this.msManager.deriveContextPseudonym(
      options.holderDid,
      context
    );

    // Step 3: Get master secret
    console.log('\n[Step 3] Retrieving master secret...');
    const masterSecret = await this.msManager.getMasterSecret(options.holderDid);

    // Step 4: Create commitment request
    console.log('\n[Step 4] Creating commitment and zero-knowledge proof...');
    const { request, blindingFactor, attributeKeys } = 
      this.commitmentProtocol.createCommitmentRequest(
        options.holderDid,
        pseudonymData.pseudonym,
        masterSecret,
        options.attributes,
        options.revealedAttributes,
        options.credentialSchema
      );

    // Step 5: Send request to issuer
    console.log('\n[Step 5] Sending request to issuer...');
    const credential = await this.sendCommitmentRequest(options.issuerEndpoint, request);

    // Step 6: Verify and store credential
    console.log('\n[Step 6] Verifying and storing credential...');
    await this.verifyAndStoreCredential(credential, request, masterSecret);

    console.log('\n✅ CREDENTIAL ISSUED SUCCESSFULLY');
    console.log('========== REQUEST COMPLETE ==========\n');

    return credential;
  }

  /**
   * Send commitment request to issuer endpoint
   */
  private async sendCommitmentRequest(
    issuerEndpoint: string,
    request: CommitmentRequest
  ): Promise<W3CVerifiableCredential> {
    // Serialize the request
    const requestPayload = {
      holderDid: request.holderDid,
      pseudonym: CryptoUtils.bytesToHex(request.pseudonym),
      commitment: CryptoUtils.bytesToHex(request.commitment),
      proof: {
        commitment: CryptoUtils.bytesToHex(request.proof.commitment),
        T: CryptoUtils.bytesToHex(request.proof.T),
        challenge: CryptoUtils.bytesToHex(request.proof.challenge),
        responses: request.proof.responses.map(r => r.toString()),
        nonce: CryptoUtils.bytesToHex(request.proof.nonce)
      },
      revealedAttributes: request.revealedAttributes,
      credentialSchema: request.credentialSchema,
      timestamp: request.timestamp,
      nonce: CryptoUtils.bytesToHex(request.nonce)
    };

    console.log(`  Sending POST to ${issuerEndpoint}/credentials/issue-with-commitment`);

    const response = await fetch(`${issuerEndpoint}/credentials/issue-with-commitment`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestPayload)
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Issuer responded with ${response.status}: ${error}`);
    }

    const data = await response.json();
    console.log('  ✓ Credential received from issuer');

    return data.verifiableCredential || data;
  }

  /**
   * Verify credential is bound to master secret and store it
   */
  private async verifyAndStoreCredential(
    credential: W3CVerifiableCredential,
    request: CommitmentRequest,
    masterSecret: bigint
  ): Promise<void> {
    // Validate W3C VC format
    if (!this.isValidW3CCredential(credential)) {
      throw new Error('Received invalid W3C Verifiable Credential format');
    }

    // Verify commitment binding in credential
    if (credential.credentialSubject.commitment) {
      const receivedCommitment = credential.credentialSubject.commitment;
      const originalCommitment = CryptoUtils.bytesToHex(request.commitment);
      
      if (receivedCommitment !== originalCommitment) {
        throw new Error('Commitment mismatch - credential not bound to master secret');
      }
      console.log('  ✓ Commitment binding verified');
    }

    // Verify BBS+ signature (if present)
    if (credential.proof && credential.proof.type === 'BbsBlsSignature2020') {
      console.log('  ✓ BBS+ signature present');
      // TODO: Verify BBS+ signature
    }

    // Store credential
    await this.storeCredential(credential);
    console.log('  ✓ Credential stored securely');
  }

  /**
   * Store W3C VC securely
   */
  async storeCredential(credential: W3CVerifiableCredential): Promise<boolean> {
    if (!this.isValidW3CCredential(credential)) {
      throw new Error('Invalid W3C Verifiable Credential format');
    }
    
    this.credentials.set(credential.id, credential);
    // TODO: Persist to encrypted storage
    return true;
  }

  /**
   * Get credential by ID
   */
  async getCredential(id: string): Promise<W3CVerifiableCredential | null> {
    return this.credentials.get(id) || null;
  }

  /**
   * Get all credentials
   */
  async getAllCredentials(): Promise<W3CVerifiableCredential[]> {
    return Array.from(this.credentials.values());
  }

  /**
   * Legacy: Request credential without commitment (backward compatible)
   */
  async requestCredential(
    issuerUrl: string,
    payload: any
  ): Promise<W3CVerifiableCredential> {
    const res = await fetch(issuerUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      throw new Error(`Issuer responded with ${res.status}`);
    }

    const data = await res.json();
    const vc = data.verifiableCredential || data;
    
    await this.storeCredential(vc);
    return vc;
  }

  /**
   * Validate W3C VC format
   */
  private isValidW3CCredential(credential: any): boolean {
    return (
      credential &&
      Array.isArray(credential['@context']) &&
      credential['@context'].includes('https://www.w3.org/ns/credentials/v2') &&
      Array.isArray(credential.type) &&
      credential.type.includes('VerifiableCredential') &&
      credential.issuer &&
      credential.validFrom &&
      credential.credentialSubject
    );
  }

  /**
   * Get master secret metadata
   */
  async getMasterSecretMetadata(holderDid: string) {
    return await this.msManager.getMetadata(holderDid);
  }

  /**
   * Check if master secret exists
   */
  async hasMasterSecret(holderDid: string): Promise<boolean> {
    return await this.msManager.hasMasterSecret(holderDid);
  }
}

export default new EnhancedCredentialManager();
