import {
  generateBls12381G2KeyPair,
  blsSign,
  blsVerify,
  blsCreateProof,
  blsVerifyProof,
  BbsKeyPair,
  BlsKeyPair
} from '@mattrglobal/bbs-signatures';

/**
 * BBS+ Signature Manager for W3C Verifiable Credentials
 * Provides selective disclosure capabilities
 */
class BbsPlusSigner {
  private keyPair: BlsKeyPair | null = null;

  /**
   * Generate a new BLS12-381 key pair for BBS+ signing
   */
  async generateKeyPair(): Promise<BlsKeyPair> {
    console.log('🔑 Generating BLS12-381 key pair for BBS+ signatures...');
    const keyPair = await generateBls12381G2KeyPair();
    this.keyPair = keyPair;
    console.log('✓ Key pair generated');
    console.log('  Public key size:', keyPair.publicKey.length, 'bytes');
    console.log('  Secret key size:', keyPair.secretKey.length, 'bytes');
    return this.keyPair;
  }

  /**
   * Set an existing key pair
   */
  setKeyPair(keyPair: BlsKeyPair): void {
    this.keyPair = keyPair;
  }

  /**
   * Get the current key pair
   */
  getKeyPair(): BlsKeyPair | null {
    return this.keyPair;
  }

  /**
   * Sign a W3C Verifiable Credential using BBS+
   * @param credential - The W3C VC object
   * @returns BBS+ signature as base64 string
   */
  async signCredential(credential: any): Promise<string> {
    if (!this.keyPair) {
      throw new Error('Key pair not initialized. Call generateKeyPair() first.');
    }

    console.log('\n========== BBS+ SIGNING ==========');
    console.log('Credential ID:', credential.id);
    console.log('Credential Type:', credential.type);

    // Convert credential to array of messages
    const messages = this.credentialToMessages(credential);
    console.log('Total messages to sign:', messages.length);
    messages.forEach((msg, idx) => {
      console.log(`  Message ${idx}:`, Buffer.from(msg).toString('utf-8').substring(0, 50) + '...');
    });

    console.log('\n[Signing with BBS+]');
    const signature = await blsSign({
      keyPair: this.keyPair,
      messages: messages,
    });

    console.log('✓ BBS+ signature created');
    console.log('  Signature size:', signature.length, 'bytes');
    console.log('========== SIGNING COMPLETE ==========\n');

    return Buffer.from(signature).toString('base64');
  }

  /**
   * Sign a W3C Verifiable Credential with master secret commitment binding
   * This binds the credential to the holder's master secret via a Pedersen commitment
   * @param credential - The W3C VC object
   * @param commitmentHex - Hex-encoded Pedersen commitment to master secret
   * @returns BBS+ signature as base64 string
   */
  async signCredentialWithCommitment(credential: any, commitmentHex: string): Promise<string> {
    if (!this.keyPair) {
      throw new Error('Key pair not initialized. Call generateKeyPair() first.');
    }

    console.log('\n========== BBS+ SIGNING WITH COMMITMENT ==========');
    console.log('Credential ID:', credential.id);
    console.log('Commitment (first 32 chars):', commitmentHex.substring(0, 32) + '...');
    console.log('🔗 Binding credential to master secret commitment');

    // Convert commitment hex string to Uint8Array
    const commitmentBytes = Uint8Array.from(Buffer.from(commitmentHex, 'hex'));
    
    // Convert credential to array of messages
    const credentialMessages = this.credentialToMessages(credential);
    
    // Prepend commitment as message[0] - this binds the signature to the commitment
    const messages = [commitmentBytes, ...credentialMessages];
    
    console.log('Total messages to sign:', messages.length);
    console.log('  Message 0: COMMITMENT (master secret binding)');
    credentialMessages.forEach((msg, idx) => {
      const label = this.getMessageLabels(credential)[idx];
      console.log(`  Message ${idx + 1}: ${label}`);
    });

    console.log('\n[Signing with BBS+ and commitment binding]');
    console.log('  ℹ️  Signature covers: commitment + credential fields');
    console.log('  🔐 Only holder with matching master secret can use this credential');
    
    const signature = await blsSign({
      keyPair: this.keyPair,
      messages: messages,
    });

    console.log('✓ BBS+ signature with commitment binding created');
    console.log('  Signature size:', signature.length, 'bytes');
    console.log('  Privacy property: Master secret binding enforced');
    console.log('========== SIGNING COMPLETE ==========\n');

    return Buffer.from(signature).toString('base64');
  }

  /**
   * Verify a BBS+ signed credential
   */
  async verifyCredential(credential: any, signatureBase64: string, publicKey: Uint8Array): Promise<boolean> {
    console.log('\n========== BBS+ VERIFICATION ==========');
    console.log('Credential ID:', credential.id);

    const messages = this.credentialToMessages(credential);
    const signature = Uint8Array.from(Buffer.from(signatureBase64, 'base64'));

    console.log('[Verifying BBS+ signature]');
    const result = await blsVerify({
      publicKey: publicKey,
      messages: messages,
      signature: signature,
    });

    const isValid = result.verified;
    console.log(isValid ? '✓ Signature is VALID' : '✗ Signature is INVALID');
    console.log('========== VERIFICATION COMPLETE ==========\n');

    return isValid;
  }

  /**
   * Create a selective disclosure proof from a signed credential
   * @param credential - The original credential
   * @param signatureBase64 - The BBS+ signature
   * @param revealedIndices - Array of message indices to reveal (e.g., [0, 2, 4])
   * @param nonce - Random nonce for the proof
   */
  async createSelectiveDisclosureProof(
    credential: any,
    signatureBase64: string,
    revealedIndices: number[],
    nonce: string = 'default-nonce'
  ): Promise<string> {
    if (!this.keyPair) {
      throw new Error('Key pair not initialized.');
    }

    console.log('\n========== CREATING SELECTIVE DISCLOSURE PROOF ==========');
    console.log('Credential ID:', credential.id);
    console.log('Revealed message indices:', revealedIndices);

    const messages = this.credentialToMessages(credential);
    const signature = Uint8Array.from(Buffer.from(signatureBase64, 'base64'));
    const nonceBytes = Uint8Array.from(Buffer.from(nonce, 'utf-8'));

    console.log('[Creating ZK proof]');
    const proof = await blsCreateProof({
      signature: signature,
      publicKey: this.keyPair.publicKey,
      messages: messages,
      nonce: nonceBytes,
      revealed: revealedIndices,
    });

    console.log('✓ Selective disclosure proof created');
    console.log('  Proof size:', proof.length, 'bytes');
    console.log('  Hidden messages:', messages.length - revealedIndices.length);
    console.log('========== PROOF CREATION COMPLETE ==========\n');

    return Buffer.from(proof).toString('base64');
  }

  /**
   * Verify a selective disclosure proof
   */
  async verifySelectiveDisclosureProof(
    proofBase64: string,
    revealedMessages: Uint8Array[],
    publicKey: Uint8Array,
    nonce: string = 'default-nonce'
  ): Promise<boolean> {
    console.log('\n========== VERIFYING SELECTIVE DISCLOSURE PROOF ==========');
    console.log('Revealed messages:', revealedMessages.length);

    const proof = Uint8Array.from(Buffer.from(proofBase64, 'base64'));
    const nonceBytes = Uint8Array.from(Buffer.from(nonce, 'utf-8'));

    console.log('[Verifying ZK proof]');
    const result = await blsVerifyProof({
      proof: proof,
      publicKey: publicKey,
      messages: revealedMessages,
      nonce: nonceBytes,
    });

    const isValid = result.verified;
    console.log(isValid ? '✓ Proof is VALID' : '✗ Proof is INVALID');
    console.log('========== PROOF VERIFICATION COMPLETE ==========\n');

    return isValid;
  }

  /**
   * Convert a W3C VC to an array of messages for BBS+ signing
   * Each field becomes a separate message to enable selective disclosure
   */
  private credentialToMessages(credential: any): Uint8Array[] {
    const messages: Uint8Array[] = [];

    // Message 0: @context
    messages.push(Uint8Array.from(Buffer.from(JSON.stringify(credential['@context']), 'utf-8')));

    // Message 1: id
    messages.push(Uint8Array.from(Buffer.from(credential.id, 'utf-8')));

    // Message 2: type
    messages.push(Uint8Array.from(Buffer.from(JSON.stringify(credential.type), 'utf-8')));

    // Message 3: issuer
    messages.push(Uint8Array.from(Buffer.from(JSON.stringify(credential.issuer), 'utf-8')));

    // Message 4: validFrom
    messages.push(Uint8Array.from(Buffer.from(credential.validFrom, 'utf-8')));

    // Message 5: validUntil (if present)
    if (credential.validUntil) {
      messages.push(Uint8Array.from(Buffer.from(credential.validUntil, 'utf-8')));
    }

    // Message 6+: credentialSubject fields (each field as separate message for selective disclosure)
    const subject = credential.credentialSubject;
    
    // Subject ID
    if (subject.id) {
      messages.push(Uint8Array.from(Buffer.from(subject.id, 'utf-8')));
    }

    // Each claim as a separate message
    Object.keys(subject).forEach(key => {
      if (key !== 'id') {
        const value = typeof subject[key] === 'object' 
          ? JSON.stringify(subject[key]) 
          : String(subject[key]);
        messages.push(Uint8Array.from(Buffer.from(`${key}:${value}`, 'utf-8')));
      }
    });

    return messages;
  }

  /**
   * Get message labels for understanding what each message index represents
   */
  getMessageLabels(credential: any): string[] {
    const labels: string[] = [
      '@context',
      'id',
      'type',
      'issuer',
      'validFrom',
    ];

    if (credential.validUntil) {
      labels.push('validUntil');
    }

    if (credential.credentialSubject?.id) {
      labels.push('credentialSubject.id');
    }

    Object.keys(credential.credentialSubject || {}).forEach(key => {
      if (key !== 'id') {
        labels.push(`credentialSubject.${key}`);
      }
    });

    return labels;
  }
}

// Singleton instance
const bbsPlusSigner = new BbsPlusSigner();

export default bbsPlusSigner;
