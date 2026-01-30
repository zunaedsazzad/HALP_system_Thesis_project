import keyManager from './key-manager';

type DidDoc = any;

export class DidManager {
  private store: Map<string, DidDoc> = new Map();
  private defaultDid: string | null = null;
  private didToKeyId: Map<string, string> = new Map();

  async createDid(idHint?: string): Promise<{ did: string; doc: DidDoc }> {
    console.log('\n[DID Manager] Creating new DID...');
    console.log('ID hint:', idHint || 'none');
    const { id, publicKeyPem } = await keyManager.generateKeyPair(idHint);
    const did = `did:local:${id}`;
    console.log('Generated DID:', did);
    const vmId = `${did}#key-1`;
    const doc = {
      '@context': 'https://www.w3.org/ns/did/v1',
      id: did,
      verificationMethod: [
        {
          id: vmId,
          type: 'RsaVerificationKey2018',
          controller: did,
          publicKeyPem,
        },
      ],
      assertionMethod: [vmId],
    };
    this.store.set(did, doc);
    // remember which key id corresponds to this DID
    this.didToKeyId.set(did, id);
    if (!this.defaultDid) {
      this.defaultDid = did;
      console.log('✓ Set as default DID');
    }
    console.log('✓ DID document created and stored');
    return { did, doc };
  }

  async resolve(did: string): Promise<DidDoc | null> {
    console.log('[DID Manager] Resolving DID:', did);
    const doc = this.store.get(did) ?? null;
    if (doc) {
      console.log('✓ DID document found');
    } else {
      console.log('⚠ DID document not found');
    }
    return doc;
  }

  async getPrivateKeyForDid(did: string): Promise<string | null> {
    const keyId = this.didToKeyId.get(did);
    if (!keyId) return null;
    return await keyManager.getPrivateKey(keyId);
  }

  async getOrCreateDefaultDid(): Promise<{ did: string; doc: DidDoc }> {
    if (process.env.ISSUER_DID) {
      const set = this.store.get(process.env.ISSUER_DID as string);
      if (set) return { did: process.env.ISSUER_DID as string, doc: set };
      // if env-specified DID exists but not in store, return a minimal doc placeholder
      return { did: process.env.ISSUER_DID as string, doc: { id: process.env.ISSUER_DID } };
    }

    if (this.defaultDid) {
      const doc = this.store.get(this.defaultDid as string) as DidDoc;
      return { did: this.defaultDid as string, doc };
    }

    return await this.createDid('issuer');
  }
}

export default new DidManager();
