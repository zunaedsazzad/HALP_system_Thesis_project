import { generateKeyPairSync } from 'crypto';

export class KeyManager {
  private store: Map<string, { publicKeyPem: string; privateKeyPem: string }> = new Map();

  constructor() {}

  async generateKeyPair(idHint?: string): Promise<{ id: string; publicKeyPem: string; privateKeyPem: string }> {
    // Generate RSA key pair for RS256 signing (demo only). Use 2048 bits for example.
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const id = idHint || `key-${Date.now()}`;
    this.store.set(id, { publicKeyPem, privateKeyPem });
    return { id, publicKeyPem, privateKeyPem };
  }

  async getPublicKey(id: string): Promise<string | null> {
    return this.store.get(id)?.publicKeyPem ?? null;
  }

  async getPrivateKey(id: string): Promise<string | null> {
    return this.store.get(id)?.privateKeyPem ?? null;
  }
}

export default new KeyManager();
