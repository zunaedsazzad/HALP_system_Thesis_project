// W3C Verifiable Credential type definition
interface W3CVerifiableCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: { id: string; name?: string } | string;
  validFrom: string;
  validUntil?: string;
  credentialSubject: {
    id?: string;
    [key: string]: any;
  };
  credentialStatus?: any;
  proof?: any;
}

export class CredentialManager {
  private credentials: Map<string, W3CVerifiableCredential> = new Map();

  async storeCredential(credential: W3CVerifiableCredential): Promise<boolean> {
    // Store W3C VC securely in wallet storage
    if (!this.isValidW3CCredential(credential)) {
      throw new Error('Invalid W3C Verifiable Credential format');
    }
    this.credentials.set(credential.id, credential);
    // TODO: persist to encrypted storage
    return true;
  }

  async getCredential(id: string): Promise<W3CVerifiableCredential | null> {
    return this.credentials.get(id) || null;
  }

  async getAllCredentials(): Promise<W3CVerifiableCredential[]> {
    return Array.from(this.credentials.values());
  }
  
  async requestCredential(issuerUrl: string, payload: any): Promise<W3CVerifiableCredential> {
    // Request a W3C Verifiable Credential from an issuer endpoint
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
    
    // Validate and store the W3C VC
    await this.storeCredential(vc);
    return vc;
  }

  private isValidW3CCredential(credential: any): boolean {
    // Basic W3C VC v2.0 validation
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
}

export default new CredentialManager();
