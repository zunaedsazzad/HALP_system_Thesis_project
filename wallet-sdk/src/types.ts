// W3C Verifiable Credentials Data Model v2.0 Type Definitions

export interface W3CVerifiableCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: W3CIssuer | string;
  validFrom: string;
  validUntil?: string;
  credentialSubject: W3CCredentialSubject;
  credentialStatus?: W3CCredentialStatus;
  credentialSchema?: W3CCredentialSchema[];
  proof?: W3CProof | W3CProof[];
  evidence?: W3CEvidence[];
  termsOfUse?: W3CTermsOfUse[];
  refreshService?: W3CRefreshService;
}

export interface W3CIssuer {
  id: string;
  name?: string;
  description?: string;
}

export interface W3CCredentialSubject {
  id?: string;
  [key: string]: any;
}

export interface W3CCredentialStatus {
  id: string;
  type: string;
  [key: string]: any;
}

export interface W3CCredentialSchema {
  id: string;
  type: string;
}

export interface W3CProof {
  type: string;
  created?: string;
  verificationMethod?: string;
  proofPurpose?: string;
  proofValue?: string;
  [key: string]: any;
}

export interface W3CEvidence {
  id?: string;
  type: string[];
  [key: string]: any;
}

export interface W3CTermsOfUse {
  type: string;
  [key: string]: any;
}

export interface W3CRefreshService {
  type: string;
  url: string;
  [key: string]: any;
}

export interface W3CVerifiablePresentation {
  '@context': string[];
  id?: string;
  type: string[];
  holder?: string;
  verifiableCredential: W3CVerifiableCredential[];
  proof?: W3CProof | W3CProof[];
}
