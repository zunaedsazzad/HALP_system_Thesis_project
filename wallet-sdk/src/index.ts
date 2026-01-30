export { default as CredentialManager } from './credential-manager';
export { default as ProofGenerator } from './proof-generator';
export * from './pseudonym-deriver';
export { default as EnhancedCredentialManager } from './credential-manager-enhanced';
export { default as MasterSecretManager } from './master-secret-manager';
export { default as CommitmentProtocol } from './commitment-protocol';
export { TrustedSetup, default as PublicParametersManager } from './public-parameters';
export * from './crypto-utils';

// Authentication Protocol Exports
export { default as PoseidonHash } from './poseidon-hash';
export { default as NullifierManager } from './nullifier-manager';
export { default as AuthProofGenerator, AuthProofGenerator as AuthProofGeneratorClass } from './auth-proof-generator';
export * from './auth-types';

// Hybrid Proof Generation (SNARK + BBS+)
export { 
  default as HybridProofGenerator, 
  HybridProofGenerator as HybridProofGeneratorClass,
  HybridAuthProof,
  HybridAuthPackage,
  SnarkPublicInputs,
  StoredCredential,
  BBSSelectiveDisclosureProof
} from './hybrid-proof-generator';

