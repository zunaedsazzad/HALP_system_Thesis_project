/**
 * Authentication Protocol Types for HALP System
 * Based on the 4-phase authentication process from the thesis
 */

/**
 * Phase 1: Challenge Generation Types
 */
export interface AuthChallenge {
  /** Unique identifier for this challenge */
  challengeId: string;
  /** Random 256-bit challenge from BLS12-381 scalar field (hex encoded) */
  challenge: string;
  /** Service domain identifier for scoping authentication */
  domain: string;
  /** Current Merkle tree root from nullifier registry (hex encoded) */
  registryRoot: string;
  /** SNARK circuit identifier for compatibility */
  circuitId: string;
  /** Timestamp when challenge was created */
  createdAt: number;
  /** Timestamp when challenge expires */
  expiresAt: number;
}

export interface ChallengeRequest {
  /** Service domain the holder wants to authenticate for */
  domain: string;
  /** Optional: specific credential type required */
  credentialType?: string;
}

/**
 * Phase 2: Proof Generation Types
 */
export interface AuthProofInputs {
  /** Master secret (private - never transmitted) */
  masterSecret: bigint;
  /** Session nonce (private) */
  sessionNonce: bigint;
  /** Credential identifier (private) */
  credentialId: string;
  /** BBS+ signature components (private) */
  signatureComponents: SignatureComponents;
  /** Merkle non-membership proof (private) */
  merkleProof: MerkleNonMembershipProof;
}

export interface SignatureComponents {
  /** BBS+ signature value */
  signature: string;
  /** Signature proof for selective disclosure */
  signatureProof?: string;
}

export interface MerkleNonMembershipProof {
  /** Sibling hashes along the path */
  siblings: string[];
  /** Path indices (0 = left, 1 = right) */
  pathIndices: number[];
  /** The leaf being proven (nullifier) */
  leaf: string;
  /** Root at time of proof generation */
  root: string;
}

export interface AuthProofPublicInputs {
  /** Session-specific pseudonym P = Poseidon(ms, nonce, domain) */
  pseudonym: string;
  /** Nullifier Nf = Poseidon(credID, nonce, domain) */
  nullifier: string;
  /** Registry Merkle root */
  registryRoot: string;
  /** Challenge from verifier */
  challenge: string;
  /** Issuer public key for credential verification */
  issuerPublicKey: string;
}

/**
 * Phase 3: Proof Submission Types
 */
export interface AuthenticationPackage {
  /** The original challenge (for binding) */
  challenge: string;
  /** Challenge ID for lookup */
  challengeId: string;
  /** zk-SNARK proof (hex encoded) */
  proof: string;
  /** Session-specific pseudonym (hex encoded) */
  pseudonym: string;
  /** Nullifier to prevent replay (hex encoded) */
  nullifier: string;
  /** Merkle root used during proof generation */
  registryRoot: string;
  /** Domain being authenticated for */
  domain: string;
  /** Proof timestamp */
  timestamp: number;
}

/**
 * Phase 4: Verification Types
 */
export interface VerificationResult {
  /** Whether verification succeeded */
  valid: boolean;
  /** Session-specific pseudonym (for session binding) */
  pseudonym?: string;
  /** Service domain */
  domain?: string;
  /** JWT session token (on success) */
  sessionToken?: string;
  /** Token expiration time */
  tokenExpiresAt?: number;
  /** Error message (on failure) */
  error?: string;
  /** Error code for programmatic handling */
  errorCode?: AuthErrorCode;
}

export enum AuthErrorCode {
  INVALID_CHALLENGE = 'INVALID_CHALLENGE',
  CHALLENGE_EXPIRED = 'CHALLENGE_EXPIRED',
  INVALID_PROOF = 'INVALID_PROOF',
  NULLIFIER_REUSED = 'NULLIFIER_REUSED',
  REGISTRY_ROOT_MISMATCH = 'REGISTRY_ROOT_MISMATCH',
  INTERNAL_ERROR = 'INTERNAL_ERROR',
}

/**
 * Nullifier Registry Types
 */
export interface NullifierCheckRequest {
  /** Nullifier to check (hex encoded) */
  nullifier: string;
}

export interface NullifierCheckResponse {
  /** Whether nullifier has been used */
  used: boolean;
  /** When it was used (if used) */
  usedAt?: number;
}

export interface NullifierRegistration {
  /** Nullifier being registered (hex encoded) */
  nullifier: string;
  /** Domain it was used for */
  domain: string;
  /** Pseudonym associated */
  pseudonym: string;
  /** Registration timestamp */
  timestamp: number;
}

/**
 * Merkle Tree Types
 */
export interface MerkleRootResponse {
  /** Current Merkle root (hex encoded) */
  root: string;
  /** Tree height */
  height: number;
  /** Number of leaves */
  leafCount: number;
  /** Timestamp of last update */
  updatedAt: number;
}

export interface MerkleProofRequest {
  /** Leaf value to prove (non-)membership for */
  leaf: string;
  /** Type of proof requested */
  proofType: 'membership' | 'non-membership';
}

export interface MerkleProofResponse {
  /** Whether proof generation succeeded */
  success: boolean;
  /** The proof data */
  proof?: MerkleNonMembershipProof;
  /** Error message if failed */
  error?: string;
}
