pragma circom 2.1.6;

/**
 * HALP Authentication Circuit
 * 
 * This circuit proves knowledge of:
 * 1. Master secret that derives the pseudonym
 * 2. Credential ID that derives the nullifier
 * 3. Commitment opening (masterSecret, blindingFactor)
 * 4. Non-membership in the nullifier registry (Merkle proof)
 * 
 * Public Inputs:
 * - pseudonym: P = Poseidon(masterSecret, sessionNonce, domainHash)
 * - nullifier: Nf = Poseidon(credentialIdHash, sessionNonce, domainHash)
 * - commitmentHash: C = Poseidon(masterSecret, blindingFactor)
 * - registryRoot: Merkle root of nullifier registry
 * - challenge: Random challenge from verifier
 * 
 * Private Inputs:
 * - masterSecret: User's master secret
 * - sessionNonce: Session-specific nonce
 * - domainHash: Hash of the service domain
 * - credentialIdHash: Hash of the credential ID
 * - blindingFactor: Blinding factor for commitment
 * - merkleSiblings[20]: Merkle proof siblings
 * - merklePathIndices[20]: Path direction indicators (0=left, 1=right)
 * - lowNullifier: The low nullifier for non-membership proof
 * - lowNullifierNextIdx: Next index in the indexed tree
 */

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mux1.circom";
include "circomlib/circuits/bitify.circom";

/**
 * Poseidon hash of 2 inputs
 * Uses circomlib's Poseidon with nInputs=2
 */
template Poseidon2() {
    signal input in[2];
    signal output out;
    
    component hasher = Poseidon(2);
    hasher.inputs[0] <== in[0];
    hasher.inputs[1] <== in[1];
    out <== hasher.out;
}

/**
 * Poseidon hash of 3 inputs
 * Uses circomlib's Poseidon with nInputs=3
 */
template Poseidon3() {
    signal input in[3];
    signal output out;
    
    component hasher = Poseidon(3);
    hasher.inputs[0] <== in[0];
    hasher.inputs[1] <== in[1];
    hasher.inputs[2] <== in[2];
    out <== hasher.out;
}

/**
 * Merkle tree inclusion/non-membership proof verifier
 * For indexed Merkle tree non-membership proof
 */
template MerkleProof(levels) {
    signal input leaf;
    signal input siblings[levels];
    signal input pathIndices[levels];
    signal output root;
    
    component hashers[levels];
    component muxes[levels];
    
    signal hashes[levels + 1];
    hashes[0] <== leaf;
    
    for (var i = 0; i < levels; i++) {
        // Ensure pathIndices are binary
        pathIndices[i] * (1 - pathIndices[i]) === 0;
        
        hashers[i] = Poseidon2();
        muxes[i] = MultiMux1(2);
        
        // Mux to select order based on path
        muxes[i].c[0][0] <== hashes[i];
        muxes[i].c[0][1] <== siblings[i];
        muxes[i].c[1][0] <== siblings[i];
        muxes[i].c[1][1] <== hashes[i];
        muxes[i].s <== pathIndices[i];
        
        hashers[i].in[0] <== muxes[i].out[0];
        hashers[i].in[1] <== muxes[i].out[1];
        
        hashes[i + 1] <== hashers[i].out;
    }
    
    root <== hashes[levels];
}

/**
 * Non-membership proof for indexed Merkle tree
 * Proves that a nullifier is NOT in the tree by showing:
 * 1. lowNullifier < nullifier < lowNullifier.nextValue
 * 2. lowNullifier is a valid leaf in the tree
 */
template NonMembershipProof(levels) {
    signal input nullifier;
    signal input lowNullifier;
    signal input lowNullifierNextValue;
    signal input lowNullifierNextIdx;
    signal input siblings[levels];
    signal input pathIndices[levels];
    signal output root;
    
    // Verify: lowNullifier < nullifier
    // Use 252 bits (maximum supported by circomlib's LessThan)
    // BN128 field is ~254 bits but LessThan uses Num2Bits which requires n <= 252
    component lt1 = LessThan(252);
    lt1.in[0] <== lowNullifier;
    lt1.in[1] <== nullifier;
    lt1.out === 1;
    
    // Verify: nullifier < lowNullifierNextValue (or nextValue == 0 meaning end of list)
    component isZero = IsZero();
    isZero.in <== lowNullifierNextValue;
    
    component lt2 = LessThan(252);
    lt2.in[0] <== nullifier;
    lt2.in[1] <== lowNullifierNextValue;
    
    // Either nextValue is 0 (end of list) or nullifier < nextValue
    signal validRange;
    validRange <== isZero.out + lt2.out - isZero.out * lt2.out; // OR gate
    validRange === 1;
    
    // Compute the leaf hash: H(lowNullifier, lowNullifierNextValue, lowNullifierNextIdx)
    component leafHasher = Poseidon3();
    leafHasher.in[0] <== lowNullifier;
    leafHasher.in[1] <== lowNullifierNextValue;
    leafHasher.in[2] <== lowNullifierNextIdx;
    
    // Verify Merkle inclusion of the low nullifier leaf
    component merkleProof = MerkleProof(levels);
    merkleProof.leaf <== leafHasher.out;
    for (var i = 0; i < levels; i++) {
        merkleProof.siblings[i] <== siblings[i];
        merkleProof.pathIndices[i] <== pathIndices[i];
    }
    
    root <== merkleProof.root;
}

/**
 * Main HALP Authentication Circuit
 */
template HalpAuth(merkleLevels) {
    // ========== PUBLIC INPUTS ==========
    signal input pseudonym;          // P = Poseidon(ms, nonce, domain)
    signal input nullifier;          // Nf = Poseidon(credIdHash, nonce, domain)
    signal input commitmentHash;     // C = Poseidon(ms, r)
    signal input registryRoot;       // Expected Merkle root
    signal input challenge;          // Verifier's challenge (for binding)
    
    // ========== PRIVATE INPUTS ==========
    signal input masterSecret;
    signal input sessionNonce;
    signal input domainHash;
    signal input credentialIdHash;
    signal input blindingFactor;
    
    // Merkle non-membership proof inputs
    signal input lowNullifier;
    signal input lowNullifierNextValue;
    signal input lowNullifierNextIdx;
    signal input merkleSiblings[merkleLevels];
    signal input merklePathIndices[merkleLevels];
    
    // ========== CONSTRAINTS ==========
    
    // 1. Verify pseudonym derivation: P = Poseidon(masterSecret, sessionNonce, domainHash)
    component pseudonymHasher = Poseidon3();
    pseudonymHasher.in[0] <== masterSecret;
    pseudonymHasher.in[1] <== sessionNonce;
    pseudonymHasher.in[2] <== domainHash;
    pseudonymHasher.out === pseudonym;
    
    // 2. Verify nullifier derivation: Nf = Poseidon(credentialIdHash, sessionNonce, domainHash)
    component nullifierHasher = Poseidon3();
    nullifierHasher.in[0] <== credentialIdHash;
    nullifierHasher.in[1] <== sessionNonce;
    nullifierHasher.in[2] <== domainHash;
    nullifierHasher.out === nullifier;
    
    // 3. Verify commitment opening: C = Poseidon(masterSecret, blindingFactor)
    component commitmentHasher = Poseidon2();
    commitmentHasher.in[0] <== masterSecret;
    commitmentHasher.in[1] <== blindingFactor;
    commitmentHasher.out === commitmentHash;
    
    // 4. Verify non-membership in nullifier registry
    component nonMembership = NonMembershipProof(merkleLevels);
    nonMembership.nullifier <== nullifier;
    nonMembership.lowNullifier <== lowNullifier;
    nonMembership.lowNullifierNextValue <== lowNullifierNextValue;
    nonMembership.lowNullifierNextIdx <== lowNullifierNextIdx;
    for (var i = 0; i < merkleLevels; i++) {
        nonMembership.siblings[i] <== merkleSiblings[i];
        nonMembership.pathIndices[i] <== merklePathIndices[i];
    }
    nonMembership.root === registryRoot;
    
    // 5. Challenge binding (ensures proof is fresh)
    // We include challenge in the public inputs to bind the proof to this session
    // The challenge itself is verified by the verifier
    signal challengeSquare;
    challengeSquare <== challenge * challenge; // Dummy constraint to use challenge
}

// Instantiate with 20 levels (supports ~1M nullifiers)
component main {public [pseudonym, nullifier, commitmentHash, registryRoot, challenge]} = HalpAuth(20);
