/**
 * Real SNARK Proof Generator for HALP System
 * 
 * This script generates real Groth16 proofs using the halp-auth circuit.
 * It's called by the PowerShell test script to demonstrate real proof generation.
 * 
 * Usage: node generate-real-proof.js <challenge> <domain> <outputFile>
 */

// Resolve modules from the circuits directory where snarkjs is installed
const path = require('path');
const circuitsDir = path.join(__dirname, '..', 'circuits');
const walletSdkDir = path.join(__dirname, '..', 'wallet-sdk');

// Try to load from circuits first, then wallet-sdk
let snarkjs, buildPoseidon;
try {
    snarkjs = require(path.join(circuitsDir, 'node_modules', 'snarkjs'));
} catch (e) {
    try {
        snarkjs = require(path.join(walletSdkDir, 'node_modules', 'snarkjs'));
    } catch (e2) {
        snarkjs = require('snarkjs');
    }
}

try {
    buildPoseidon = require(path.join(walletSdkDir, 'node_modules', 'circomlibjs')).buildPoseidon;
} catch (e) {
    try {
        buildPoseidon = require(path.join(circuitsDir, 'node_modules', 'circomlibjs')).buildPoseidon;
    } catch (e2) {
        buildPoseidon = require('circomlibjs').buildPoseidon;
    }
}

const crypto = require('crypto');
const fs = require('fs');

// Circuit files
const CIRCUITS_DIR = path.join(__dirname, '..', 'circuits', 'build');
const CIRCUIT_WASM = path.join(CIRCUITS_DIR, 'halp-auth_js', 'halp-auth.wasm');
const CIRCUIT_ZKEY = path.join(CIRCUITS_DIR, 'halp-auth_final.zkey');
const VERIFICATION_KEY = path.join(CIRCUITS_DIR, 'verification_key.json');

const MERKLE_LEVELS = 20;

// Helper to generate random field element
function randomFieldElement() {
    // BN128 scalar field order
    const FIELD_ORDER = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
    const bytes = crypto.randomBytes(32);
    const value = BigInt('0x' + bytes.toString('hex'));
    return value % FIELD_ORDER;
}

// Helper to convert bigint to hex string
function toHex(value) {
    const hex = value.toString(16);
    return '0x' + hex.padStart(64, '0');
}

// Poseidon hash wrapper
class PoseidonWrapper {
    constructor(poseidon) {
        this.poseidon = poseidon;
        this.F = poseidon.F;
    }

    hash2(a, b) {
        const result = this.poseidon([this.F.e(a), this.F.e(b)]);
        return this.F.toObject(result);
    }

    hash3(a, b, c) {
        const result = this.poseidon([this.F.e(a), this.F.e(b), this.F.e(c)]);
        return this.F.toObject(result);
    }

    hashString(str) {
        const bytes = Buffer.from(str, 'utf8');
        const chunks = [];
        for (let i = 0; i < bytes.length; i += 31) {
            const chunk = bytes.slice(i, Math.min(i + 31, bytes.length));
            chunks.push(BigInt('0x' + chunk.toString('hex')));
        }
        
        if (chunks.length === 0) {
            return this.hash2(BigInt(0), BigInt(0));
        } else if (chunks.length === 1) {
            return this.hash2(chunks[0], BigInt(0));
        } else {
            let acc = this.hash2(chunks[0], chunks[1]);
            for (let i = 2; i < chunks.length; i++) {
                acc = this.hash2(acc, chunks[i]);
            }
            return acc;
        }
    }
}

// Generate indexed Merkle tree for non-membership proof
function generateEmptyIndexedMerkleTree(poseidon, levels) {
    // For an empty tree with a single sentinel node at 0
    // The sentinel: (value=0, nextValue=0, nextIdx=0)
    // When nextValue=0, circuit treats it as "end of list" (see circuit line ~140)
    // This means any nullifier > 0 is valid (not in tree)
    
    // Leaf hash: H(0, 0, 0) - sentinel with nextValue=0 means end of sorted list
    const sentinelLeafHash = poseidon.hash3(BigInt(0), BigInt(0), BigInt(0));
    
    // Build the tree path from leaf to root
    const siblings = [];
    const pathIndices = [];
    
    let currentHash = sentinelLeafHash;
    
    // For a tree with only the sentinel at index 0, all path indices are 0 (go left)
    // and all siblings are zeros (empty subtrees)
    for (let i = 0; i < levels; i++) {
        pathIndices.push(0);
        siblings.push(BigInt(0)); // Empty sibling
        // currentHash = H(currentHash, 0) since we go left
        currentHash = poseidon.hash2(currentHash, BigInt(0));
    }
    
    return {
        root: currentHash,
        lowNullifier: BigInt(0),
        lowNullifierNextValue: BigInt(0),  // 0 = end of list, circuit handles this
        lowNullifierNextIdx: BigInt(0),
        siblings,
        pathIndices
    };
}

async function generateRealProof(challengeHex, domain) {
    console.log('\n╔════════════════════════════════════════════════════════════════════╗');
    console.log('║        REAL zk-SNARK PROOF GENERATION (Groth16)                    ║');
    console.log('╚════════════════════════════════════════════════════════════════════╝\n');

    // Check circuit files exist
    if (!fs.existsSync(CIRCUIT_WASM)) {
        throw new Error(`Circuit WASM not found: ${CIRCUIT_WASM}`);
    }
    if (!fs.existsSync(CIRCUIT_ZKEY)) {
        throw new Error(`Circuit zkey not found: ${CIRCUIT_ZKEY}`);
    }

    console.log('[1/8] Initializing Poseidon hash function...');
    const poseidonRaw = await buildPoseidon();
    const poseidon = new PoseidonWrapper(poseidonRaw);
    console.log('      ✓ Poseidon initialized (BN254 curve)\n');

    // Maximum value for LessThan(252) - all values must be < 2^252
    const MAX_252_BIT = 2n ** 252n;
    const fitsIn252Bits = (val) => BigInt(val) < MAX_252_BIT;

    console.log('[2/8] Generating cryptographic secrets...');
    
    // Retry until we get values that fit in 252 bits (circuit limitation)
    let masterSecret, sessionNonce, blindingFactor, credentialId;
    let domainHash, credentialIdHash;
    let pseudonymRaw, nullifierRaw;
    let attempts = 0;
    const MAX_ATTEMPTS = 100;
    
    while (attempts < MAX_ATTEMPTS) {
        attempts++;
        masterSecret = randomFieldElement();
        sessionNonce = randomFieldElement();
        blindingFactor = randomFieldElement();
        credentialId = 'urn:uuid:' + crypto.randomUUID();
        
        domainHash = poseidon.hashString(domain);
        credentialIdHash = poseidon.hashString(credentialId);
        
        pseudonymRaw = poseidon.hash3(masterSecret, sessionNonce, domainHash);
        nullifierRaw = poseidon.hash3(credentialIdHash, sessionNonce, domainHash);
        
        // Check if all values fit in 252 bits (circuit uses LessThan(252))
        if (fitsIn252Bits(pseudonymRaw) && fitsIn252Bits(nullifierRaw)) {
            console.log(`      ✓ Found valid values on attempt ${attempts}`);
            break;
        }
    }
    
    if (attempts >= MAX_ATTEMPTS) {
        throw new Error('Could not generate values that fit in 252 bits after ' + MAX_ATTEMPTS + ' attempts');
    }
    
    console.log('      ✓ Master secret generated (256-bit random)');
    console.log('      ✓ Session nonce generated');
    console.log('      ✓ Blinding factor generated');
    console.log(`      ✓ Credential ID: ${credentialId}\n`);

    console.log('[3/8] Computing derived values...');
    console.log(`      ✓ Domain hash: ${toHex(domainHash).substring(0, 24)}...`);
    console.log(`      ✓ Credential ID hash: ${toHex(credentialIdHash).substring(0, 24)}...\n`);

    console.log('[4/8] Computing pseudonym...');
    console.log('      Formula: P = Poseidon(masterSecret, sessionNonce, domainHash)');
    const pseudonym = toHex(pseudonymRaw);
    console.log(`      ✓ Pseudonym: ${pseudonym.substring(0, 40)}... (${pseudonymRaw.toString(2).length} bits)\n`);

    console.log('[5/8] Computing nullifier...');
    console.log('      Formula: Nf = Poseidon(credentialIdHash, sessionNonce, domainHash)');
    const nullifier = toHex(nullifierRaw);
    console.log(`      ✓ Nullifier: ${nullifier.substring(0, 40)}... (${nullifierRaw.toString(2).length} bits)\n`);

    console.log('[6/8] Computing commitment hash...');
    console.log('      Formula: C = Poseidon(masterSecret, blindingFactor)');
    const commitmentHashRaw = poseidon.hash2(masterSecret, blindingFactor);
    const commitmentHash = toHex(commitmentHashRaw);
    console.log(`      ✓ Commitment: ${commitmentHash.substring(0, 40)}...\n`);

    console.log('[7/8] Building indexed Merkle tree for non-membership proof...');
    const merkleTree = generateEmptyIndexedMerkleTree(poseidon, MERKLE_LEVELS);
    const registryRoot = toHex(merkleTree.root);
    console.log(`      ✓ Tree root: ${registryRoot.substring(0, 40)}...`);
    console.log(`      ✓ Tree levels: ${MERKLE_LEVELS}`);
    console.log(`      ✓ Low nullifier: 0 (sentinel node)`);
    console.log(`      ✓ Path indices: [${merkleTree.pathIndices.slice(0, 5).join(', ')}...]\n`);

    // Parse challenge
    const challenge = challengeHex.startsWith('0x') ? challengeHex : '0x' + challengeHex;

    // Prepare circuit inputs
    const hexToDecimal = (hex) => {
        const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
        return BigInt('0x' + cleanHex).toString();
    };

    const circuitInputs = {
        // Public inputs
        pseudonym: hexToDecimal(pseudonym),
        nullifier: hexToDecimal(nullifier),
        commitmentHash: hexToDecimal(commitmentHash),
        registryRoot: hexToDecimal(registryRoot),
        challenge: hexToDecimal(challenge),
        // Private inputs
        masterSecret: masterSecret.toString(),
        sessionNonce: sessionNonce.toString(),
        domainHash: domainHash.toString(),
        credentialIdHash: credentialIdHash.toString(),
        blindingFactor: blindingFactor.toString(),
        lowNullifier: merkleTree.lowNullifier.toString(),
        lowNullifierNextValue: merkleTree.lowNullifierNextValue.toString(),
        lowNullifierNextIdx: merkleTree.lowNullifierNextIdx.toString(),
        merkleSiblings: merkleTree.siblings.map(s => s.toString()),
        merklePathIndices: merkleTree.pathIndices
    };

    console.log('[8/8] Generating Groth16 proof with snarkjs...');
    console.log('      ⏳ This may take 5-15 seconds...\n');
    
    const startTime = Date.now();

    console.log('      ┌─────────────────────────────────────────────────┐');
    console.log('      │  CIRCUIT INPUTS (PUBLIC)                        │');
    console.log('      ├─────────────────────────────────────────────────┤');
    console.log(`      │  Pseudonym:   ${pseudonym.substring(0, 28)}...  │`);
    console.log(`      │  Nullifier:   ${nullifier.substring(0, 28)}...  │`);
    console.log(`      │  Commitment:  ${commitmentHash.substring(0, 28)}...  │`);
    console.log(`      │  Registry:    ${registryRoot.substring(0, 28)}...  │`);
    console.log(`      │  Challenge:   ${challenge.substring(0, 28)}...  │`);
    console.log('      └─────────────────────────────────────────────────┘\n');

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInputs,
        CIRCUIT_WASM,
        CIRCUIT_ZKEY
    );

    const proofTime = Date.now() - startTime;

    console.log('      ┌─────────────────────────────────────────────────┐');
    console.log('      │  GROTH16 PROOF GENERATED                        │');
    console.log('      ├─────────────────────────────────────────────────┤');
    console.log(`      │  π_a[0]: ${proof.pi_a[0].substring(0, 30)}...   │`);
    console.log(`      │  π_a[1]: ${proof.pi_a[1].substring(0, 30)}...   │`);
    console.log(`      │  π_b[0][0]: ${proof.pi_b[0][0].substring(0, 26)}... │`);
    console.log(`      │  π_b[0][1]: ${proof.pi_b[0][1].substring(0, 26)}... │`);
    console.log(`      │  π_c[0]: ${proof.pi_c[0].substring(0, 30)}...   │`);
    console.log(`      │  π_c[1]: ${proof.pi_c[1].substring(0, 30)}...   │`);
    console.log('      ├─────────────────────────────────────────────────┤');
    console.log(`      │  Time: ${proofTime}ms                              │`);
    console.log(`      │  Public signals: ${publicSignals.length}                        │`);
    console.log('      └─────────────────────────────────────────────────┘\n');

    // Verify the proof locally
    console.log('[VERIFY] Verifying proof locally with verification key...');
    const vKey = JSON.parse(fs.readFileSync(VERIFICATION_KEY, 'utf8'));
    const isValid = await snarkjs.groth16.verify(vKey, publicSignals, proof);
    
    if (isValid) {
        console.log('         ✅ LOCAL VERIFICATION PASSED!\n');
    } else {
        console.log('         ❌ LOCAL VERIFICATION FAILED!\n');
    }

    // Prepare output
    const result = {
        success: true,
        proofGenerated: true,
        proofTime: proofTime,
        localVerification: isValid,
        proof: {
            pi_a: proof.pi_a,
            pi_b: proof.pi_b,
            pi_c: proof.pi_c,
            protocol: proof.protocol || 'groth16',
            curve: proof.curve || 'bn128'
        },
        publicSignals: publicSignals,
        publicInputs: {
            pseudonym: pseudonym,
            nullifier: nullifier,
            commitmentHash: commitmentHash,
            registryRoot: registryRoot,
            challenge: challenge
        },
        metadata: {
            domain: domain,
            credentialId: credentialId,
            timestamp: Date.now(),
            circuitFile: 'halp-auth.circom',
            provingSystem: 'Groth16',
            curve: 'BN254 (alt_bn128)'
        }
    };

    console.log('╔════════════════════════════════════════════════════════════════════╗');
    console.log('║                    ✅ PROOF GENERATION COMPLETE                    ║');
    console.log('╠════════════════════════════════════════════════════════════════════╣');
    console.log(`║  Proof Time:        ${proofTime}ms                                        `);
    console.log(`║  Local Verified:    ${isValid ? 'YES ✓' : 'NO ✗'}                                        `);
    console.log(`║  Public Signals:    ${publicSignals.length}                                           `);
    console.log(`║  Domain:            ${domain}                              `);
    console.log('╚════════════════════════════════════════════════════════════════════╝\n');

    return result;
}

// Main execution
async function main() {
    const args = process.argv.slice(2);
    
    if (args.length < 2) {
        console.log('Usage: node generate-real-proof.js <challenge> <domain> [outputFile]');
        console.log('\nExample:');
        console.log('  node generate-real-proof.js 0x1234... test.halp.local proof-output.json');
        process.exit(1);
    }

    const challenge = args[0];
    const domain = args[1];
    const outputFile = args[2];

    try {
        const result = await generateRealProof(challenge, domain);
        
        if (outputFile) {
            fs.writeFileSync(outputFile, JSON.stringify(result, null, 2));
            console.log(`Proof saved to: ${outputFile}`);
        }
        
        // Output JSON for PowerShell to parse
        console.log('\n--- JSON OUTPUT START ---');
        console.log(JSON.stringify(result));
        console.log('--- JSON OUTPUT END ---');
        
        process.exit(0);
    } catch (error) {
        console.error('Error generating proof:', error.message);
        console.log('\n--- JSON OUTPUT START ---');
        console.log(JSON.stringify({ success: false, error: error.message }));
        console.log('--- JSON OUTPUT END ---');
        process.exit(1);
    }
}

main();
