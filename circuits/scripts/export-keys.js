/**
 * Export Keys Script for HALP Circuit
 * 
 * Copies the generated circuit files to wallet-sdk and verifier-service
 * so they can generate and verify SNARK proofs.
 * 
 * Files distributed:
 * - wallet-sdk: halp-auth.wasm (witness), halp-auth_final.zkey (proving), verification_key.json
 * - verifier-service: verification_key.json (for verification)
 */

const fs = require('fs');
const path = require('path');

const BUILD_DIR = path.join(__dirname, '..', 'build');
const WALLET_SDK_DIR = path.join(__dirname, '..', '..', 'wallet-sdk', 'circuits');
const VERIFIER_SERVICE_DIR = path.join(__dirname, '..', '..', 'verifier-service', 'circuits');

// Files needed for proof generation (wallet-sdk)
const FILES_FOR_WALLET = [
    { src: 'halp-auth_js/halp-auth.wasm', desc: 'WASM witness calculator' },
    { src: 'halp-auth_final.zkey', desc: 'Proving key (Groth16)' },
    { src: 'verification_key.json', desc: 'Verification key (for local testing)' }
];

// Files needed for proof verification (verifier-service)
const FILES_FOR_VERIFIER = [
    { src: 'verification_key.json', desc: 'Verification key' }
];

function ensureDir(dir) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`  Created directory: ${dir}`);
    }
}

function copyFile(src, dest, desc) {
    if (!fs.existsSync(src)) {
        console.error(`  ✗ Source file not found: ${src}`);
        return false;
    }
    
    fs.copyFileSync(src, dest);
    const stats = fs.statSync(dest);
    const sizeStr = stats.size > 1024 * 1024 
        ? `${(stats.size / 1024 / 1024).toFixed(2)} MB`
        : `${(stats.size / 1024).toFixed(1)} KB`;
    console.log(`  ✓ ${path.basename(dest)} (${sizeStr}) - ${desc}`);
    return true;
}

async function main() {
    console.log('='.repeat(70));
    console.log('Exporting Circuit Files to Services');
    console.log('='.repeat(70));
    
    // Check build directory exists
    if (!fs.existsSync(BUILD_DIR)) {
        console.error(`\n✗ Build directory not found: ${BUILD_DIR}`);
        console.error('  Run the circuit build first: .\\build-circuit.ps1');
        process.exit(1);
    }
    
    // Ensure target directories exist
    ensureDir(WALLET_SDK_DIR);
    ensureDir(VERIFIER_SERVICE_DIR);
    
    let allSuccess = true;
    
    // Copy files to wallet-sdk
    console.log('\n[wallet-sdk/circuits]');
    console.log('  For: SNARK proof generation');
    for (const file of FILES_FOR_WALLET) {
        const src = path.join(BUILD_DIR, file.src);
        const dest = path.join(WALLET_SDK_DIR, path.basename(file.src));
        if (!copyFile(src, dest, file.desc)) {
            allSuccess = false;
        }
    }
    
    // Copy files to verifier-service
    console.log('\n[verifier-service/circuits]');
    console.log('  For: SNARK proof verification');
    for (const file of FILES_FOR_VERIFIER) {
        const src = path.join(BUILD_DIR, file.src);
        const dest = path.join(VERIFIER_SERVICE_DIR, path.basename(file.src));
        if (!copyFile(src, dest, file.desc)) {
            allSuccess = false;
        }
    }
    
    // Summary
    console.log('\n' + '='.repeat(70));
    if (allSuccess) {
        console.log('✓ Export Complete!');
        console.log('='.repeat(70));
        
        console.log('\nFiles exported to:');
        console.log(`  ${WALLET_SDK_DIR}/`);
        fs.readdirSync(WALLET_SDK_DIR).forEach(f => {
            console.log(`    - ${f}`);
        });
        console.log(`  ${VERIFIER_SERVICE_DIR}/`);
        fs.readdirSync(VERIFIER_SERVICE_DIR).forEach(f => {
            console.log(`    - ${f}`);
        });
        
        console.log('\nNext Steps:');
        console.log('  1. Restart the services to load new circuit files:');
        console.log('     Stop-Job *; Remove-Job *');
        console.log('     .\\scripts\\start-all-services.ps1');
        console.log('  2. Test the full flow:');
        console.log('     .\\scripts\\test-full-flow.ps1');
    } else {
        console.log('✗ Export had errors - some files were not copied');
        console.log('='.repeat(70));
        process.exit(1);
    }
}

main()
    .then(() => process.exit(0))
    .catch((err) => {
        console.error('Export failed:', err);
        process.exit(1);
    });
