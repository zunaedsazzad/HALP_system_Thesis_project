/**
 * Trusted Setup Script for HALP Authentication Circuit
 * 
 * This script performs the Groth16 trusted setup ceremony:
 * 1. Powers of Tau ceremony (Phase 1) - can use Hermez production files
 * 2. Circuit-specific setup (Phase 2)
 * 3. Verification key export
 * 
 * For PRODUCTION: Use Hermez Powers of Tau files from:
 * https://github.com/hermeznetwork/phase2ceremony_4
 * 
 * These were generated through a multi-party computation (MPC) ceremony
 * with 1000+ participants, making them cryptographically secure.
 * 
 * Usage:
 *   node trusted-setup.js              # Generate local ptau (development)
 *   node trusted-setup.js --hermez     # Use Hermez production ptau (recommended)
 *   node trusted-setup.js --skip-ptau  # Skip ptau, use existing file
 *   node trusted-setup.js --power=18   # Use 2^18 ptau size
 */

const snarkjs = require('snarkjs');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const crypto = require('crypto');

const BUILD_DIR = path.join(__dirname, '..', 'build');
const R1CS_FILE = path.join(BUILD_DIR, 'halp-auth.r1cs');

// Hermez trusted Powers of Tau (production-grade, 2^16 supports ~65K constraints)
// Using the iden3 hosted version which is more reliable
const HERMEZ_PTAU_URL = 'https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau';
const HERMEZ_PTAU_FILE = path.join(BUILD_DIR, 'powersOfTau28_hez_final_16.ptau');

// Local generated ptau (for development/testing)
const LOCAL_PTAU_FILE = path.join(BUILD_DIR, 'pot_final.ptau');

// Output files
const ZKEY_INIT_FILE = path.join(BUILD_DIR, 'halp-auth_0.zkey');
const ZKEY_CONTRIB_FILE = path.join(BUILD_DIR, 'halp-auth_1.zkey');
const ZKEY_FINAL_FILE = path.join(BUILD_DIR, 'halp-auth_final.zkey');
const VKEY_FILE = path.join(BUILD_DIR, 'verification_key.json');

// Parse command line arguments
const args = process.argv.slice(2);
const useHermez = args.includes('--hermez') || args.includes('-h');
const skipPtau = args.includes('--skip-ptau') || args.includes('-s');
const ptauPowerArg = args.find(a => a.startsWith('--power='));
const ptauPower = ptauPowerArg ? parseInt(ptauPowerArg.split('=')[1]) : 16;

/**
 * Download a file from URL with progress indication
 */
function downloadFile(url, destPath) {
    return new Promise((resolve, reject) => {
        console.log(`  Downloading: ${url}`);
        console.log(`  Destination: ${destPath}`);
        
        const file = fs.createWriteStream(destPath);
        const protocol = url.startsWith('https') ? https : http;
        
        protocol.get(url, (response) => {
            // Handle redirects
            if (response.statusCode === 301 || response.statusCode === 302) {
                file.close();
                fs.unlinkSync(destPath);
                return downloadFile(response.headers.location, destPath).then(resolve).catch(reject);
            }
            
            if (response.statusCode !== 200) {
                file.close();
                fs.unlinkSync(destPath);
                reject(new Error(`HTTP ${response.statusCode}: ${response.statusMessage}`));
                return;
            }
            
            const totalSize = parseInt(response.headers['content-length'], 10);
            let downloadedSize = 0;
            let lastPercent = 0;
            
            response.on('data', (chunk) => {
                downloadedSize += chunk.length;
                if (totalSize) {
                    const percent = Math.floor((downloadedSize / totalSize) * 100);
                    if (percent >= lastPercent + 10) {
                        process.stdout.write(`  Progress: ${percent}% (${(downloadedSize / 1024 / 1024).toFixed(1)} MB)\r`);
                        lastPercent = percent;
                    }
                }
            });
            
            response.pipe(file);
            
            file.on('finish', () => {
                file.close();
                console.log(`\n  ✓ Download complete: ${(downloadedSize / 1024 / 1024).toFixed(1)} MB`);
                resolve();
            });
        }).on('error', (err) => {
            file.close();
            if (fs.existsSync(destPath)) fs.unlinkSync(destPath);
            reject(err);
        });
    });
}

/**
 * Generate Powers of Tau locally (for development)
 */
async function generateLocalPtau(power) {
    console.log(`\n[Phase 1] Generating Local Powers of Tau (2^${power})...`);
    console.log('  ⚠️  WARNING: For production, use Hermez ptau with --hermez flag');
    
    const ptau0 = path.join(BUILD_DIR, 'pot_0.ptau');
    const ptau1 = path.join(BUILD_DIR, 'pot_1.ptau');
    const ptauBeacon = path.join(BUILD_DIR, 'pot_beacon.ptau');
    
    // Start new powers of tau ceremony
    console.log('  Starting new accumulator...');
    await snarkjs.powersOfTau.newAccumulator("bn128", power, ptau0);
    
    // Contribute with random entropy
    console.log('  Adding contribution (random entropy)...');
    const entropy1 = `halp-contribution-${Date.now()}-${crypto.randomBytes(16).toString('hex')}`;
    await snarkjs.powersOfTau.contribute(ptau0, ptau1, 'HALP Contributor 1', entropy1);
    
    // Apply random beacon for finalization
    console.log('  Applying random beacon...');
    const beaconHash = crypto.randomBytes(32).toString('hex');
    await snarkjs.powersOfTau.beacon(ptau1, ptauBeacon, beaconHash, 10);
    
    // Prepare for phase 2
    console.log('  Preparing for phase 2...');
    await snarkjs.powersOfTau.preparePhase2(ptauBeacon, LOCAL_PTAU_FILE);
    
    // Cleanup intermediate files
    console.log('  Cleaning up intermediate files...');
    if (fs.existsSync(ptau0)) fs.unlinkSync(ptau0);
    if (fs.existsSync(ptau1)) fs.unlinkSync(ptau1);
    if (fs.existsSync(ptauBeacon)) fs.unlinkSync(ptauBeacon);
    
    console.log(`  ✓ Powers of Tau saved: ${LOCAL_PTAU_FILE}`);
    return LOCAL_PTAU_FILE;
}

/**
 * Download Hermez Powers of Tau (production-grade)
 */
async function downloadHermezPtau() {
    console.log('\n[Phase 1] Using Hermez Production Powers of Tau');
    console.log('  Source: Hermez trusted setup ceremony (1000+ participants)');
    console.log('  This provides cryptographic security for production use.');
    
    if (fs.existsSync(HERMEZ_PTAU_FILE)) {
        const stats = fs.statSync(HERMEZ_PTAU_FILE);
        console.log(`  ✓ Already downloaded: ${(stats.size / 1024 / 1024).toFixed(1)} MB`);
        return HERMEZ_PTAU_FILE;
    }
    
    await downloadFile(HERMEZ_PTAU_URL, HERMEZ_PTAU_FILE);
    return HERMEZ_PTAU_FILE;
}

/**
 * Run Phase 2 setup (circuit-specific)
 */
async function runPhase2Setup(ptauFile) {
    console.log('\n[Phase 2] Circuit-Specific Setup (Groth16)');
    
    // Generate initial zkey
    console.log('  Generating initial zkey from R1CS and PTAU...');
    console.log('  (This may take 1-2 minutes for large circuits)');
    await snarkjs.zKey.newZKey(R1CS_FILE, ptauFile, ZKEY_INIT_FILE);
    console.log('  ✓ Initial zkey generated');
    
    // Contribute to phase 2
    console.log('  Adding phase 2 contribution...');
    const entropy2 = `halp-phase2-${Date.now()}-${crypto.randomBytes(16).toString('hex')}`;
    await snarkjs.zKey.contribute(ZKEY_INIT_FILE, ZKEY_FINAL_FILE, 'HALP Phase2 Contributor', entropy2);
    console.log('  ✓ Phase 2 contribution added');
    console.log('  ✓ Final zkey generated');
    
    // Cleanup intermediate zkey files
    console.log('  Cleaning up intermediate zkeys...');
    if (fs.existsSync(ZKEY_INIT_FILE)) fs.unlinkSync(ZKEY_INIT_FILE);
}

/**
 * Export verification key
 */
async function exportVerificationKey() {
    console.log('\n[Phase 3] Exporting Verification Key');
    
    const vKey = await snarkjs.zKey.exportVerificationKey(ZKEY_FINAL_FILE);
    fs.writeFileSync(VKEY_FILE, JSON.stringify(vKey, null, 2));
    
    const stats = fs.statSync(VKEY_FILE);
    console.log(`  ✓ Verification key exported: ${(stats.size / 1024).toFixed(1)} KB`);
    
    return vKey;
}

/**
 * Verify the setup
 */
async function verifySetup(ptauFile) {
    console.log('\n[Phase 4] Verifying Setup');
    
    console.log('  Verifying zkey against R1CS and PTAU...');
    const isValid = await snarkjs.zKey.verifyFromR1cs(R1CS_FILE, ptauFile, ZKEY_FINAL_FILE);
    
    if (isValid) {
        console.log('  ✓ Zkey verification PASSED');
    } else {
        console.log('  ✗ Zkey verification FAILED!');
        throw new Error('Zkey verification failed');
    }
    
    return isValid;
}

/**
 * Main execution
 */
async function main() {
    console.log('='.repeat(70));
    console.log('HALP Authentication Circuit - Groth16 Trusted Setup');
    console.log('='.repeat(70));
    
    console.log('\nConfiguration:');
    console.log(`  Use Hermez PTAU: ${useHermez}`);
    console.log(`  Skip PTAU gen:   ${skipPtau}`);
    console.log(`  PTAU Power:      2^${ptauPower}`);
    
    // Check R1CS file exists
    if (!fs.existsSync(R1CS_FILE)) {
        console.error(`\n✗ Error: R1CS file not found: ${R1CS_FILE}`);
        console.error('  Run circuit compilation first:');
        console.error('  circom halp-auth.circom --r1cs --wasm --sym -o build -l node_modules');
        process.exit(1);
    }
    
    // Display circuit info
    console.log('\n[Circuit Information]');
    const r1csInfo = await snarkjs.r1cs.info(R1CS_FILE);
    console.log(`  Constraints:     ${r1csInfo.nConstraints.toLocaleString()}`);
    console.log(`  Private inputs:  ${r1csInfo.nPrvInputs}`);
    console.log(`  Public inputs:   ${r1csInfo.nPubInputs}`);
    console.log(`  Total signals:   ${r1csInfo.nVars}`);
    
    // Calculate required powers of tau
    const requiredPower = Math.ceil(Math.log2(r1csInfo.nConstraints + r1csInfo.nPubInputs + 1));
    console.log(`  Required PTAU:   2^${requiredPower} (minimum for ${r1csInfo.nConstraints} constraints)`);
    
    // Phase 1: Powers of Tau
    let ptauFile;
    
    if (skipPtau) {
        // Use existing ptau file
        if (fs.existsSync(HERMEZ_PTAU_FILE)) {
            ptauFile = HERMEZ_PTAU_FILE;
            console.log(`\n[Phase 1] Using existing Hermez PTAU`);
        } else if (fs.existsSync(LOCAL_PTAU_FILE)) {
            ptauFile = LOCAL_PTAU_FILE;
            console.log(`\n[Phase 1] Using existing local PTAU`);
        } else {
            console.error('\n✗ Error: No existing PTAU file found. Remove --skip-ptau flag.');
            process.exit(1);
        }
    } else if (useHermez) {
        // Download production Hermez ptau
        ptauFile = await downloadHermezPtau();
    } else {
        // Generate local ptau
        const actualPower = Math.max(ptauPower, requiredPower);
        if (actualPower > ptauPower) {
            console.log(`\n  Note: Increasing PTAU power from ${ptauPower} to ${actualPower} to fit circuit`);
        }
        ptauFile = await generateLocalPtau(actualPower);
    }
    
    // Phase 2: Circuit-specific setup
    await runPhase2Setup(ptauFile);
    
    // Phase 3: Export verification key
    await exportVerificationKey();
    
    // Phase 4: Verify everything
    await verifySetup(ptauFile);
    
    // Summary
    console.log('\n' + '='.repeat(70));
    console.log('✓ TRUSTED SETUP COMPLETE');
    console.log('='.repeat(70));
    
    console.log('\nGenerated Files:');
    
    const zkeyStats = fs.statSync(ZKEY_FINAL_FILE);
    const vkeyStats = fs.statSync(VKEY_FILE);
    console.log(`  Proving Key (zkey):`);
    console.log(`    ${path.basename(ZKEY_FINAL_FILE)}`);
    console.log(`    Size: ${(zkeyStats.size / 1024 / 1024).toFixed(2)} MB`);
    console.log(`  Verification Key:`);
    console.log(`    ${path.basename(VKEY_FILE)}`);
    console.log(`    Size: ${(vkeyStats.size / 1024).toFixed(2)} KB`);
    
    console.log('\nNext Steps:');
    console.log('  1. Run "node scripts/export-keys.js" to copy files to services');
    console.log('  2. Restart wallet-service and verifier-service');
    console.log('  3. Test with: .\\scripts\\test-full-flow.ps1');
    
    if (!useHermez) {
        console.log('\n⚠️  SECURITY NOTE:');
        console.log('  This setup used locally generated Powers of Tau.');
        console.log('  For production deployment, re-run with --hermez flag:');
        console.log('    node scripts/trusted-setup.js --hermez');
    }
}

main()
    .then(() => process.exit(0))
    .catch((err) => {
        console.error('\n✗ Setup failed:', err.message);
        if (process.env.DEBUG) console.error(err.stack);
        process.exit(1);
    });
