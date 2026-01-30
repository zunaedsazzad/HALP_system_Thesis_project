"use strict";
/**
 * Setup Script for Public Parameters
 * Generates and saves public parameters for the commitment scheme
 */
Object.defineProperty(exports, "__esModule", { value: true });
const public_parameters_1 = require("./src/public-parameters");
async function main() {
    try {
        console.log('Setting up public parameters for HALP credential system...\n');
        // Generate parameters with 20 attribute slots
        const params = public_parameters_1.TrustedSetup.setupDefaultParameters();
        console.log('\n✅ Setup complete!');
        console.log('Public parameters saved to: public-parameters.json');
        console.log('\n⚠️  IMPORTANT: In production, use a secure MPC ceremony for trusted setup!');
    }
    catch (error) {
        console.error('❌ Setup failed:', error);
        process.exit(1);
    }
}
main();
