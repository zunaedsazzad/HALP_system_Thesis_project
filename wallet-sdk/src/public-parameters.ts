/**
 * Public Parameters for Pedersen Commitment Scheme
 * These parameters must be generated through trusted setup
 */

import { G1Operations, CryptoUtils, G1Point } from './crypto-utils';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import * as fs from 'fs';
import * as path from 'path';

export interface PublicParameters {
  version: number;
  maxAttributes: number;
  generatorG: string; // Hex-encoded G1 point
  attributeGenerators: string[]; // Hex-encoded G1 points [H1, H2, ..., Hk]
  blindingGenerator: string; // Hex-encoded G1 point Hr
  generatedAt: number;
}

/**
 * Trusted Setup for Public Parameters
 * In production, use secure MPC ceremony
 */
export class TrustedSetup {
  private static readonly PARAMS_VERSION = 1;
  private static readonly DEFAULT_MAX_ATTRIBUTES = 20;

  /**
   * Generate public parameters using hash-to-curve
   * This is deterministic and transparent (no toxic waste)
   */
  static generateParameters(maxAttributes: number = this.DEFAULT_MAX_ATTRIBUTES): PublicParameters {
    console.log('\n========== GENERATING PUBLIC PARAMETERS ==========');
    console.log(`Max attributes: ${maxAttributes}`);
    
    // Base generator G (standard BLS12-381 G1 generator)
    const G = G1Operations.getGenerator();
    const generatorG = CryptoUtils.bytesToHex(G1Operations.serialize(G));
    console.log(`✓ Base generator G`);

    // Generate independent generators for attributes using hash-to-curve
    const attributeGenerators: string[] = [];
    console.log('\n[Generating attribute generators]');
    for (let i = 0; i < maxAttributes; i++) {
      const domain = `BBS_ATTR_GENERATOR_${i}_V1`;
      const H_i = G1Operations.hashToCurve(domain);
      attributeGenerators.push(CryptoUtils.bytesToHex(G1Operations.serialize(H_i)));
      
      if (i < 5 || i >= maxAttributes - 2) {
        console.log(`  H[${i}]: ${attributeGenerators[i].substring(0, 16)}...`);
      } else if (i === 5) {
        console.log(`  ... (${maxAttributes - 7} more) ...`);
      }
    }
    console.log(`✓ Generated ${maxAttributes} attribute generators`);

    // Generate blinding factor generator
    const H_r = G1Operations.hashToCurve('BBS_BLINDING_GENERATOR_V1');
    const blindingGenerator = CryptoUtils.bytesToHex(G1Operations.serialize(H_r));
    console.log(`✓ Blinding generator Hr: ${blindingGenerator.substring(0, 16)}...`);

    const params: PublicParameters = {
      version: this.PARAMS_VERSION,
      maxAttributes,
      generatorG,
      attributeGenerators,
      blindingGenerator,
      generatedAt: Date.now()
    };

    console.log('\n✅ PUBLIC PARAMETERS GENERATED');
    console.log('========== GENERATION COMPLETE ==========\n');

    return params;
  }

  /**
   * Save parameters to file
   */
  static saveParameters(params: PublicParameters, filepath?: string): void {
    const defaultPath = path.join(__dirname, '..', '..', 'public-parameters.json');
    const targetPath = filepath || defaultPath;
    
    fs.writeFileSync(targetPath, JSON.stringify(params, null, 2), 'utf-8');
    console.log(`✓ Public parameters saved to: ${targetPath}`);
  }

  /**
   * Load parameters from file
   */
  static loadParameters(filepath?: string): PublicParameters {
    const defaultPath = path.join(__dirname, '..', '..', 'public-parameters.json');
    const targetPath = filepath || defaultPath;
    
    if (!fs.existsSync(targetPath)) {
      throw new Error(`Public parameters file not found: ${targetPath}`);
    }
    
    const data = fs.readFileSync(targetPath, 'utf-8');
    const params = JSON.parse(data) as PublicParameters;
    
    console.log(`✓ Public parameters loaded from: ${targetPath}`);
    console.log(`  Version: ${params.version}`);
    console.log(`  Max attributes: ${params.maxAttributes}`);
    console.log(`  Generated at: ${new Date(params.generatedAt).toISOString()}`);
    
    return params;
  }

  /**
   * Verify parameters are valid
   */
  static verifyParameters(params: PublicParameters): boolean {
    try {
      // Verify base generator
      const G_bytes = CryptoUtils.hexToBytes(params.generatorG);
      const G = G1Operations.deserialize(G_bytes);
      
      // Verify attribute generators
      if (params.attributeGenerators.length !== params.maxAttributes) {
        console.error('❌ Number of attribute generators does not match maxAttributes');
        return false;
      }
      
      for (let i = 0; i < params.attributeGenerators.length; i++) {
        const H_bytes = CryptoUtils.hexToBytes(params.attributeGenerators[i]);
        G1Operations.deserialize(H_bytes); // Throws if invalid
      }
      
      // Verify blinding generator
      const Hr_bytes = CryptoUtils.hexToBytes(params.blindingGenerator);
      G1Operations.deserialize(Hr_bytes);
      
      console.log('✓ Public parameters verified successfully');
      return true;
      
    } catch (error) {
      console.error('❌ Parameter verification failed:', error);
      return false;
    }
  }

  /**
   * Generate and save default parameters
   */
  static setupDefaultParameters(): PublicParameters {
    console.log('\n========== SETTING UP DEFAULT PARAMETERS ==========');
    
    const params = this.generateParameters();
    this.saveParameters(params);
    
    if (!this.verifyParameters(params)) {
      throw new Error('Generated parameters failed verification');
    }
    
    console.log('========== SETUP COMPLETE ==========\n');
    return params;
  }
}

/**
 * Public Parameters Manager
 * Handles loading and accessing public parameters
 */
export class PublicParametersManager {
  private params: PublicParameters | null = null;
  private parsedGenerators: {
    G: G1Point;
    attributeGenerators: G1Point[];
    blindingGenerator: G1Point;
  } | null = null;

  /**
   * Load and parse public parameters
   */
  loadParameters(filepath?: string): void {
    this.params = TrustedSetup.loadParameters(filepath);
    
    // Parse generators
    const G = G1Operations.deserialize(CryptoUtils.hexToBytes(this.params.generatorG));
    
    const attributeGenerators = this.params.attributeGenerators.map(hex =>
      G1Operations.deserialize(CryptoUtils.hexToBytes(hex))
    );
    
    const blindingGenerator = G1Operations.deserialize(
      CryptoUtils.hexToBytes(this.params.blindingGenerator)
    );
    
    this.parsedGenerators = {
      G,
      attributeGenerators,
      blindingGenerator
    };
    
    console.log('✓ Public parameters loaded and parsed');
  }

  /**
   * Get parsed generators
   */
  getGenerators() {
    if (!this.parsedGenerators) {
      throw new Error('Parameters not loaded. Call loadParameters() first.');
    }
    return this.parsedGenerators;
  }

  /**
   * Get raw parameters
   */
  getParameters(): PublicParameters {
    if (!this.params) {
      throw new Error('Parameters not loaded. Call loadParameters() first.');
    }
    return this.params;
  }

  /**
   * Get maximum number of attributes
   */
  getMaxAttributes(): number {
    if (!this.params) {
      throw new Error('Parameters not loaded. Call loadParameters() first.');
    }
    return this.params.maxAttributes;
  }
}

export default new PublicParametersManager();
