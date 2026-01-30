export class ProofGenerator {
  async generateProof(credential: any, options?: any): Promise<any> {
    // TODO: generate selective disclosure / SNARK / ZK proof
    return { proof: 'proof-stub' };
  }
}

export default new ProofGenerator();
