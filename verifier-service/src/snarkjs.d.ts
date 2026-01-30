/**
 * Type declarations for snarkjs
 */
declare module 'snarkjs' {
  export namespace groth16 {
    function fullProve(
      input: Record<string, any>,
      wasmFile: string,
      zkeyFile: string,
      logger?: any
    ): Promise<{
      proof: {
        pi_a: string[];
        pi_b: string[][];
        pi_c: string[];
        protocol: string;
        curve: string;
      };
      publicSignals: string[];
    }>;

    function verify(
      vKey: any,
      publicSignals: string[],
      proof: {
        pi_a: string[];
        pi_b: string[][];
        pi_c: string[];
        protocol?: string;
        curve?: string;
      }
    ): Promise<boolean>;
  }

  export namespace powersOfTau {
    function newAccumulator(
      curve: any,
      power: number,
      fileName: string,
      logger?: any
    ): Promise<void>;

    function contribute(
      oldPtauFile: string,
      newPtauFile: string,
      name: string,
      entropy: string,
      logger?: any
    ): Promise<void>;

    function beacon(
      oldPtauFile: string,
      newPtauFile: string,
      name: string,
      beaconIterations: number,
      logger?: any
    ): Promise<void>;

    function preparePhase2(
      oldPtauFile: string,
      newPtauFile: string,
      logger?: any
    ): Promise<void>;
  }

  export namespace zKey {
    function newZKey(
      r1csFile: string,
      ptauFile: string,
      zkeyFile: string,
      logger?: any
    ): Promise<void>;

    function contribute(
      oldZkeyFile: string,
      newZkeyFile: string,
      name: string,
      entropy: string,
      logger?: any
    ): Promise<void>;

    function beacon(
      oldZkeyFile: string,
      newZkeyFile: string,
      name: string,
      beaconIterations: number,
      logger?: any
    ): Promise<void>;

    function exportVerificationKey(
      zkeyFile: string,
      logger?: any
    ): Promise<any>;

    function verifyFromR1cs(
      r1csFile: string,
      ptauFile: string,
      zkeyFile: string,
      logger?: any
    ): Promise<boolean>;
  }

  export namespace r1cs {
    function info(
      r1csFile: string,
      logger?: any
    ): Promise<{
      nConstraints: number;
      nPrvInputs: number;
      nPubInputs: number;
      nLabels: number;
      nOutputs: number;
    }>;
  }

  export const curves: {
    bn128: any;
    bls12381: any;
  };
}
