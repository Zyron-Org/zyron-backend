import { Injectable } from '@nestjs/common';
import {
  ChainConfigService,
  TransactionVerifierService,
  BytecodeVerifierService,
  AttestationService,
  AttestationConfirmerService,
  AttestationSubmitterService,
  ChainConfig,
} from './services';

@Injectable()
export class BlockchainService {
  constructor(
    private chainConfig: ChainConfigService,
    private txVerifier: TransactionVerifierService,
    private bytecodeVerifier: BytecodeVerifierService,
    private attestation: AttestationService,
    private attestationConfirmer: AttestationConfirmerService,
    private attestationSubmitter: AttestationSubmitterService,
  ) {}

  getChainConfig(chainId: number): ChainConfig | undefined {
    return this.chainConfig.getChainConfig(chainId);
  }

  getSupportedChains(): ChainConfig[] {
    return this.chainConfig.getSupportedChains();
  }

  getProvider(chainId: number) {
    return this.chainConfig.getProvider(chainId);
  }

  verifyTransaction(chainId: number, txHash: string) {
    return this.txVerifier.verifyTransaction(chainId, txHash);
  }

  getContractBytecodeHash(chainId: number, contractAddress: string) {
    return this.bytecodeVerifier.getContractBytecodeHash(chainId, contractAddress);
  }

  getExplorerTxUrl(chainId: number, txHash: string): string {
    return this.txVerifier.getExplorerTxUrl(chainId, txHash);
  }

  // ─── Attestation Delegates ────────────────────────────
  buildAttestationPayload(auditId: string) {
    return this.attestation.buildAttestationPayload(auditId);
  }

  computeFindingsMerkleRoot(findings: { displayId: string; severity: string }[]) {
    return this.attestation.computeFindingsMerkleRoot(findings);
  }

  submitAutomatedAttestation(auditId: string, chainId?: number) {
    return this.attestationSubmitter.submitAutomatedAttestation(auditId, chainId);
  }

  submitSignedAttestation(
    auditId: string,
    signature: string,
    signerAddress: string,
    payloadMessage: any,
    targetChainId?: number,
  ) {
    return this.attestationSubmitter.submitSignedAttestation(
      auditId,
      signature,
      signerAddress,
      payloadMessage,
      targetChainId,
    );
  }

  verifyOnChain(auditId: string, targetChainId?: number) {
    return this.attestationSubmitter.verifyOnChain(auditId, targetChainId);
  }

  confirmAttestation(auditId: string, signature: string, merkleRoot: string, txHash?: string) {
    return this.attestationConfirmer.confirmAttestation(auditId, signature, merkleRoot, txHash);
  }

  revokeAttestation(auditId: string, reason: string) {
    return this.attestationConfirmer.revokeAttestation(auditId, reason);
  }
}
