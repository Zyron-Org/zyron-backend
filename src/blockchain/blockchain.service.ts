import { Injectable, Optional } from '@nestjs/common';
import {
  ChainConfigService,
  TransactionVerifierService,
  BytecodeVerifierService,
  AttestationService,
  AttestationConfirmerService,
  AttestationSubmitterService,
  ChainConfig,
} from './services';
import { ChainAdapterRegistry, ChainMatrixEntry } from './adapters';

@Injectable()
export class BlockchainService {
  private readonly adapterRegistry: ChainAdapterRegistry;

  constructor(
    private chainConfig: ChainConfigService,
    private txVerifier: TransactionVerifierService,
    private bytecodeVerifier: BytecodeVerifierService,
    private attestation: AttestationService,
    private attestationConfirmer: AttestationConfirmerService,
    private attestationSubmitter: AttestationSubmitterService,
    @Optional() adapterRegistry?: ChainAdapterRegistry,
  ) {
    this.adapterRegistry = adapterRegistry || new ChainAdapterRegistry(this.chainConfig);
  }

  getChainConfig(chainId: number): ChainConfig | undefined {
    return this.chainConfig.getChainConfig(chainId);
  }

  getSupportedChains(): ChainConfig[] {
    return this.chainConfig.getSupportedChains();
  }

  getSupportedChainMatrix(): ChainMatrixEntry[] {
    return this.adapterRegistry.getSupportedChainMatrix();
  }

  getAdapter(chainId: number) {
    return this.adapterRegistry.getAdapter(chainId);
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
  buildAttestationPayload(auditId: string, signerAddress?: string, chainId?: number) {
    return this.attestation.buildAttestationPayload(auditId, signerAddress, chainId);
  }

  prepareChainAttestation(
    auditId: string,
    chainId: number,
    signerAddress?: string,
    targetContractAddressOverride?: string,
  ) {
    return this.attestation.prepareChainAttestation(
      auditId,
      chainId,
      signerAddress,
      targetContractAddressOverride,
    );
  }

  approveChainAttestation(params: {
    auditId: string;
    chainId: number;
    signature: string;
    signerAddress: string;
  }) {
    return this.attestation.approveChainAttestation(params);
  }

  submitApprovedChainAttestation(auditId: string, chainId: number) {
    return this.attestationSubmitter.submitApprovedChainAttestation(auditId, chainId);
  }

  getAuditEvidenceBundle(auditId: string) {
    return this.attestation.getAuditEvidenceBundle(auditId);
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

  setAttestationAddress(chainId: number, address: string) {
    this.chainConfig.setAttestationAddress(chainId, address);
  }
}
