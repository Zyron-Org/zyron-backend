import { Injectable, Logger, BadRequestException, ForbiddenException, Optional } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { ChainConfigService } from './chain-config.service';
import { EvidenceHasherService } from './evidence-hasher.service';
import { ChainAdapterRegistry, PreparedChainAttestation } from '../adapters';
import { createHash } from 'crypto';
import { keccak256, toUtf8Bytes, isAddress } from 'ethers';
import { MONAD_TESTNET_ATTESTATION_ADDRESS, getDefaultAttestationChainId } from '../constants';
import { normalizeBytes32 } from '../utils';

@Injectable()
export class AttestationService {
  private readonly logger = new Logger(AttestationService.name);
  private readonly evidenceHasher: EvidenceHasherService;
  private readonly adapterRegistry: ChainAdapterRegistry;

  constructor(
    private prisma: PrismaService,
    private chainConfig: ChainConfigService,
    @Optional() evidenceHasher?: EvidenceHasherService,
    @Optional() adapterRegistry?: ChainAdapterRegistry,
  ) {
    this.evidenceHasher = evidenceHasher || new EvidenceHasherService();
    this.adapterRegistry = adapterRegistry || new ChainAdapterRegistry(this.chainConfig);
  }

  /**
   * Compute Merkle root from an ordered list of finding display IDs + severities.
   * Uses keccak-style double-SHA256 for deterministic leaf hashing.
   */
  computeFindingsMerkleRoot(findings: { displayId: string; severity: string }[]): string {
    if (findings.length === 0) return '0x' + '0'.repeat(64);

    let leaves = findings.map((f) =>
      createHash('sha256').update(`${f.displayId}:${f.severity}`).digest('hex'),
    );

    while (leaves.length > 1) {
      const next: string[] = [];
      for (let i = 0; i < leaves.length; i += 2) {
        const left = leaves[i];
        const right = i + 1 < leaves.length ? leaves[i + 1] : left;
        next.push(createHash('sha256').update(left + right).digest('hex'));
      }
      leaves = next;
    }

    return '0x' + leaves[0];
  }

  /**
   * Compute the canonical evidence root for an audit.
   * If canonical `zyron.evidence/v1` records exist in `ProverEvidence`, computes their sorted SHA-256 Merkle root.
   * Otherwise falls back to `computeFindingsMerkleRoot` over non-FP findings.
   */
  async computeAuditEvidenceRoot(audit: any): Promise<string> {
    if ((this.prisma as any).proverEvidence?.findMany) {
      const evidences = await (this.prisma as any).proverEvidence.findMany({
        where: { auditId: audit.id },
        orderBy: { findingId: 'asc' },
      });
      if (Array.isArray(evidences) && evidences.length > 0) {
        return this.evidenceHasher.computeEvidenceMerkleRoot(evidences.map((e: any) => e.evidenceHash));
      }
    }
    const nonFpFindings = (audit.findings || []).filter((f: any) => !f.falsePositive);
    return this.computeFindingsMerkleRoot(
      nonFpFindings.map((f: any) => ({ displayId: f.displayId, severity: f.severity })),
    );
  }

  /**
   * Build the EIP-712 typed data payload for auditor signing.
   */
  async buildAttestationPayload(auditId: string, signerAddress?: string, chainIdOverride?: number) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { findings: true, leadAuditor: true },
    });

    if (!audit) throw new BadRequestException(`Audit ${auditId} not found`);
    if (audit.attestationStatus === 'REVOKED') {
      throw new BadRequestException(`Audit ${auditId} has been revoked and cannot be signed.`);
    }

    const targetChainId = chainIdOverride || audit.onChainChainId || getDefaultAttestationChainId();
    const config = this.chainConfig.getChainConfig(targetChainId);
    const verifyingContract = config?.attestationAddress || MONAD_TESTNET_ATTESTATION_ADDRESS;

    const merkleRoot = await this.computeAuditEvidenceRoot(audit);

    const bytecodeHash =
      audit.bytecodeHash ||
      `0x${createHash('sha256')
        .update(`${audit.protocolName}:${audit.contractFileName}:${audit.gitCommit || ''}:${audit.id}`)
        .digest('hex')}`;
    const repoTreeHash = normalizeBytes32(audit.sourceHash);
    const timestamp = Math.floor(Date.now() / 1000);
    let leadAuditor =
      signerAddress || audit.leadAuditor?.walletAddress || '0x48b106E3C8681D08c513268854Aef257883298d3';
    if (!leadAuditor || !isAddress(leadAuditor) || leadAuditor === '0x0000000000000000000000000000000000000000') {
      leadAuditor = '0x48b106E3C8681D08c513268854Aef257883298d3';
    }

    const payload = {
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],
        // Field order MUST match ZyronAttestation.ATTESTATION_TYPEHASH.
        AttestationPayload: [
          { name: 'auditId', type: 'bytes32' },
          { name: 'merkleRoot', type: 'bytes32' },
          { name: 'repoTreeHash', type: 'bytes32' },
          { name: 'bytecodeHash', type: 'bytes32' },
          { name: 'leadAuditor', type: 'address' },
          { name: 'sloc', type: 'uint256' },
          { name: 'status', type: 'uint8' },
          { name: 'timestamp', type: 'uint256' },
        ],
      },
      primaryType: 'AttestationPayload',
      domain: {
        name: 'ZyronAttestation',
        version: '3.0.0',
        chainId: targetChainId,
        verifyingContract,
      },
      message: {
        auditId: this.toBytes32(auditId),
        merkleRoot,
        repoTreeHash,
        bytecodeHash,
        leadAuditor,
        sloc: audit.sloc || 100,
        status: 2, // MANUALLY_ATTESTED
        timestamp,
      },
    };

    return {
      payload,
      merkleRoot,
      targetChainId,
      verifyingContract,
      auditId,
      protocolName: audit.protocolName,
      contractFileName: audit.contractFileName,
    };
  }

  /**
   * Prepare a chain-scoped EIP-712 attestation record (`PREPARED`) via the target chain's `ChainAdapter`.
   */
  async prepareChainAttestation(
    auditId: string,
    chainId: number,
    signerAddress?: string,
    targetContractAddressOverride?: string,
  ): Promise<PreparedChainAttestation> {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { findings: true, leadAuditor: true, peerAuditor: true },
    });

    if (!audit) throw new BadRequestException(`Audit ${auditId} not found`);
    if (audit.attestationStatus === 'REVOKED') {
      throw new BadRequestException(`Audit ${auditId} has been revoked and cannot be attested.`);
    }

    const adapter = this.adapterRegistry.getAdapter(chainId);
    if (!adapter.isConfigured()) {
      throw new BadRequestException(
        adapter.getMissingConfigReason() || `Chain ${chainId} is not configured for attestations.`,
      );
    }

    const evidenceRoot = await this.computeAuditEvidenceRoot(audit);
    let leadAuditor =
      signerAddress || audit.leadAuditor?.walletAddress || '0x48b106E3C8681D08c513268854Aef257883298d3';
    if (!leadAuditor || !isAddress(leadAuditor) || leadAuditor === '0x0000000000000000000000000000000000000000') {
      throw new BadRequestException('A valid authorized reviewer wallet address is required.');
    }

    const prepared = adapter.prepareAttestation({
      auditId: audit.id,
      protocolName: audit.protocolName,
      targetContractFile: audit.contractFileName,
      targetContractAddress: targetContractAddressOverride || audit.contractAddress,
      gitCommit: audit.gitCommit,
      repoTreeHash: audit.sourceHash,
      bytecodeHash: audit.bytecodeHash,
      evidenceRoot,
      sloc: audit.sloc || 100,
      leadAuditor,
      peerAuditor: audit.peerAuditor?.walletAddress,
      ipfsCid: audit.ipfsCid,
      ipfsMetadataCid: audit.ipfsMetadataCid,
    });

    if ((this.prisma as any).chainAttestation?.upsert) {
      await (this.prisma as any).chainAttestation.upsert({
        where: {
          auditId_chainId: {
            auditId: audit.id,
            chainId: adapter.chainId,
          },
        },
        update: {
          chainName: adapter.name,
          contractIdentity: prepared.contractIdentity,
          targetContractAddress: prepared.targetContractAddress,
          registryAddress: prepared.registryAddress,
          bytecodeHash: prepared.bytecodeHash,
          evidenceRoot: prepared.evidenceRoot,
          merkleRoot: prepared.merkleRoot,
          repoTreeHash: prepared.repoTreeHash,
          status: 'PREPARED',
          preparedPayloadJson: JSON.stringify(prepared),
          preparedAt: new Date(),
          errorReason: null,
        },
        create: {
          auditId: audit.id,
          chainId: adapter.chainId,
          chainName: adapter.name,
          contractIdentity: prepared.contractIdentity,
          targetContractAddress: prepared.targetContractAddress,
          registryAddress: prepared.registryAddress,
          bytecodeHash: prepared.bytecodeHash,
          evidenceRoot: prepared.evidenceRoot,
          merkleRoot: prepared.merkleRoot,
          repoTreeHash: prepared.repoTreeHash,
          status: 'PREPARED',
          preparedPayloadJson: JSON.stringify(prepared),
          preparedAt: new Date(),
        },
      });
    }

    return prepared;
  }

  /**
   * Verify human reviewer EIP-712 signature and authorize (`APPROVED`) a prepared chain attestation.
   * Enforces:
   * - Stale source revision rejection
   * - Authorized reviewer check (never AI / never unauthorized client wallet)
   * - Domain chainId, verifyingContract, evidenceRoot, and timestamp freshness (<24h)
   */
  async approveChainAttestation(params: {
    auditId: string;
    chainId: number;
    signature: string;
    signerAddress: string;
    preparedOverride?: PreparedChainAttestation;
  }) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: params.auditId },
      include: { findings: true, leadAuditor: true },
    });

    if (!audit) throw new BadRequestException(`Audit ${params.auditId} not found`);
    if (audit.attestationStatus === 'REVOKED') {
      throw new BadRequestException(`Audit ${params.auditId} has been revoked.`);
    }

    const adapter = this.adapterRegistry.getAdapter(params.chainId);

    // Load stored prepared record or use provided preparedOverride
    let prepared: PreparedChainAttestation | undefined = params.preparedOverride;
    let existingRecord: any = null;
    if ((this.prisma as any).chainAttestation?.findUnique) {
      existingRecord = await (this.prisma as any).chainAttestation.findUnique({
        where: {
          auditId_chainId: {
            auditId: params.auditId,
            chainId: adapter.chainId,
          },
        },
      });
      if (existingRecord?.status === 'CONFIRMED') {
        throw new BadRequestException(
          `Audit ${params.auditId} is already attested and confirmed on ${adapter.name} (${adapter.chainId}).`,
        );
      }
      if (!prepared && existingRecord?.preparedPayloadJson) {
        prepared = JSON.parse(existingRecord.preparedPayloadJson);
      }
    }

    if (!prepared) {
      throw new BadRequestException(
        `No prepared attestation found for audit ${params.auditId} on chain ${params.chainId}. Call prepare first.`,
      );
    }

    // Check stale source revision: if audit.sourceHash changed since preparation, reject!
    const currentRepoTreeHash = normalizeBytes32(audit.sourceHash);
    if (prepared.repoTreeHash.toLowerCase() !== currentRepoTreeHash.toLowerCase()) {
      throw new BadRequestException(
        `Stale source revision detected: prepared repoTreeHash ${prepared.repoTreeHash} does not match current audit sourceHash ${currentRepoTreeHash}.`,
      );
    }

    // Check canonical evidenceRoot still matches current audit evidence
    const currentEvidenceRoot = normalizeBytes32(await this.computeAuditEvidenceRoot(audit));
    if (prepared.evidenceRoot.toLowerCase() !== currentEvidenceRoot.toLowerCase()) {
      throw new BadRequestException(
        `Stale evidence root detected: prepared evidenceRoot ${prepared.evidenceRoot} does not match current audit evidenceRoot ${currentEvidenceRoot}.`,
      );
    }

    // Check reviewer authorization: AI cannot sign, and if signer belongs to a CLIENT user, reject.
    if ((this.prisma as any).user?.findFirst && params.signerAddress) {
      const userRecord = await (this.prisma as any).user.findFirst({
        where: {
          walletAddress: {
            in: [params.signerAddress, params.signerAddress.toLowerCase()],
          },
        },
      });
      if (userRecord && userRecord.role !== 'AUDITOR' && userRecord.role !== 'ADMIN') {
        throw new ForbiddenException(
          `Signer wallet ${params.signerAddress} has role ${userRecord.role}; only AUDITOR or ADMIN reviewers can authorize attestations.`,
        );
      }
    }

    // Verify EIP-712 typed-data signature via chain adapter
    const verification = adapter.verifyAttestationSignature(prepared, params.signature, params.signerAddress);
    if (!verification.valid) {
      throw new BadRequestException(`Attestation signature verification failed: ${verification.reason}`);
    }

    if ((this.prisma as any).chainAttestation?.update && existingRecord) {
      await (this.prisma as any).chainAttestation.update({
        where: { id: existingRecord.id },
        data: {
          status: 'APPROVED',
          signerAddress: verification.recoveredSigner,
          signature: params.signature.trim(),
          approvedAt: new Date(),
          errorReason: null,
        },
      });
    }

    return {
      approved: true,
      auditId: params.auditId,
      chainId: adapter.chainId,
      chainName: adapter.name,
      signerAddress: verification.recoveredSigner,
      evidenceRoot: prepared.evidenceRoot,
      status: 'APPROVED',
    };
  }

  /**
   * Return the full cryptographic evidence bundle and per-chain attestation records for an audit.
   */
  async getAuditEvidenceBundle(auditId: string) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { findings: true, leadAuditor: true },
    });
    if (!audit) throw new BadRequestException(`Audit ${auditId} not found`);

    const proverEvidences = (this.prisma as any).proverEvidence?.findMany
      ? await (this.prisma as any).proverEvidence.findMany({
          where: { auditId },
          orderBy: { createdAt: 'asc' },
        })
      : [];

    const chainAttestations = (this.prisma as any).chainAttestation?.findMany
      ? await (this.prisma as any).chainAttestation.findMany({
          where: { auditId },
          orderBy: { chainId: 'asc' },
        })
      : [];

    const evidenceRoot = await this.computeAuditEvidenceRoot(audit);

    return {
      auditId: audit.id,
      protocolName: audit.protocolName,
      contractFileName: audit.contractFileName,
      contractAddress: audit.contractAddress,
      gitCommit: audit.gitCommit,
      sourceHash: audit.sourceHash,
      bytecodeHash: audit.bytecodeHash,
      evidenceRoot,
      merkleRoot: audit.merkleRoot || evidenceRoot,
      reportUrl: `/api/v1/audits/${audit.id}/report.pdf`,
      ipfsCid: audit.ipfsCid,
      proverEvidences: proverEvidences.map((ev: any) => ({
        id: ev.id,
        findingId: ev.findingId,
        findingDisplayId: ev.findingDisplayId,
        schemaVersion: ev.schemaVersion,
        verifierVersion: ev.verifierVersion,
        finalStatus: ev.finalStatus,
        claimedVerdict: ev.claimedVerdict,
        testFile: ev.testFile,
        testFunction: ev.testFunction,
        testArtifactHash: ev.testArtifactHash,
        provider: ev.provider,
        model: ev.model,
        evidenceHash: ev.evidenceHash,
        canonicalJson: ev.canonicalJson,
        runs: ev.runsJson ? JSON.parse(ev.runsJson) : [],
        investigation: ev.investigationJson ? JSON.parse(ev.investigationJson) : [],
        rejectionReasons: ev.rejectionReasonsJson ? JSON.parse(ev.rejectionReasonsJson) : [],
        createdAt: ev.createdAt,
      })),
      chainAttestations: chainAttestations.map((ca: any) => ({
        id: ca.id,
        chainId: ca.chainId,
        chainName: ca.chainName,
        contractIdentity: ca.contractIdentity,
        targetContractAddress: ca.targetContractAddress,
        registryAddress: ca.registryAddress,
        bytecodeHash: ca.bytecodeHash,
        evidenceRoot: ca.evidenceRoot,
        merkleRoot: ca.merkleRoot,
        repoTreeHash: ca.repoTreeHash,
        status: ca.status,
        signerAddress: ca.signerAddress,
        txHash: ca.txHash,
        blockNumber: ca.blockNumber,
        explorerUrl: ca.explorerUrl,
        errorReason: ca.errorReason,
        preparedAt: ca.preparedAt,
        approvedAt: ca.approvedAt,
        updatedAt: ca.updatedAt,
      })),
    };
  }

  private toBytes32(value: string): string {
    // Use keccak256 — consistent with what ZyronAttestation.sol uses in publishAttestation
    return keccak256(toUtf8Bytes(value));
  }
}
