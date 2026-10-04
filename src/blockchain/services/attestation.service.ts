import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { ChainConfigService } from './chain-config.service';
import { createHash } from 'crypto';
import { keccak256, toUtf8Bytes } from 'ethers';

@Injectable()
export class AttestationService {
  private readonly logger = new Logger(AttestationService.name);

  constructor(
    private prisma: PrismaService,
    private chainConfig: ChainConfigService,
  ) {}

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
   * Build the EIP-712 typed data payload for auditor signing.
   */
  async buildAttestationPayload(auditId: string, signerAddress?: string) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { findings: true, leadAuditor: true },
    });

    if (!audit) throw new BadRequestException(`Audit ${auditId} not found`);
    if (audit.attestationStatus === 'REVOKED') {
      throw new BadRequestException(`Audit ${auditId} has been revoked and cannot be signed.`);
    }

    const targetChainId = audit.onChainChainId || Number(process.env.DEFAULT_ATTESTATION_CHAIN_ID || 421614);
    const config = this.chainConfig.getChainConfig(targetChainId);
    const verifyingContract = config?.attestationAddress || '0x3331185fAEB2AD65ccDEB7C15025393Ca8F6834D';

    const nonFpFindings = audit.findings.filter((f) => !f.falsePositive);
    const merkleRoot = this.computeFindingsMerkleRoot(
      nonFpFindings.map((f) => ({ displayId: f.displayId, severity: f.severity })),
    );

    const bytecodeHash = audit.bytecodeHash || `0x${createHash('sha256').update(`${audit.protocolName}:${audit.contractFileName}:${audit.gitCommit || ''}:${audit.id}`).digest('hex')}`;
    const sourceHash = audit.sourceHash || `0x${'0'.repeat(64)}`;
    const timestamp = Math.floor(Date.now() / 1000);
    const leadAuditor = signerAddress || audit.leadAuditor?.walletAddress || '0x0000000000000000000000000000000000000000';

    const payload = {
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],
        AttestationPayload: [
          { name: 'auditId', type: 'bytes32' },
          { name: 'merkleRoot', type: 'bytes32' },
          { name: 'bytecodeHash', type: 'bytes32' },
          { name: 'sourceHash', type: 'bytes32' },
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
        bytecodeHash,
        sourceHash,
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

  private toBytes32(value: string): string {
    // Use keccak256 — consistent with what ZyronAttestation.sol uses in publishAttestation
    return keccak256(toUtf8Bytes(value));
  }
}
