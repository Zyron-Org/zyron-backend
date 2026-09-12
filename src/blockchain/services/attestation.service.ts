import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { createHash } from 'crypto';
import { keccak256, toUtf8Bytes } from 'ethers';

@Injectable()
export class AttestationService {
  private readonly logger = new Logger(AttestationService.name);

  constructor(private prisma: PrismaService) {}

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
   * Only callable when attestationStatus === 'AUTOMATED_ONLY'.
   */
  async buildAttestationPayload(auditId: string) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { findings: true, leadAuditor: true },
    });

    if (!audit) throw new BadRequestException(`Audit ${auditId} not found`);
    if (audit.attestationStatus !== 'AUTOMATED_ONLY') {
      throw new BadRequestException(`Audit ${auditId} is already attested or revoked`);
    }

    const merkleRoot = this.computeFindingsMerkleRoot(
      audit.findings.map((f) => ({ displayId: f.displayId, severity: f.severity })),
    );

    const payload = {
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
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
      domain: { name: 'ZyronAttestation', version: '3.0.0', chainId: audit.onChainChainId || 1 },
      message: {
        auditId: this.toBytes32(auditId),
        merkleRoot,
        bytecodeHash: audit.bytecodeHash || '0x' + '0'.repeat(64),
        sourceHash: '0x' + '0'.repeat(64),
        leadAuditor: audit.leadAuditor?.walletAddress || '0x' + '0'.repeat(40),
        sloc: audit.sloc,
        status: 2, // MANUALLY_ATTESTED enum value
        timestamp: Math.floor(Date.now() / 1000),
      },
    };

    return { payload, merkleRoot };
  }

  private toBytes32(value: string): string {
    // Use keccak256 — consistent with what ZyronAttestation.sol uses in publishAttestation
    return keccak256(toUtf8Bytes(value));
  }
}
