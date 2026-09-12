import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';

@Injectable()
export class AttestationConfirmerService {
  private readonly logger = new Logger(AttestationConfirmerService.name);

  constructor(private prisma: PrismaService) {}

  /**
   * Called after the frontend submits the auditor's EIP-712 signature.
   * Transitions attestationStatus from AUTOMATED_ONLY → MANUALLY_ATTESTED.
   */
  async confirmAttestation(auditId: string, signature: string, merkleRoot: string, txHash?: string) {
    this.logger.log(`Confirming attestation for ${auditId}`);

    const audit = await this.prisma.auditRequest.findUnique({ where: { id: auditId } });
    if (!audit) throw new Error(`Audit ${auditId} not found`);

    if (audit.attestationStatus !== 'AUTOMATED_ONLY') {
      throw new Error(`Audit ${auditId} attestation status is '${audit.attestationStatus}', expected AUTOMATED_ONLY`);
    }

    return this.prisma.auditRequest.update({
      where: { id: auditId },
      data: {
        attestationStatus: 'MANUALLY_ATTESTED',
        attestationSig: signature,
        merkleRoot,
        onChainTxHash: txHash || null,
      },
    });
  }

  /**
   * Revoke a previously issued attestation (e.g. if post-audit re-scan discovers new issues).
   */
  async revokeAttestation(auditId: string, reason: string) {
    this.logger.warn(`Revoking attestation for ${auditId}: ${reason}`);

    return this.prisma.auditRequest.update({
      where: { id: auditId },
      data: {
        attestationStatus: 'REVOKED',
        failureReason: `Attestation revoked: ${reason}`,
      },
    });
  }
}
