import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { AdvanceStageDto } from '../dto/audit.dto';
import { AuditStage, FindingSeverity, FindingStatus } from '../../common/enum';
import { BlockchainService } from '../../blockchain/blockchain.service';
import { cryptoHash } from '../../common/utils/crypto.util';
import { AuditSanitizerService } from './audit-sanitizer.service';

@Injectable()
export class AdvanceStageService {
  constructor(
    private prisma: PrismaService,
    private blockchainService: BlockchainService,
    private sanitizer: AuditSanitizerService,
  ) {}

  async advanceStage(auditId: string, dto: AdvanceStageDto) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { findings: true, payment: true },
    });

    if (!audit) {
      throw new NotFoundException(`Audit ${auditId} not found`);
    }

    if (dto.stage === AuditStage.COMPLETED) {
      const openCriticalOrHigh = audit.findings.some(
        (f) => (f.severity === FindingSeverity.CRITICAL || f.severity === FindingSeverity.HIGH) && f.status !== FindingStatus.RESOLVED
      );

      if (openCriticalOrHigh) {
        throw new BadRequestException(
          'Cannot complete audit: Open Critical or High severity findings must be resolved first'
        );
      }
    }

    let stageNumber = 1;
    if (dto.stage === AuditStage.SCANNING) stageNumber = 2;
    if (dto.stage === AuditStage.IN_REVIEW) stageNumber = 3;
    if (dto.stage === AuditStage.COMPLETED) stageNumber = 4;

    const data: any = {
      stage: dto.stage,
      stageNumber,
    };

    if (dto.stage === AuditStage.COMPLETED) {
      data.completedAt = new Date();

      let bytecodeHash: string | null = null;
      if (audit.contractAddress && audit.payment?.chainId) {
        bytecodeHash = await this.blockchainService.getContractBytecodeHash(
          audit.payment.chainId,
          audit.contractAddress
        );
      }

      if (!bytecodeHash) {
        const seed = `${audit.protocolName}:${audit.contractFileName}:${audit.gitCommit}:${audit.id}`;
        bytecodeHash = cryptoHash(seed);
      }

      data.bytecodeHash = bytecodeHash.startsWith('0x') ? bytecodeHash : `0x${bytecodeHash}`;
      data.reportPdfUrl = `/reports/${auditId}-${audit.contractFileName}.pdf`;
      data.pdfSize = '2.4 MB';
    }

    const updated = await this.prisma.auditRequest.update({
      where: { id: auditId },
      data,
      include: { findings: true, leadAuditor: true },
    });

    return this.sanitizer.sanitizeAuditResult(updated);
  }
}
