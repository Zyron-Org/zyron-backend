import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { AuditStage } from '../../common/enum';
import { AuditSanitizerService } from './audit-sanitizer.service';

@Injectable()
export class ClaimTicketService {
  constructor(
    private prisma: PrismaService,
    private sanitizer: AuditSanitizerService,
  ) {}

  async claimTicket(auditId: string, auditorId: string) {
    const audit = await this.prisma.auditRequest.findUnique({ where: { id: auditId } });
    if (!audit) {
      throw new NotFoundException(`Audit ${auditId} not found`);
    }

    if (audit.leadAuditorId) {
      throw new ConflictException(`Audit ${auditId} is already claimed by auditor ${audit.leadAuditorId}`);
    }

    const updated = await this.prisma.auditRequest.update({
      where: { id: auditId },
      data: {
        leadAuditorId: auditorId,
        stage: AuditStage.IN_REVIEW,
        stageNumber: 3,
      },
      include: {
        leadAuditor: true,
        findings: true,
      },
    });

    return this.sanitizer.sanitizeAuditResult(updated);
  }
}
