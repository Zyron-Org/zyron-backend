import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { AuditStage, UserRole } from '../../common/enum';
import { AuditSanitizerService } from './audit-sanitizer.service';

@Injectable()
export class GetAuditsService {
  constructor(
    private prisma: PrismaService,
    private sanitizer: AuditSanitizerService,
  ) {}

  async findAllAudits(userId: string, role: UserRole, organizationId?: string, stageFilter?: AuditStage) {
    let where: any = {};

    if (role === UserRole.CLIENT) {
      if (organizationId) {
        where.organizationId = organizationId;
      } else {
        where.submittedById = userId;
      }
    }

    if (stageFilter) {
      where.stage = stageFilter;
    }

    const audits = await this.prisma.auditRequest.findMany({
      where,
      include: {
        submittedBy: true,
        leadAuditor: true,
        peerAuditor: true,
        findings: true,
        payment: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    return audits.map((a) => this.sanitizer.sanitizeAuditResult(a));
  }

  async findOneAudit(auditId: string, userId: string, role: UserRole, organizationId?: string) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: {
        submittedBy: true,
        leadAuditor: true,
        peerAuditor: true,
        organization: true,
        findings: {
          include: {
            comments: {
              include: { sender: true },
              orderBy: { createdAt: 'asc' },
            },
          },
          orderBy: { severity: 'asc' },
        },
        rounds: { orderBy: { roundNumber: 'asc' } },
        payment: true,
      },
    });

    if (!audit) {
      throw new NotFoundException(`Audit engagement ${auditId} not found`);
    }

    if (role === UserRole.CLIENT) {
      if (audit.organizationId && audit.organizationId !== organizationId && audit.submittedById !== userId) {
        throw new ForbiddenException('Access denied: You do not have permission to view this audit engagement');
      }
    }

    return this.sanitizer.sanitizeAuditResult(audit);
  }
}
