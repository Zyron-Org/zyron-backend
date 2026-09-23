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
        findings: {
          include: {
            comments: {
              include: { sender: true },
              orderBy: { createdAt: 'asc' },
            },
          },
          orderBy: { severity: 'asc' },
        },
        payment: true,
        rounds: { orderBy: { roundNumber: 'asc' } },
      },
      orderBy: { createdAt: 'desc' },
    });

    return audits.map((a) => {
      // Clients only see findings once auditor has approved and sent them for fixes (CORRECTIONS_REQUESTED or COMPLETED)
      if (
        role === UserRole.CLIENT &&
        a.stage !== AuditStage.CORRECTIONS_REQUESTED &&
        a.stage !== AuditStage.COMPLETED
      ) {
        a.findings = [];
      }
      return this.sanitizer.sanitizeAuditResult(a);
    });
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

      // Clients only see findings once auditor has approved and sent them for fixes (CORRECTIONS_REQUESTED or COMPLETED)
      if (
        audit.stage !== AuditStage.CORRECTIONS_REQUESTED &&
        audit.stage !== AuditStage.COMPLETED
      ) {
        audit.findings = [];
      }
    }

    return this.sanitizer.sanitizeAuditResult(audit);
  }

  async getOverviewStats() {
    const [totalAudits, inProgressAudits, completedAudits, findings, slocAgg, recentAudits] = await Promise.all([
      this.prisma.auditRequest.count(),
      this.prisma.auditRequest.count({
        where: {
          stage: {
            in: [
              AuditStage.PENDING,
              AuditStage.SCANNING,
              AuditStage.IN_REVIEW,
              AuditStage.CORRECTIONS_REQUESTED,
            ],
          },
        },
      }),
      this.prisma.auditRequest.count({
        where: { stage: AuditStage.COMPLETED },
      }),
      this.prisma.finding.findMany({
        select: { severity: true, status: true },
      }),
      this.prisma.auditRequest.aggregate({
        _sum: { sloc: true },
      }),
      this.prisma.auditRequest.findMany({
        take: 6,
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          protocolName: true,
          contractFileName: true,
          stage: true,
          sloc: true,
          network: true,
          createdAt: true,
          findings: {
            select: { id: true, severity: true, status: true },
          },
        },
      }),
    ]);

    const totalFindings = findings.length;
    const openFindings = findings.filter(
      (f) => f.status === 'OPEN' || f.status === 'FIX_SUBMITTED',
    );
    const openRisks = openFindings.length;
    const criticalRisks = openFindings.filter((f) => f.severity === 'CRITICAL').length;
    const highRisks = openFindings.filter((f) => f.severity === 'HIGH').length;
    const mediumRisks = openFindings.filter((f) => f.severity === 'MEDIUM').length;
    const lowRisks = openFindings.filter((f) => f.severity === 'LOW').length;
    const resolvedFindings = findings.filter((f) => f.status === 'RESOLVED').length;

    return {
      totalAudits,
      inProgressAudits,
      completedAudits,
      totalFindings,
      openRisks,
      criticalRisks,
      highRisks,
      mediumRisks,
      lowRisks,
      resolvedFindings,
      totalSloc: slocAgg._sum.sloc || 0,
      recentAudits,
    };
  }
}
