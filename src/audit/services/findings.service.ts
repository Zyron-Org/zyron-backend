import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { CreateFindingDto, UpdateFindingDto } from '../dto/audit.dto';
import { AuditStage, FindingStatus, UserRole } from '../../common/enum';

@Injectable()
export class FindingsService {
  constructor(private prisma: PrismaService) {}

  async createFinding(auditId: string, dto: CreateFindingDto) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { findings: true },
    });

    if (!audit) {
      throw new NotFoundException(`Audit ${auditId} not found`);
    }

    if (audit.stage === AuditStage.COMPLETED) {
      throw new BadRequestException('Cannot add findings: Target audit is completed and sealed.');
    }

    const findingCount = audit.findings.length + 1;
    const displayId = `${auditId}-${findingCount.toString().padStart(3, '0')}`;

    return this.prisma.finding.create({
      data: {
        displayId,
        title: dto.title,
        severity: dto.severity,
        cvss: dto.cvss || 'CVSS 8.5',
        status: FindingStatus.OPEN,
        taxonomy: dto.taxonomy || 'SWC-107 · CWE-841',
        location: dto.location || `${audit.contractFileName}:142`,
        impact: dto.impact || 'POTENTIAL FUNDS DRAIN',
        description: dto.description,
        vulnerableCode: dto.vulnerableCode,
        vulnerableLines: dto.vulnerableLines,
        remediatedCode: dto.remediatedCode,
        remediationNote: dto.remediationNote,
        auditId,
      },
      include: {
        comments: true,
      },
    });
  }

  async updateFinding(findingId: string, dto: UpdateFindingDto, userRole: UserRole) {
    const finding = await this.prisma.finding.findUnique({
      where: { id: findingId },
      include: { audit: true },
    });
    if (!finding) {
      throw new NotFoundException(`Finding ${findingId} not found`);
    }

    if (finding.audit?.stage === AuditStage.COMPLETED) {
      throw new BadRequestException('Cannot modify finding: Target audit is completed and sealed.');
    }

    const data: any = {};

    if (dto.severity && userRole === UserRole.AUDITOR) {
      data.severity = dto.severity;
    }

    if (dto.status) {
      data.status = dto.status;
    }

    if (dto.title !== undefined) data.title = dto.title;
    if (dto.location !== undefined) data.location = dto.location;
    if (dto.description !== undefined) data.description = dto.description;
    if (dto.remediatedCode !== undefined) data.remediatedCode = dto.remediatedCode;
    if (dto.remediationNote !== undefined) data.remediationNote = dto.remediationNote;
    if (dto.falsePositive !== undefined) data.falsePositive = dto.falsePositive;
    if (dto.fpJustification !== undefined) data.fpJustification = dto.fpJustification;
    if (dto.isMitigated !== undefined) data.isMitigated = dto.isMitigated;
    if (dto.mitigationJustification !== undefined) data.mitigationJustification = dto.mitigationJustification;

    return this.prisma.finding.update({
      where: { id: findingId },
      data,
      include: { comments: true },
    });
  }

  async findFindingsByAudit(auditId: string, userRole?: UserRole) {
    if (userRole === UserRole.CLIENT) {
      const audit = await this.prisma.auditRequest.findUnique({
        where: { id: auditId },
        select: { stage: true },
      });
      // Clients only see findings once auditor approves and flags for corrections / fixes
      if (
        audit &&
        audit.stage !== AuditStage.CORRECTIONS_REQUESTED &&
        audit.stage !== AuditStage.COMPLETED
      ) {
        return [];
      }
    }

    return this.prisma.finding.findMany({
      where: { auditId },
      include: {
        comments: {
          include: { sender: true },
          orderBy: { createdAt: 'asc' },
        },
      },
      orderBy: { severity: 'asc' },
    });
  }
}
