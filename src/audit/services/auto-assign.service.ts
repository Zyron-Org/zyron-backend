import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { AuditStage, UserRole } from '../../common/enum';

@Injectable()
export class AutoAssignService {
  private readonly logger = new Logger(AutoAssignService.name);

  constructor(private prisma: PrismaService) {}

  /**
   * Selects the best available auditor based on active workload capacity.
   */
  async findAvailableAuditor() {
    // 1. Fetch all active auditors
    const auditors = await this.prisma.user.findMany({
      where: {
        role: UserRole.AUDITOR,
        isAvailable: true,
        onboardingStatus: 'ACTIVE',
      },
    });

    if (auditors.length === 0) {
      this.logger.warn('No active auditors registered in system for auto-assignment.');
      return null;
    }

    // 2. Count active workloads for each auditor
    const auditorWorkloads = await Promise.all(
      auditors.map(async (auditor) => {
        const activeCount = await this.prisma.auditRequest.count({
          where: {
            leadAuditorId: auditor.id,
            stage: {
              in: [AuditStage.IN_REVIEW, AuditStage.CORRECTIONS_REQUESTED],
            },
          },
        });

        return {
          auditor,
          activeCount,
          maxConcurrent: auditor.maxConcurrentAudits || 3,
        };
      }),
    );

    // 3. Filter candidates who have remaining capacity
    const eligibleCandidates = auditorWorkloads.filter(
      (item) => item.activeCount < item.maxConcurrent,
    );

    if (eligibleCandidates.length === 0) {
      this.logger.warn('All active auditors are at maximum ticket capacity.');
      return null;
    }

    // 4. Sort by lowest workload (least active tickets)
    eligibleCandidates.sort((a, b) => a.activeCount - b.activeCount);

    const selected = eligibleCandidates[0].auditor;
    this.logger.log(
      `Auto-assigned ticket to auditor ${selected.name} (${selected.id}) - Current workload: ${eligibleCandidates[0].activeCount}/${eligibleCandidates[0].maxConcurrent}`,
    );

    return selected;
  }

  /**
   * Auto-assigns an unassigned audit ticket to an available auditor.
   */
  async autoAssignAudit(auditId: string) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
    });

    if (!audit) {
      return null;
    }

    // Don't overwrite if already assigned
    if (audit.leadAuditorId) {
      return audit;
    }

    const availableAuditor = await this.findAvailableAuditor();
    if (!availableAuditor) {
      return audit;
    }

    const updated = await this.prisma.auditRequest.update({
      where: { id: auditId },
      data: {
        leadAuditorId: availableAuditor.id,
        stage: audit.stage === AuditStage.PENDING ? AuditStage.IN_REVIEW : audit.stage,
        stageNumber: audit.stage === AuditStage.PENDING ? 3 : audit.stageNumber,
      },
      include: {
        leadAuditor: true,
      },
    });

    return updated;
  }
}
