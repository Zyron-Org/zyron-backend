import { Injectable, Inject, forwardRef } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { CreateAuditDto } from '../dto/audit.dto';
import { AuditStage } from '../../common/enum';
import { AuditSanitizerService } from './audit-sanitizer.service';
import { AutoAssignService } from './auto-assign.service';
import { ScanOrchestratorService } from '../../scanner/services/scan-orchestrator.service';

@Injectable()
export class CreateAuditService {
  constructor(
    private prisma: PrismaService,
    private sanitizer: AuditSanitizerService,
    private autoAssignService: AutoAssignService,
    @Inject(forwardRef(() => ScanOrchestratorService))
    private scanOrchestrator: ScanOrchestratorService,
  ) {}

  async createAudit(userId: string, organizationId: string | undefined, dto: CreateAuditDto) {
    const count = await this.prisma.auditRequest.count();
    const ticketId = `ZYR-${9480 + count + 1}`;
    const estimatedCompletion = new Date(Date.now() + 48 * 60 * 60 * 1000);

    const audit = await this.prisma.auditRequest.create({
      data: {
        id: ticketId,
        protocolName: dto.protocolName,
        contractFileName: dto.contractFileName,
        contractAddress: dto.contractAddress,
        gitCommit: dto.gitCommit || '8f9b2d4c01e9a37',
        compilerVersion: dto.compilerVersion,
        sloc: dto.sloc,
        network: dto.network || 'Ethereum Mainnet',
        stage: AuditStage.PENDING,
        stageNumber: 1,
        invariants: dto.invariants ? JSON.stringify(dto.invariants) : null,
        businessGoals: dto.businessGoals,
        githubRepoUrl: dto.githubRepoUrl,
        githubBranch: dto.githubBranch,
        sourceCode: dto.sourceCode,
        submittedById: userId,
        organizationId,
        estimatedCompletion,
      },
      include: {
        submittedBy: true,
        organization: true,
        findings: true,
        leadAuditor: true,
        rounds: true,
      },
    });

    // Auto-create Round 1 (Initial Intake & AST Scan)
    try {
      await this.prisma.auditRound.create({
        data: {
          roundNumber: 1,
          commitSha: audit.gitCommit || 'latest',
          status: 'active',
          summary: 'Initial intake and automated AST security scan',
          auditId: audit.id,
          startedAt: audit.submittedAt || new Date(),
        },
      });
    } catch (err: any) {
      console.warn(`Round 1 creation for ${audit.id} failed:`, err.message);
    }

    // Auto-assign to available auditor
    try {
      const assigned = await this.autoAssignService.autoAssignAudit(audit.id);
      if (assigned) {
        Object.assign(audit, assigned);
      }
    } catch (err: any) {
      console.warn(`Auto-assign for ${audit.id} failed:`, err.message);
    }

    // Auto-trigger security AST scan asynchronously
    if (this.scanOrchestrator) {
      this.scanOrchestrator.runScan(audit.id, dto.sourceCode).catch((err) => {
        console.warn(`Auto-scan execution for ${audit.id} failed:`, err.message);
      });
    }

    return this.sanitizer.sanitizeAuditResult(audit);
  }
}
