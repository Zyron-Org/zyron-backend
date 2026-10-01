import { Injectable, Inject, forwardRef, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { CreateAuditDto } from '../dto/audit.dto';
import { AuditStage } from '../../common/enum';
import { AuditSanitizerService } from './audit-sanitizer.service';
import { AutoAssignService } from './auto-assign.service';
import { ScanOrchestratorService } from '../../scanner/services/scan-orchestrator.service';
import { GithubService } from '../../integrations/github.service';
import {
  isBlockchainContractFile,
  containsBlockchainMarkers,
} from '../../integrations/services/github-parser.service';

@Injectable()
export class CreateAuditService {
  constructor(
    private prisma: PrismaService,
    private sanitizer: AuditSanitizerService,
    private autoAssignService: AutoAssignService,
    @Inject(forwardRef(() => ScanOrchestratorService))
    private scanOrchestrator: ScanOrchestratorService,
    @Inject(forwardRef(() => GithubService))
    private githubService: GithubService,
  ) {}

  async createAudit(userId: string, organizationId: string | undefined, dto: CreateAuditDto) {
    // 1. Contract filename and source code validation
    const hasValidExt = isBlockchainContractFile(dto.contractFileName);
    const hasContractCode = containsBlockchainMarkers(dto.sourceCode);

    if (!hasValidExt && !hasContractCode) {
      throw new BadRequestException(
        `File '${dto.contractFileName}' is not a recognized blockchain smart contract file. Zyron only audits smart contracts (.sol, .vy, .rs, .cairo, .move, .yul, .tact, .func, .circom).`,
      );
    }

    // 2. If a GitHub repo URL is specified, inspect it to verify blockchain files exist
    if (dto.githubRepoUrl) {
      try {
        const repoCheck = await this.githubService.getRepositorySolidityContracts(
          dto.githubRepoUrl,
          dto.githubBranch || 'main',
        );
        if (repoCheck && repoCheck.isInspected && repoCheck.contracts.length === 0) {
          throw new BadRequestException(
            `The connected repository (${dto.githubRepoUrl}) does not contain any supported smart contract files (.sol, .vy, .rs, .cairo, .move, .yul, .tact). Zyron cannot audit non-blockchain repositories.`,
          );
        }
      } catch (err: any) {
        if (err instanceof BadRequestException) {
          throw err;
        }
        // If repo inspection failed due to network / rate limit / private repo, we allow through if contract file/code passed check 1
      }
    }

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
