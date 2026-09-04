import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { CreateAuditDto } from '../dto/audit.dto';
import { AuditStage } from '../../common/enum';
import { AuditSanitizerService } from './audit-sanitizer.service';

@Injectable()
export class CreateAuditService {
  constructor(
    private prisma: PrismaService,
    private sanitizer: AuditSanitizerService,
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
        githubRepoUrl: dto.githubRepoUrl,
        githubBranch: dto.githubBranch,
        submittedById: userId,
        organizationId,
        estimatedCompletion,
      },
      include: {
        submittedBy: true,
        organization: true,
        findings: true,
      },
    });

    return this.sanitizer.sanitizeAuditResult(audit);
  }
}
