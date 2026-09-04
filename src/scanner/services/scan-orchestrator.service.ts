import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { TokenRuleScannerService } from './token-rule-scanner.service';
import { AiLocalReasonerService } from './ai-local-reasoner.service';
import { GithubWebhookHandlerService } from './github-webhook-handler.service';
import { FindingStatus } from '../../common/enum';

@Injectable()
export class ScanOrchestratorService {
  private readonly logger = new Logger(ScanOrchestratorService.name);

  constructor(
    private prisma: PrismaService,
    private tokenScanner: TokenRuleScannerService,
    private aiAuditService: AiLocalReasonerService,
    private webhookHandler: GithubWebhookHandlerService,
  ) {}

  getScanJobsByAudit(auditId: string) {
    return this.prisma.scanJob.findMany({ where: { auditId }, orderBy: { createdAt: 'desc' } });
  }

  processGithubBotMention(payload: any) {
    return this.webhookHandler.processGithubBotMention(payload);
  }

  async runScan(auditId: string, customCode?: string) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { findings: true },
    });
    if (!audit) throw new NotFoundException(`Audit engagement ${auditId} not found`);

    const scanJob = await this.prisma.scanJob.create({
      data: {
        auditId,
        tool: 'slither-mythril-gemini-ai-engine',
        status: 'running',
        passNumber: 1,
        totalPasses: 3,
        startedAt: new Date(),
        logOutput: `[INFO] Initializing Zyron AI & Static Security engine for ${audit.contractFileName}...\n`,
      },
    });

    const code = customCode || `pragma solidity ^0.8.20;\ncontract ${audit.contractFileName.replace('.sol', '')} { address public owner; }`;
    const tokenResult = this.tokenScanner.analyzeTokenCode(audit.contractFileName, code);
    const aiResult = await this.aiAuditService.analyzeContractWithAi(audit.contractFileName, code);
    const allFindings = [...tokenResult.findings, ...aiResult.findings];

    for (let i = 0; i < allFindings.length; i++) {
      const f = allFindings[i];
      const displayId = `${auditId}-${(audit.findings.length + i + 1).toString().padStart(3, '0')}`;
      await this.prisma.finding.create({
        data: {
          displayId,
          title: f.title,
          severity: f.severity,
          cvss: f.cvss,
          status: FindingStatus.OPEN,
          taxonomy: f.taxonomy,
          location: f.location,
          impact: f.impact,
          description: f.description,
          remediatedCode: f.remediatedCode,
          auditId,
        },
      });
    }

    const updatedJob = await this.prisma.scanJob.update({
      where: { id: scanJob.id },
      data: {
        status: 'completed',
        passNumber: 3,
        completedAt: new Date(),
        results: JSON.stringify({ tokenResult, aiResult }),
        logOutput: `${scanJob.logOutput}[SUCCESS] Scan completed. Found ${allFindings.length} issues.\n`,
      },
    });

    return { scanJob: updatedJob, findingsCount: allFindings.length, tokenResult, aiResult };
  }
}
