import { Injectable, Logger, Optional, ServiceUnavailableException } from '@nestjs/common';
import { PrismaService } from '../database/database.module';
import { AiProviderFactory, AiScanResult } from './ai-providers';
import { FindingPersisterService } from './services/finding-persister.service';
import { GithubService } from '../integrations/github.service';

@Injectable()
export class AiAuditService {
  private readonly logger = new Logger(AiAuditService.name);

  constructor(
    private providerFactory: AiProviderFactory,
    private prisma: PrismaService,
    @Optional() private githubService?: GithubService,
    @Optional() private findingPersister?: FindingPersisterService,
  ) {}

  /**
   * Run deep cloud LLM smart contract security audit.
   * Discards local mock heuristics: if no cloud provider is reachable, throws and pauses the audit.
   */
  async analyzeContractWithAi(
    contractFileName: string,
    code: string,
    requestedModelOrProvider?: string,
    staticFindings?: any[],
    protocolContext?: { protocolName?: string; businessGoals?: string },
    auditId?: string,
    additionalFiles?: Map<string, string> | Record<string, string>,
  ): Promise<AiScanResult> {
    try {
      let filesInScope = additionalFiles;

      // If additionalFiles was not explicitly provided but an auditId is attached,
      // dynamically fetch all contracts in the repository tree from GitHub so the LLM has multi-file scope.
      if (!filesInScope && auditId && this.githubService) {
        try {
          const audit = await this.prisma.auditRequest.findUnique({
            where: { id: auditId },
          });
          if (audit?.githubRepoUrl) {
            const { owner, repo } = this.githubService.parseRepoUrl(audit.githubRepoUrl);
            const branch = audit.gitCommit || audit.githubBranch || 'main';
            this.logger.log(`[AiAuditService] Ingesting multi-file repository contracts for AI scope from ${owner}/${repo} (${branch})...`);
            const tree = await this.githubService.fetchRepoTree(owner, repo, branch);
            if (tree && tree.contracts?.length > 0) {
              const fileMap = new Map<string, string>();
              await Promise.all(
                tree.contracts.map(async (filePath) => {
                  try {
                    const content = await this.githubService!.fetchFileContent(owner, repo, filePath, branch);
                    if (content) {
                      fileMap.set(filePath, content);
                    }
                  } catch (fetchErr: any) {
                    this.logger.warn(`[AiAuditService] Failed to fetch repo file ${filePath}: ${fetchErr.message}`);
                  }
                }),
              );
              if (fileMap.size > 0) {
                filesInScope = fileMap;
                this.logger.log(`[AiAuditService] Ingested ${fileMap.size} contracts into multi-file AI review scope.`);
              }
            }
          }
        } catch (err: any) {
          this.logger.warn(`[AiAuditService] Failed to ingest repo files for multi-file scope: ${err.message}`);
        }
      }

      const provider = this.providerFactory.getProvider(requestedModelOrProvider);
      const result = await provider.analyzeContract(
        contractFileName,
        code,
        staticFindings,
        protocolContext,
        requestedModelOrProvider,
        filesInScope,
      );

      // Persist AI triage decisions (FP flags and novel findings) if auditId is present
      if (auditId && this.findingPersister) {
        await this.findingPersister.applyAiTriage(auditId, result);
      }

      return result;
    } catch (err: any) {
      this.logger.error(`AI Audit failed: ${err.message}`);

      // If an auditId is attached, pause the audit in DB and record failure reason for admin
      if (auditId) {
        await this.prisma.auditRequest.update({
          where: { id: auditId },
          data: {
            stage: 'FAILED',
            failureReason: `AI Review Paused: ${err.message}. Administrator action required to restore cloud API connection.`,
          },
        }).catch((e) => this.logger.warn(`Failed to update audit state on AI failure: ${e.message}`));
      }

      throw new ServiceUnavailableException(
        `Cloud AI review failed. Audit paused. ${err.message}`,
      );
    }
  }

  /**
   * Triage static AST findings with verified cloud LLMs.
   */
  async triageStaticFindingsWithAi(
    contractFileName: string,
    code: string,
    staticFindings: any[],
    protocolContext?: { protocolName?: string; businessGoals?: string },
    requestedModelOrProvider?: string,
    auditId?: string,
    additionalFiles?: Map<string, string> | Record<string, string>,
  ): Promise<AiScanResult> {
    return this.analyzeContractWithAi(
      contractFileName,
      code,
      requestedModelOrProvider,
      staticFindings,
      protocolContext,
      auditId,
      additionalFiles,
    );
  }

  /**
   * Admin resumes a previously paused/failed AI audit job.
   */
  async resumeAuditAi(auditId: string, customProvider?: string) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { findings: true },
    });

    if (!audit) throw new Error(`Audit engagement ${auditId} not found.`);

    const sourceCode = audit.sourceCode || audit.contractFileName;
    if (!sourceCode) throw new Error(`No source code available for audit ${auditId}`);

    // Verify provider is available before updating DB
    const provider = this.providerFactory.getProvider(customProvider);

    // Reset failure reason and resume to IN_REVIEW
    await this.prisma.auditRequest.update({
      where: { id: auditId },
      data: {
        stage: 'IN_REVIEW',
        failureReason: null,
      },
    });

    // Execute cloud triage
    return this.analyzeContractWithAi(
      audit.contractFileName,
      sourceCode,
      provider.id,
      audit.findings,
      { protocolName: audit.protocolName, businessGoals: audit.businessGoals || undefined },
      auditId,
    );
  }

  getSupportedProviders() {
    return this.providerFactory.getSupportedProviders();
  }
}
