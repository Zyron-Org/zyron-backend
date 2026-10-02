import { Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import { PrismaService } from '../database/database.module';
import { AiProviderFactory, AiScanResult } from './ai-providers';

@Injectable()
export class AiAuditService {
  private readonly logger = new Logger(AiAuditService.name);

  constructor(
    private providerFactory: AiProviderFactory,
    private prisma: PrismaService,
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
  ): Promise<AiScanResult> {
    try {
      const provider = this.providerFactory.getProvider(requestedModelOrProvider);
      return await provider.analyzeContract(
        contractFileName,
        code,
        staticFindings,
        protocolContext,
        requestedModelOrProvider,
      );
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
  ): Promise<AiScanResult> {
    return this.analyzeContractWithAi(
      contractFileName,
      code,
      requestedModelOrProvider,
      staticFindings,
      protocolContext,
      auditId,
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
