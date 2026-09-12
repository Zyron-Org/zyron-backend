import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import * as crypto from 'crypto';
import { PrismaService } from '../../database/database.module';
import { GithubWebhookHandlerService } from './github-webhook-handler.service';
import { LegacyScanRunnerService } from './legacy-scan-runner.service';
import { ASTEngineRunnerService } from './ast-engine-runner.service';
import { FindingPersisterService } from './finding-persister.service';
import { AuditStage } from '../../common/enum';

@Injectable()
export class ScanOrchestratorService {
  private readonly logger = new Logger(ScanOrchestratorService.name);

  constructor(
    private prisma: PrismaService,
    private webhookHandler: GithubWebhookHandlerService,
    private legacyRunner: LegacyScanRunnerService,
    private astRunner: ASTEngineRunnerService,
    private findingPersister: FindingPersisterService,
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

    // Determine source code: use customCode, or audit contract code if present
    const sourceCode = customCode || audit.contractFileName;
    if (!sourceCode) {
      throw new Error(`No source code available for audit ${auditId}`);
    }

    // Compute source SHA-256 hash for attestation verification
    const sourceHash = crypto.createHash('sha256').update(sourceCode).digest('hex');

    await this.prisma.auditRequest.update({
      where: { id: auditId },
      data: {
        stage: AuditStage.SCANNING,
        stageNumber: 2,
        attestationStatus: 'AUTOMATED_ONLY',
        sourceHash: `0x${sourceHash}`,
      },
    });

    const scanJob = await this.prisma.scanJob.create({
      data: {
        auditId,
        tool: 'zyron-ast-engine-v3.0.0',
        status: 'running',
        passNumber: 1,
        totalPasses: 14,
        startedAt: new Date(),
        logOutput: `[INFO] Initializing Zyron AST Production Engine (v3.0.0) for ${audit.contractFileName}...\n[INFO] Source SHA-256 Hash: 0x${sourceHash}\n`,
      },
    });

    // Track ScanRun in DB
    const scanRun = await this.prisma.scanRun.create({
      data: {
        auditId,
        engineVersion: 'v3.0.0-ast',
        ruleSetVersion: 'v2026.09',
        sourceHash: `0x${sourceHash}`,
        totalPasses: 14,
        status: 'running',
      },
    });

    const existingCount = audit.findings.length;

    // Phase 1: Legacy regex scanners (for backward compatibility)
    const legacyFindings = await this.legacyRunner.run(audit.contractFileName, sourceCode);
    const legacyCount = await this.findingPersister.persistLegacyFindings(auditId, existingCount, legacyFindings);

    // Phase 2: AST engine (14-pass deep AST/CFG/Taint analysis)
    const astResult = await this.astRunner.run(auditId, audit.contractFileName, sourceCode);
    const astPersistedCount = await this.findingPersister.persistASTFindings(
      auditId,
      existingCount + legacyCount,
      astResult.findings,
    );

    const totalFindings = legacyCount + astPersistedCount;

    // Update ScanRun and ScanJob completion
    await this.prisma.scanRun.update({
      where: { id: scanRun.id },
      data: {
        status: 'completed',
        passesCompleted: 14,
        findingsCount: totalFindings,
        durationMs: astResult.totalDurationMs,
        diagnostics: JSON.stringify(astResult.diagnostics),
        completedAt: new Date(),
      },
    });

    const updatedJob = await this.prisma.scanJob.update({
      where: { id: scanJob.id },
      data: {
        status: 'completed',
        passNumber: 14,
        completedAt: new Date(),
        results: JSON.stringify({
          legacyCount,
          astCount: astPersistedCount,
          diagnosticsCount: astResult.diagnostics.length,
          durationMs: astResult.totalDurationMs,
        }),
        logOutput: `${scanJob.logOutput}[SUCCESS] Scan completed in ${astResult.totalDurationMs}ms. Found ${totalFindings} issues across 14 AST passes.\n`,
      },
    });

    await this.prisma.auditRequest.update({
      where: { id: auditId },
      data: { stage: AuditStage.IN_REVIEW, stageNumber: 3 },
    });

    return { scanJob: updatedJob, scanRunId: scanRun.id, findingsCount: totalFindings };
  }
}
