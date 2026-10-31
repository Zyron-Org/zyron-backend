import { Injectable, Logger, BadRequestException, UnauthorizedException, Optional } from '@nestjs/common';
import axios from 'axios';
import * as crypto from 'crypto';
import { PrismaService } from '../../database/database.module';
import { ScannerGateway } from '../scanner.gateway';
import { EvidenceHasherService } from '../../blockchain/services/evidence-hasher.service';
import { getDefaultAttestationChainId } from '../../blockchain/constants';
import { ZYRON_AGENT_URL, AGENT_API_KEY, CALLBACK_SHARED_SECRET, PORT } from '../../config';
import { AuditStage } from '../../common/enum';

export interface ProverFindingItem {
  id: string;
  title: string;
  severity: string;
  description?: string;
  location?: string;
  vulnerableFunction?: string;
}

export interface ProverResultItem {
  findingId: string;
  verdict?: 'PROVEN_EXPLOIT' | 'PROVEN_FALSE_POSITIVE' | 'INCONCLUSIVE' | 'CANNOT_REPRODUCE' | 'COMPILATION_FAILED' | string;
  status?: string;
  synthesizedPoC?: string;
  exploitSuccess?: boolean;
  fundsDrainedEth?: number;
  deltaBalance?: string;
  traceSteps?: any[];
  errorReason?: string;
  summary?: string;
  verification?: {
    verifierVersion?: string;
    claimedVerdict?: string;
    finalStatus?: 'PROVEN_EXPLOIT' | 'PROVEN_FALSE_POSITIVE' | 'INCONCLUSIVE';
    reasonCodes?: string[];
    sourceHashes?: Record<string, string>;
    testFile?: string;
    testFunction?: string;
    testArtifactSha256?: string;
    runs?: Array<{
      run?: number;
      exitCode: number;
      passed: boolean;
      gasUsed?: number;
      outputSha256: string;
    }>;
  };
  investigation?: any[];
  model?: { provider: string; model: string; turns?: number; totalTokens?: number };
}

export interface ProverCallbackPayload {
  jobId: string;
  auditId: string;
  status?: 'COMPLETED' | 'FAILED';
  error?: string;
  results: ProverResultItem[];
  durationMs: number;
}

@Injectable()
export class AgentProverClientService {
  private readonly logger = new Logger(AgentProverClientService.name);
  private readonly evidenceHasher: EvidenceHasherService;

  constructor(
    private prisma: PrismaService,
    private scannerGateway: ScannerGateway,
    @Optional() evidenceHasher?: EvidenceHasherService,
  ) {
    this.evidenceHasher = evidenceHasher || new EvidenceHasherService();
  }

  /**
   * Dispatch critical and high findings to the autonomous AI prover & sandbox microservice
   */
  async dispatchProverJob(
    auditId: string,
    sourceCode: string,
    findings: ProverFindingItem[],
  ): Promise<{ dispatched: boolean; count: number; jobId?: string; message: string }> {
    const targetFindings = findings;

    if (targetFindings.length === 0) {
      this.logger.log(`[AgentProverClient] Audit ${auditId} has no findings to prove.`);
      return {
        dispatched: false,
        count: 0,
        message: 'No findings requiring EVM sandbox proof.',
      };
    }

    const callbackUrl = `http://localhost:${PORT}/api/v1/scanner/prover-callback`;

    this.logger.log(
      `[AgentProverClient] Dispatching ${targetFindings.length} finding(s) for audit ${auditId} to Zyron Agent (${ZYRON_AGENT_URL})...`,
    );

    try {
      // Query audit details to attach repository and compiler metadata
      const audit = await this.prisma.auditRequest.findUnique({
        where: { id: auditId },
      });

      const repo = audit?.githubRepoUrl
        ? {
            url: audit.githubRepoUrl,
            branch: audit.githubBranch || undefined,
            commit: audit.gitCommit || undefined,
          }
        : undefined;

      const response = await axios.post(
        `${ZYRON_AGENT_URL}/api/v1/prover/jobs`,
        {
          auditId,
          sourceCode,
          contractFileName: audit?.contractFileName,
          compilerVersion: audit?.compilerVersion,
          network: audit?.network,
          repo,
          findings: targetFindings,
          callbackUrl,
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'x-zyron-agent-key': AGENT_API_KEY,
          },
          timeout: 15000,
        },
      );

      this.logger.log(
        `[AgentProverClient] Job submitted successfully: ${response.data.jobId} (status: ${response.data.status})`,
      );

      // Mark target findings as RUNNING so UI displays active prover progress
      await this.prisma.finding.updateMany({
        where: {
          id: { in: targetFindings.map((f) => f.id) },
        },
        data: {
          fuzzTestStatus: 'RUNNING',
        },
      });

      return {
        dispatched: true,
        count: targetFindings.length,
        jobId: response.data.jobId,
        message: `Dispatched ${targetFindings.length} finding(s) to autonomous EVM sandbox.`,
      };
    } catch (err: any) {
      this.logger.warn(
        `[AgentProverClient] Failed to dispatch prover job: ${err.response?.data?.message || err.message}`,
      );
      return {
        dispatched: false,
        count: targetFindings.length,
        message: `Autonomous agent microservice unavailable: ${err.message}`,
      };
    }
  }

  /**
   * Handle webhook callback from zyron-agent containing EVM simulation results & traces
   */
  async handleProverCallback(
    signatureHeader: string | undefined,
    rawBody: string | undefined,
    payload: ProverCallbackPayload,
  ) {
    // Verify HMAC-SHA256 signature (enforced whenever CALLBACK_SHARED_SECRET env is explicitly configured or header is present)
    const activeSecret = process.env.CALLBACK_SHARED_SECRET || CALLBACK_SHARED_SECRET;
    const requireHmac = Boolean(process.env.CALLBACK_SHARED_SECRET) || Boolean(signatureHeader);
    if (requireHmac && activeSecret) {
      if (!signatureHeader) {
        this.logger.error(`[AgentProverClient] Missing x-zyron-agent-signature header on prover callback!`);
        throw new UnauthorizedException('Missing callback signature.');
      }
      const bodyToSign = rawBody ?? JSON.stringify(payload);
      const hmac = crypto.createHmac('sha256', activeSecret);
      hmac.update(bodyToSign);
      const expectedSig = `sha256=${hmac.digest('hex')}`;

      const sigBuf = Buffer.from(signatureHeader, 'utf8');
      const expBuf = Buffer.from(expectedSig, 'utf8');
      if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
        this.logger.error(`[AgentProverClient] HMAC signature mismatch on prover callback!`);
        throw new UnauthorizedException('Invalid callback signature.');
      }
    }

    const { auditId, results, jobId, status, error } = payload;
    this.logger.log(
      `[AgentProverClient] Received prover callback for audit ${auditId} (job: ${jobId}, status: ${status || 'COMPLETED'}, results: ${results?.length || 0})`,
    );

    // If the prover failed, halt the pipeline and mark stage as FAILED
    if (status === 'FAILED') {
      const failureReason = `AI EVM Sandbox Prover Error: ${error || 'Synthesis/Simulation failed'}`;
      this.logger.error(`[AgentProverClient] Prover execution failed for audit ${auditId}: ${failureReason}`);

      await this.prisma.auditRequest.update({
        where: { id: auditId },
        data: {
          stage: 'FAILED',
          failureReason,
        },
      });

      await this.prisma.scanJob.updateMany({
        where: { auditId },
        data: {
          status: 'failed',
        },
      });

      this.scannerGateway.emitScanProgress(auditId, {
        passNumber: 14,
        totalPasses: 14,
        tool: 'zyron-agent-prover',
        log: `[PROVER ERROR] ${failureReason}`,
        findingCount: 0,
      });

      return { success: false, error: failureReason };
    }

    if (!Array.isArray(results)) {
      throw new BadRequestException('Payload missing valid results array');
    }

    const auditRecord = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
    });

    let updatedCount = 0;
    const evidenceHashes: string[] = [];

    for (const result of results) {
      try {
        const finding = await this.prisma.finding.findFirst({
          where: {
            OR: [
              { id: result.findingId },
              { displayId: result.findingId },
            ],
          },
        });

        if (!finding) {
          this.logger.warn(`[AgentProverClient] Finding ${result.findingId} not found for audit ${auditId}`);
          continue;
        }

        // Deterministic verifier status takes precedence over raw model claim
        const rawStatus = result.verification?.finalStatus || result.verdict || result.status;
        const normalizedVerdict = this.evidenceHasher.normalizeVerificationStatus(rawStatus);
        const isFalsePositive = normalizedVerdict === 'PROVEN_FALSE_POSITIVE';
        const isExploit = normalizedVerdict === 'PROVEN_EXPLOIT';
        const fundsDrained = result.fundsDrainedEth !== undefined ? `${result.fundsDrainedEth} ETH` : (result.deltaBalance || '0.0 ETH');

        let fpJustification = finding.fpJustification;
        if (isFalsePositive) {
          fpJustification =
            (result as any).reasoning ||
            result.summary ||
            `Autonomous EVM Sandbox Verification: Invariant held during simulated attack. Target funds preserved (${fundsDrained} drained).`;
        }

        await this.prisma.finding.update({
          where: { id: finding.id },
          data: {
            traceSteps: result.traceSteps ? JSON.stringify(result.traceSteps) : null,
            synthesizedPoC: result.synthesizedPoC || null,
            fuzzTestStatus: normalizedVerdict,
            fundsDrainedEth: typeof result.fundsDrainedEth === 'number' ? result.fundsDrainedEth : null,
            falsePositive: isFalsePositive ? true : finding.falsePositive,
            fpJustification,
            confidence: isExploit ? '100%' : (isFalsePositive ? '10%' : finding.confidence),
          },
        });

        // Build and persist canonical zyron.evidence/v1 record
        const sourceHashes = result.verification?.sourceHashes || (auditRecord?.sourceHash ? { [auditRecord.contractFileName || 'Contract.sol']: auditRecord.sourceHash } : {});
        const testArtifactHash =
          result.verification?.testArtifactSha256 ||
          (result.synthesizedPoC
            ? '0x' + crypto.createHash('sha256').update(result.synthesizedPoC, 'utf8').digest('hex')
            : '');
        const runs = (result.verification?.runs || []).map((r) => ({
          exitCode: r.exitCode,
          passed: r.passed,
          stdoutHash: r.outputSha256.startsWith('0x') ? r.outputSha256 : `0x${r.outputSha256}`,
          gasUsed: r.gasUsed,
        }));

        const evidenceRecord = this.evidenceHasher.buildFindingEvidenceV1({
          auditId,
          findingId: finding.id,
          displayId: finding.displayId,
          repository: auditRecord?.githubRepoUrl || null,
          gitCommit: auditRecord?.gitCommit || null,
          sourceHashes,
          targetContractFile: auditRecord?.contractFileName || 'Contract.sol',
          targetContractAddress: auditRecord?.contractAddress || null,
          chainId: auditRecord?.onChainChainId || getDefaultAttestationChainId(),
          bytecodeHash: auditRecord?.bytecodeHash || null,
          ruleId: finding.ruleId,
          severity: finding.severity,
          taxonomy: finding.taxonomy,
          testFile: result.verification?.testFile || null,
          testFunction: result.verification?.testFunction || null,
          testArtifactHash,
          claimedVerdict: result.verification?.claimedVerdict || result.verdict || normalizedVerdict,
          finalStatus: normalizedVerdict,
          runs,
          rejectionReasons: result.verification?.reasonCodes || [],
          verifierVersion: result.verification?.verifierVersion || 'zyron-verifier/2.0.0',
          provider: result.model?.provider || 'meta',
          model: result.model?.model || 'muse-spark-1.3',
          reportRef: {
            ipfsCid: auditRecord?.ipfsCid || null,
            reportUrl: `/api/v1/audits/${auditId}/report.pdf`,
          },
        });

        evidenceHashes.push(evidenceRecord.evidenceHash);

        if ((this.prisma as any).proverEvidence?.upsert) {
          await (this.prisma as any).proverEvidence.upsert({
            where: {
              auditId_findingId: {
                auditId,
                findingId: finding.id,
              },
            },
            update: {
              findingDisplayId: finding.displayId,
              schemaVersion: evidenceRecord.schemaVersion,
              verifierVersion: result.verification?.verifierVersion || 'zyron-verifier/2.0.0',
              finalStatus: normalizedVerdict,
              claimedVerdict: result.verification?.claimedVerdict || result.verdict || normalizedVerdict,
              testFile: result.verification?.testFile || null,
              testFunction: result.verification?.testFunction || null,
              testArtifactHash: testArtifactHash || null,
              sourceHashesJson: JSON.stringify(sourceHashes),
              provider: result.model?.provider || 'meta',
              model: result.model?.model || 'muse-spark-1.3',
              runsJson: JSON.stringify(runs),
              investigationJson: result.investigation ? JSON.stringify(result.investigation) : null,
              canonicalJson: evidenceRecord.canonicalJson,
              evidenceHash: evidenceRecord.evidenceHash,
              rejectionReasonsJson: JSON.stringify(result.verification?.reasonCodes || []),
            },
            create: {
              auditId,
              findingId: finding.id,
              findingDisplayId: finding.displayId,
              schemaVersion: evidenceRecord.schemaVersion,
              verifierVersion: result.verification?.verifierVersion || 'zyron-verifier/2.0.0',
              finalStatus: normalizedVerdict,
              claimedVerdict: result.verification?.claimedVerdict || result.verdict || normalizedVerdict,
              testFile: result.verification?.testFile || null,
              testFunction: result.verification?.testFunction || null,
              testArtifactHash: testArtifactHash || null,
              sourceHashesJson: JSON.stringify(sourceHashes),
              provider: result.model?.provider || 'meta',
              model: result.model?.model || 'muse-spark-1.3',
              runsJson: JSON.stringify(runs),
              investigationJson: result.investigation ? JSON.stringify(result.investigation) : null,
              canonicalJson: evidenceRecord.canonicalJson,
              evidenceHash: evidenceRecord.evidenceHash,
              rejectionReasonsJson: JSON.stringify(result.verification?.reasonCodes || []),
            },
          });
        }

        updatedCount++;
      } catch (err: any) {
        this.logger.error(`[AgentProverClient] Error updating finding ${result.findingId}: ${err.message}`);
      }
    }

    // Broadcast update via WebSocket gateway
    this.scannerGateway.emitProverComplete(auditId, {
      jobId,
      updatedCount,
      results,
    });

    // Advance audit to IN_REVIEW now that the AI EVM prover has completed simulation
    const currentAudit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
    });
    const evidenceMerkleRoot =
      evidenceHashes.length > 0 ? this.evidenceHasher.computeEvidenceMerkleRoot(evidenceHashes) : undefined;
    if (currentAudit && (currentAudit.stage === 'SCANNING' || currentAudit.stage === 'PENDING')) {
      await this.prisma.auditRequest.update({
        where: { id: auditId },
        data: {
          stage: AuditStage.IN_REVIEW,
          stageNumber: 3,
          failureReason: null,
          ...(evidenceMerkleRoot ? { merkleRoot: evidenceMerkleRoot } : {}),
        },
      });
    } else if (currentAudit && evidenceMerkleRoot) {
      await this.prisma.auditRequest.update({
        where: { id: auditId },
        data: { merkleRoot: evidenceMerkleRoot },
      });
    }

    this.logger.log(`[AgentProverClient] Successfully updated ${updatedCount} finding(s) with EVM traces. Audit advanced to IN_REVIEW.`);
    return { success: true, updatedCount, evidenceMerkleRoot };
  }

  /**
   * Manually trigger autonomous sandbox verification for all High/Critical findings in an audit
   */
  async proveAuditFindings(auditId: string) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { findings: true },
    });

    if (!audit) {
      throw new BadRequestException(`Audit ${auditId} not found`);
    }

    const sourceCode = audit.sourceCode || audit.contractFileName;
    if (!sourceCode) {
      throw new BadRequestException(`No contract source code available for audit ${auditId}`);
    }

    // Reset failure state upon manual rerun
    await this.prisma.auditRequest.update({
      where: { id: auditId },
      data: {
        stage: AuditStage.SCANNING,
        failureReason: null,
      },
    });

    return this.dispatchProverJob(
      auditId,
      sourceCode,
      audit.findings.map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        description: f.description,
        location: f.location,
        vulnerableFunction: f.location?.split(':')[1] || undefined,
      })),
    );
  }

  /**
   * Internal endpoint helper: retrieve submitter's GitHub OAuth token for private repository clone
   */
  async getRepoCredentials(apiKey: string | undefined, auditId: string) {
    if (!apiKey || apiKey !== AGENT_API_KEY) {
      throw new UnauthorizedException('Invalid or missing x-zyron-agent-key header.');
    }

    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { submittedBy: true },
    });

    if (!audit) {
      return { token: null };
    }

    return {
      token: audit.submittedBy?.githubAccessToken || null,
    };
  }

  /**
   * Fetch autonomous prover execution transcript / logs for a given finding
   */
  async getFindingTranscript(findingId: string) {
    try {
      const response = await axios.get(
        `${ZYRON_AGENT_URL}/api/v1/prover/findings/${findingId}/transcript`,
        {
          headers: { 'x-zyron-agent-key': AGENT_API_KEY },
          timeout: 5000,
        },
      );
      return response.data;
    } catch (err: any) {
      this.logger.warn(`Failed to fetch transcript for finding ${findingId}: ${err.message}`);
      return { findingId, entriesCount: 0, entries: [] };
    }
  }
}
