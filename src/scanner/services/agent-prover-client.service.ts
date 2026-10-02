import { Injectable, Logger, BadRequestException, UnauthorizedException } from '@nestjs/common';
import axios from 'axios';
import * as crypto from 'crypto';
import { PrismaService } from '../../database/database.module';
import { ScannerGateway } from '../scanner.gateway';
import { ZYRON_AGENT_URL, AGENT_API_KEY, CALLBACK_SHARED_SECRET, PORT } from '../../config';

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
  verdict: 'PROVEN_EXPLOIT' | 'PROVEN_FALSE_POSITIVE' | 'CANNOT_REPRODUCE' | 'COMPILATION_FAILED';
  synthesizedPoC: string;
  exploitSuccess: boolean;
  fundsDrainedEth: number;
  traceSteps: Array<{
    stepIndex: number;
    type: string;
    from: string;
    to: string;
    functionCalled: string;
    valueWei: string;
    gasUsed: number;
    success: boolean;
    stateChangeSummary: string;
  }>;
  errorReason?: string;
}

export interface ProverCallbackPayload {
  jobId: string;
  auditId: string;
  results: ProverResultItem[];
  durationMs: number;
}

@Injectable()
export class AgentProverClientService {
  private readonly logger = new Logger(AgentProverClientService.name);

  constructor(
    private prisma: PrismaService,
    private scannerGateway: ScannerGateway,
  ) {}

  /**
   * Dispatch critical and high findings to the autonomous AI prover & sandbox microservice
   */
  async dispatchProverJob(
    auditId: string,
    sourceCode: string,
    findings: ProverFindingItem[],
  ): Promise<{ dispatched: boolean; count: number; jobId?: string; message: string }> {
    const targetFindings = findings.filter(
      (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH',
    );

    if (targetFindings.length === 0) {
      this.logger.log(`[AgentProverClient] Audit ${auditId} has no Critical or High findings to prove.`);
      return {
        dispatched: false,
        count: 0,
        message: 'No Critical or High severity findings requiring EVM sandbox proof.',
      };
    }

    const callbackUrl = `http://localhost:${PORT}/api/v1/scanner/prover-callback`;

    this.logger.log(
      `[AgentProverClient] Dispatching ${targetFindings.length} finding(s) for audit ${auditId} to Zyron Agent (${ZYRON_AGENT_URL})...`,
    );

    try {
      // Mark finding records as QUEUED
      for (const finding of targetFindings) {
        await this.prisma.finding.updateMany({
          where: { id: finding.id },
          data: { fuzzTestStatus: 'QUEUED' },
        });
      }

      const response = await axios.post(
        `${ZYRON_AGENT_URL}/api/v1/prover/jobs`,
        {
          auditId,
          sourceCode,
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
    // Verify HMAC-SHA256 signature
    if (signatureHeader && CALLBACK_SHARED_SECRET && rawBody) {
      const hmac = crypto.createHmac('sha256', CALLBACK_SHARED_SECRET);
      hmac.update(rawBody);
      const expectedSig = `sha256=${hmac.digest('hex')}`;

      if (signatureHeader !== expectedSig) {
        this.logger.error(`[AgentProverClient] HMAC signature mismatch on prover callback!`);
        throw new UnauthorizedException('Invalid callback signature.');
      }
    }

    const { auditId, results, jobId } = payload;
    this.logger.log(
      `[AgentProverClient] Received prover callback for audit ${auditId} (job: ${jobId}, results: ${results?.length || 0})`,
    );

    if (!Array.isArray(results)) {
      throw new BadRequestException('Payload missing valid results array');
    }

    let updatedCount = 0;
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

        const isFalsePositive = result.verdict === 'PROVEN_FALSE_POSITIVE';
        const isExploit = result.verdict === 'PROVEN_EXPLOIT';

        let fpJustification = finding.fpJustification;
        if (isFalsePositive) {
          fpJustification = `Autonomous EVM Sandbox Verification: Reverted safely during simulated execution. Cannot drain contract funds (${result.fundsDrainedEth} ETH drained).`;
        }

        await this.prisma.finding.update({
          where: { id: finding.id },
          data: {
            traceSteps: result.traceSteps ? JSON.stringify(result.traceSteps) : null,
            synthesizedPoC: result.synthesizedPoC || null,
            fuzzTestStatus: result.verdict,
            falsePositive: isFalsePositive ? true : finding.falsePositive,
            fpJustification,
            confidence: isExploit ? '100%' : (isFalsePositive ? '10%' : finding.confidence),
          },
        });

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

    this.logger.log(`[AgentProverClient] Successfully updated ${updatedCount} finding(s) with EVM traces.`);
    return { success: true, updatedCount };
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
}
