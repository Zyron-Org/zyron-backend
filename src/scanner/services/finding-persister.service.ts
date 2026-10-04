import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { FindingStatus } from '../../common/enum';
import { PassFinding } from '../engine/types';
import { LegacyFinding } from './legacy-scan-runner.service';
import { AiScanResult } from '../ai-providers';

@Injectable()
export class FindingPersisterService {
  private readonly logger = new Logger(FindingPersisterService.name);

  constructor(private prisma: PrismaService) {}

  async persistLegacyFindings(auditId: string, startIdx: number, findings: LegacyFinding[]): Promise<number> {
    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      const displayId = `${auditId}-${(startIdx + i + 1).toString().padStart(3, '0')}`;
      const foundBy = (f as any).foundBy || ((f as any).ruleId?.startsWith('ZYRON-AI') ? 'AI' : 'STATIC');
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
          foundBy,
          auditId,
        },
      });
    }
    return findings.length;
  }

  async persistASTFindings(auditId: string, startIdx: number, findings: PassFinding[]): Promise<number> {
    let persistedCount = 0;

    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      const locationStr = `${f.filePath}:${f.line}`;

      // Check if identical finding already exists for this audit
      const existing = await this.prisma.finding.findFirst({
        where: {
          auditId,
          location: locationStr,
          title: f.title,
        },
      });

      if (existing) {
        this.logger.debug(`Skipping duplicate finding for ${locationStr}: ${f.title}`);
        continue;
      }

      const displayId = `${auditId}-${(startIdx + persistedCount + 1).toString().padStart(3, '0')}`;
      const remediationText = f.remediation || f.recommendation || 'Remediation advice unavailable.';

      await this.prisma.finding.create({
        data: {
          displayId,
          title: f.title,
          severity: f.severity,
          status: FindingStatus.OPEN,
          confidence: f.confidence,
          analysisPass: f.analysisPass,
          taxonomy: `${f.swcId} · ${f.cweId}`,
          location: locationStr,
          impact: f.description,
          description: `${f.description}\n\nCode Snippet:\n${f.vulnerableCode || f.codeSnippet}\n\nRemediation:\n${remediationText}`,
          remediatedCode: remediationText,
          ruleId: f.ruleId,
          foundBy: 'STATIC',
          auditId,
        },
      });

      persistedCount++;
    }

    return persistedCount;
  }

  /**
   * Reconcile AST findings during a re-audit / remediation pass:
   * 1. Marks eliminated findings as RESOLVED with audit comment.
   * 2. Marks still-present findings as UNRESOLVED / OPEN.
   * 3. Flags any newly introduced flaws as REGRESSION findings.
   */
  async reconcileASTFindings(
    auditId: string,
    newFindings: PassFinding[],
    commitRef?: string,
  ): Promise<{ resolvedCount: number; unresolvedCount: number; regressionCount: number }> {
    const existingFindings = await this.prisma.finding.findMany({
      where: { auditId },
    });

    const systemUser = await this.prisma.user.findFirst({
      where: { role: 'ADMIN' },
    });

    const commitShort = (commitRef || 'latest').slice(0, 7);
    let resolvedCount = 0;
    let unresolvedCount = 0;
    let regressionCount = 0;

    const isMatching = (existing: any, incoming: PassFinding) => {
      const existFile = existing.location?.split(':')[0]?.split('/').pop();
      const incomingFile = incoming.filePath?.split('/').pop();
      if (!existFile || !incomingFile || existFile !== incomingFile) return false;

      if (existing.ruleId && incoming.ruleId && existing.ruleId === incoming.ruleId) return true;
      if (
        existing.title &&
        incoming.title &&
        existing.title.toLowerCase().trim() === incoming.title.toLowerCase().trim()
      ) {
        return true;
      }

      return false;
    };

    for (const ef of existingFindings) {
      if (ef.falsePositive || ef.status === FindingStatus.WONT_FIX) {
        continue;
      }

      const stillPresent = newFindings.find((nf) => isMatching(ef, nf));

      if (!stillPresent) {
        await this.prisma.finding.update({
          where: { id: ef.id },
          data: {
            status: FindingStatus.RESOLVED,
            isMitigated: true,
            remediationNote: `Automated AST re-scan verified fix in commit ${commitShort}.`,
          },
        });

        if (systemUser) {
          await this.prisma.comment.create({
            data: {
              findingId: ef.id,
              auditId,
              senderId: systemUser.id,
              commitRef,
              message: `[VERIFIED RESOLVED] Static AST analysis re-verification confirmed this vulnerability is resolved in commit ${commitShort}.`,
            },
          });
        }
        resolvedCount++;
        this.logger.log(`[Re-Audit] Finding ${ef.displayId} verified RESOLVED at ${commitShort}`);
      } else {
        await this.prisma.finding.update({
          where: { id: ef.id },
          data: {
            status: FindingStatus.OPEN,
            remediationNote: `Vulnerability STILL DETECTED in commit ${commitShort} at line ${stillPresent.line}.`,
          },
        });

        if (systemUser) {
          await this.prisma.comment.create({
            data: {
              findingId: ef.id,
              auditId,
              senderId: systemUser.id,
              commitRef,
              message: `[UNRESOLVED] Vulnerability was still detected in commit ${commitShort} at line ${stillPresent.line}.`,
            },
          });
        }
        unresolvedCount++;
        this.logger.warn(`[Re-Audit] Finding ${ef.displayId} STILL PRESENT at ${commitShort}`);
      }
    }

    // Check for regressions
    for (const nf of newFindings) {
      const matched = existingFindings.find((ef) => isMatching(ef, nf));
      if (!matched) {
        const totalCount = await this.prisma.finding.count({ where: { auditId } });
        const displayId = `${auditId}-${(totalCount + 1).toString().padStart(3, '0')}`;
        const locationStr = `${nf.filePath}:${nf.line}`;
        const remediationText = nf.remediation || nf.recommendation || 'Remediation advice unavailable.';

        await this.prisma.finding.create({
          data: {
            displayId,
            title: `[REGRESSION] ${nf.title}`,
            severity: nf.severity,
            status: FindingStatus.OPEN,
            confidence: nf.confidence,
            analysisPass: nf.analysisPass,
            taxonomy: `${nf.swcId} · ${nf.cweId}`,
            location: locationStr,
            impact: `New regression introduced in remediation commit ${commitShort}. ${nf.description}`,
            description: `REGRESSION ALERT: Introduced in commit ${commitShort}.\n\n${nf.description}\n\nCode Snippet:\n${nf.vulnerableCode || nf.codeSnippet}\n\nRemediation:\n${remediationText}`,
            remediatedCode: remediationText,
            ruleId: nf.ruleId,
            foundBy: 'STATIC',
            auditId,
          },
        });
        regressionCount++;
        this.logger.warn(`[Re-Audit] REGRESSION detected: ${nf.title} at ${locationStr}`);
      }
    }

    return { resolvedCount, unresolvedCount, regressionCount };
  }

  /**
   * Apply AI triage decisions:
   * 1. Updates static findings flagged by AI as false positive or confirmed.
   * 2. Persists novel findings discovered independently by the AI (Task 2).
   */
  async applyAiTriage(
    auditId: string,
    aiResult: AiScanResult,
  ): Promise<{ triagedCount: number; novelAddedCount: number }> {
    let triagedCount = 0;
    let novelAddedCount = 0;

    const existingFindings = await this.prisma.finding.findMany({ where: { auditId } });

    for (const af of aiResult.findings) {
      // Find matching existing static finding by ruleId, location, or exact title
      const matched = existingFindings.find(
        (ef) =>
          (af.ruleId && ef.ruleId === af.ruleId) ||
          (af.location && ef.location === af.location) ||
          ef.title.toLowerCase() === af.title.toLowerCase(),
      );

      if (matched) {
        const isFp =
          af.falsePositive ||
          af.decision === 'FALSE_POSITIVE' ||
          af.decision === 'DISMISS_INTENDED_DESIGN';

        await this.prisma.finding.update({
          where: { id: matched.id },
          data: {
            falsePositive: isFp,
            fpJustification:
              af.fpJustification ||
              af.justification ||
              (isFp ? 'Flagged as intentional protocol pattern / false positive during AI triage.' : undefined),
            remediationNote: af.pocScenario
              ? `[AI Triage Analysis]:\n${af.pocScenario}`
              : matched.remediationNote,
          },
        });
        triagedCount++;
      } else {
        // Novel finding discovered by AI
        const displayId = `${auditId}-${(existingFindings.length + novelAddedCount + 1).toString().padStart(3, '0')}`;
        await this.prisma.finding.create({
          data: {
            displayId,
            title: af.title,
            severity: af.severity || 'HIGH',
            cvss: af.cvss || 'CVSS 8.5',
            status: FindingStatus.OPEN,
            confidence: 'HIGH_CONFIDENCE',
            taxonomy: af.taxonomy || 'SWC-107 · CWE-841',
            location: af.location || 'Unknown',
            impact: af.impact || 'Protocol vulnerability identified during AI deep inspection',
            description: `${af.description}${af.pocScenario ? `\n\nPoC / Attack Scenario:\n${af.pocScenario}` : ''}`,
            remediatedCode: af.remediatedCode || undefined,
            ruleId: af.ruleId || `ZYRON-AI-${String(novelAddedCount + 1).padStart(3, '0')}`,
            falsePositive: !!af.falsePositive,
            fpJustification: af.fpJustification,
            foundBy: 'AI',
            auditId,
          },
        });
        novelAddedCount++;
      }
    }

    this.logger.log(
      `[AI Triage Persisted] Audit ${auditId}: ${triagedCount} findings triaged, ${novelAddedCount} novel AI findings recorded.`,
    );

    return { triagedCount, novelAddedCount };
  }
}

