import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { FindingStatus } from '../../common/enum';
import { PassFinding } from '../engine/types';
import { LegacyFinding } from './legacy-scan-runner.service';

@Injectable()
export class FindingPersisterService {
  private readonly logger = new Logger(FindingPersisterService.name);

  constructor(private prisma: PrismaService) {}

  async persistLegacyFindings(auditId: string, startIdx: number, findings: LegacyFinding[]): Promise<number> {
    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      const displayId = `${auditId}-${(startIdx + i + 1).toString().padStart(3, '0')}`;
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
          auditId,
        },
      });

      persistedCount++;
    }

    return persistedCount;
  }
}
