import { Injectable, Logger } from '@nestjs/common';
import { TokenRuleScannerService } from './token-rule-scanner.service';
import { AiAuditService } from '../ai-audit.service';

export interface LegacyFinding {
  title: string;
  severity: string;
  cvss: string;
  taxonomy: string;
  location: string;
  impact: string;
  description: string;
  remediatedCode?: string;
}

@Injectable()
export class LegacyScanRunnerService {
  private readonly logger = new Logger(LegacyScanRunnerService.name);

  constructor(
    private tokenScanner: TokenRuleScannerService,
    private aiAuditService: AiAuditService,
  ) {}

  async run(
    contractFileName: string,
    code: string,
    additionalFiles?: Map<string, string>,
  ): Promise<LegacyFinding[]> {
    this.logger.log(`Running legacy scanners on ${contractFileName}`);
    const tokenResult = this.tokenScanner.analyzeTokenCode(contractFileName, code);
    try {
      const aiResult = await this.aiAuditService.analyzeContractWithAi(
        contractFileName,
        code,
        undefined,
        undefined,
        undefined,
        undefined,
        additionalFiles,
      );
      return [...tokenResult.findings, ...aiResult.findings];
    } catch (err: any) {
      this.logger.warn(`AI analysis skipped in legacy runner: ${err.message}`);
      return tokenResult.findings;
    }
  }
}
