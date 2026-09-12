import { Injectable, Logger } from '@nestjs/common';
import { TokenRuleScannerService } from './token-rule-scanner.service';
import { AiLocalReasonerService } from './ai-local-reasoner.service';

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
    private aiAuditService: AiLocalReasonerService,
  ) {}

  async run(contractFileName: string, code: string): Promise<LegacyFinding[]> {
    this.logger.log(`Running legacy scanners on ${contractFileName}`);
    const tokenResult = this.tokenScanner.analyzeTokenCode(contractFileName, code);
    const aiResult = await this.aiAuditService.analyzeContractWithAi(contractFileName, code);
    return [...tokenResult.findings, ...aiResult.findings];
  }
}
