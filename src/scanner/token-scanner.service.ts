import { Injectable } from '@nestjs/common';
import { TokenRuleScannerService } from './services';
import { FindingSeverity } from '../common/enum';

export interface TokenAnalysisFinding {
  title: string;
  severity: FindingSeverity;
  cvss: string;
  taxonomy: string;
  location: string;
  impact: string;
  description: string;
  vulnerableCode?: string;
  remediatedCode?: string;
}

export interface TokenScanResult {
  contractFileName: string;
  tokenRiskScore: number;
  summary: string;
  findings: TokenAnalysisFinding[];
}

@Injectable()
export class TokenScannerService {
  constructor(private tokenRuleScanner: TokenRuleScannerService) {}

  analyzeTokenCode(contractFileName: string, code: string): TokenScanResult {
    return this.tokenRuleScanner.analyzeTokenCode(contractFileName, code);
  }
}
