import { FindingSeverity } from '../../common/enum';

export interface AiFinding {
  title: string;
  severity: FindingSeverity;
  cvss: string;
  taxonomy: string;
  location: string;
  impact: string;
  description: string;
  vulnerableCode?: string;
  remediatedCode?: string;
  ruleId?: string;
  decision?: 'CONFIRMED' | 'DOWNGRADE' | 'DISMISS_INTENDED_DESIGN' | 'FALSE_POSITIVE';
  justification?: string;
  falsePositive?: boolean;
  fpJustification?: string;
  pocScenario?: string;
  confidence?: 'HIGH_CONFIDENCE' | 'NEEDS_MANUAL_REVIEW' | 'INFORMATIONAL';
}

export interface AiScanResult {
  provider: string;
  modelUsed: string;
  contractFileName: string;
  analysisSummary: string;
  findings: AiFinding[];
}

export interface AiProvider {
  readonly id: string;
  readonly displayName: string;
  isAvailable(): boolean;
  getMissingConfigReason(): string | null;
  analyzeContract(
    contractFileName: string,
    code: string,
    staticFindings?: any[],
    protocolContext?: { protocolName?: string; businessGoals?: string },
    modelOverride?: string,
  ): Promise<AiScanResult>;
}
