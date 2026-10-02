import { Injectable } from '@nestjs/common';
import { AiLocalReasonerService } from './services';
import { FindingSeverity } from '../common/enum';

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
  modelUsed: string;
  contractFileName: string;
  analysisSummary: string;
  findings: AiFinding[];
}

@Injectable()
export class AiAuditService {
  constructor(private localReasoner: AiLocalReasonerService) {}

  analyzeContractWithAi(
    contractFileName: string,
    code: string,
    requestedModel = 'Gemini 1.5 Pro',
    staticFindings?: any[],
    protocolContext?: { protocolName?: string; businessGoals?: string },
  ) {
    return this.localReasoner.analyzeContractWithAi(
      contractFileName,
      code,
      requestedModel,
      staticFindings,
      protocolContext,
    );
  }

  triageStaticFindingsWithAi(
    contractFileName: string,
    code: string,
    staticFindings: any[],
    protocolContext?: { protocolName?: string; businessGoals?: string },
    requestedModel = 'Gemini 1.5 Pro',
  ) {
    return this.localReasoner.analyzeContractWithAi(
      contractFileName,
      code,
      requestedModel,
      staticFindings,
      protocolContext,
    );
  }

  runLocalAiAnalysis(
    contractFileName: string,
    code: string,
    modelName: string,
    staticFindings?: any[],
    protocolContext?: { protocolName?: string; businessGoals?: string },
  ) {
    return this.localReasoner.runLocalAiAnalysis(
      contractFileName,
      code,
      modelName,
      staticFindings,
      protocolContext,
    );
  }
}
