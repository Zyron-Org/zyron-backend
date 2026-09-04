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

  analyzeContractWithAi(contractFileName: string, code: string, requestedModel = 'Gemini 1.5 Pro') {
    return this.localReasoner.analyzeContractWithAi(contractFileName, code, requestedModel);
  }

  runLocalAiAnalysis(contractFileName: string, code: string, modelName: string) {
    return this.localReasoner.runLocalAiAnalysis(contractFileName, code, modelName);
  }
}
