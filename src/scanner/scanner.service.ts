import { Injectable } from '@nestjs/common';
import { ScanOrchestratorService } from './services';

@Injectable()
export class ScannerService {
  constructor(private orchestrator: ScanOrchestratorService) {}

  runScan(auditId: string, customCode?: string) {
    return this.orchestrator.runScan(auditId, customCode);
  }

  getScanJobsByAudit(auditId: string) {
    return this.orchestrator.getScanJobsByAudit(auditId);
  }

  processGithubBotMention(payload: any) {
    return this.orchestrator.processGithubBotMention(payload);
  }
}
