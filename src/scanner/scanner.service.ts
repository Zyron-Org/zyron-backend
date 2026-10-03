import { Injectable } from '@nestjs/common';
import { ScanOrchestratorService, AgentProverClientService } from './services';

@Injectable()
export class ScannerService {
  constructor(
    private orchestrator: ScanOrchestratorService,
    private proverClient: AgentProverClientService,
  ) {}

  runScan(auditId: string, customCode?: string) {
    return this.orchestrator.runScan(auditId, customCode);
  }

  getScanJobsByAudit(auditId: string) {
    return this.orchestrator.getScanJobsByAudit(auditId);
  }

  processGithubBotMention(payload: any) {
    return this.orchestrator.processGithubBotMention(payload);
  }

  proveAuditFindings(auditId: string) {
    return this.proverClient.proveAuditFindings(auditId);
  }

  handleProverCallback(signature: string | undefined, rawBody: string | undefined, payload: any) {
    return this.proverClient.handleProverCallback(signature, rawBody, payload);
  }

  getRepoCredentials(apiKey: string | undefined, auditId: string) {
    return this.proverClient.getRepoCredentials(apiKey, auditId);
  }
}
