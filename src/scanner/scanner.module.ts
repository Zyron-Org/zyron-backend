import { Module, forwardRef } from '@nestjs/common';
import { ScannerService } from './scanner.service';
import { TokenScannerService } from './token-scanner.service';
import { AiAuditService } from './ai-audit.service';
import { ScannerGateway } from './scanner.gateway';
import { ScannerController } from './scanner.controller';
import { GithubWebhookController } from './github-webhook.controller';
import { IntegrationsModule } from '../integrations/integrations.module';
import { AuthModule } from '../auth/auth.module';
import { AuditModule } from '../audit/audit.module';
import { ScannerEngineModule } from './engine/scanner-engine.module';
import { PassRegistryService } from './passes/pass-registry';
import {
  TokenRuleScannerService,
  AiGeminiClientService,
  GithubWebhookHandlerService,
  LegacyScanRunnerService,
  ASTEngineRunnerService,
  FindingPersisterService,
  ScanOrchestratorService,
} from './services';
import {
  GeminiProviderService,
  AnthropicProviderService,
  OpenAiProviderService,
  DeepSeekProviderService,
  AiProviderFactory,
} from './ai-providers';

@Module({
  imports: [AuthModule, IntegrationsModule, forwardRef(() => AuditModule), ScannerEngineModule],
  controllers: [ScannerController, GithubWebhookController],
  providers: [
    ScannerService,
    TokenScannerService,
    AiAuditService,
    ScannerGateway,
    TokenRuleScannerService,
    AiGeminiClientService,
    GeminiProviderService,
    AnthropicProviderService,
    OpenAiProviderService,
    DeepSeekProviderService,
    AiProviderFactory,
    GithubWebhookHandlerService,
    PassRegistryService,
    LegacyScanRunnerService,
    ASTEngineRunnerService,
    FindingPersisterService,
    ScanOrchestratorService,
  ],
  exports: [
    ScannerService,
    TokenScannerService,
    AiAuditService,
    ScannerGateway,
    TokenRuleScannerService,
    GeminiProviderService,
    AnthropicProviderService,
    OpenAiProviderService,
    DeepSeekProviderService,
    AiProviderFactory,
    GithubWebhookHandlerService,
    PassRegistryService,
    LegacyScanRunnerService,
    ASTEngineRunnerService,
    FindingPersisterService,
    ScanOrchestratorService,
  ],
})
export class ScannerModule {}
