import { Module } from '@nestjs/common';
import { ScannerService } from './scanner.service';
import { TokenScannerService } from './token-scanner.service';
import { ScannerGateway } from './scanner.gateway';
import { ScannerController } from './scanner.controller';
import { GithubWebhookController } from './github-webhook.controller';
import { IntegrationsModule } from '../integrations/integrations.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [AuthModule, IntegrationsModule],
  controllers: [ScannerController, GithubWebhookController],
  providers: [ScannerService, TokenScannerService, ScannerGateway],
  exports: [ScannerService, TokenScannerService, ScannerGateway],
})
export class ScannerModule {}
