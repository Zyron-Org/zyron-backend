import { Module, forwardRef } from '@nestjs/common';
import { AuditController, FindingController } from './audit.controller';
import { AuditService } from './audit.service';
import { AuthModule } from '../auth/auth.module';
import { BlockchainModule } from '../blockchain/blockchain.module';
import { ScannerModule } from '../scanner/scanner.module';
import { IntegrationsModule } from '../integrations/integrations.module';
import {
  AuditSanitizerService,
  CreateAuditService,
  GetAuditsService,
  ClaimTicketService,
  AdvanceStageService,
  FindingsService,
  CommentsService,
  AutoAssignService,
} from './services';

@Module({
  imports: [AuthModule, BlockchainModule, forwardRef(() => ScannerModule), forwardRef(() => IntegrationsModule)],
  controllers: [AuditController, FindingController],
  providers: [
    AuditService,
    AuditSanitizerService,
    CreateAuditService,
    GetAuditsService,
    ClaimTicketService,
    AdvanceStageService,
    FindingsService,
    CommentsService,
    AutoAssignService,
  ],
  exports: [
    AuditService,
    AuditSanitizerService,
    CreateAuditService,
    GetAuditsService,
    ClaimTicketService,
    AdvanceStageService,
    FindingsService,
    CommentsService,
    AutoAssignService,
  ],
})
export class AuditModule {}
