import { Module } from '@nestjs/common';
import { AuditController, FindingController } from './audit.controller';
import { AuditService } from './audit.service';
import { AuthModule } from '../auth/auth.module';
import { BlockchainModule } from '../blockchain/blockchain.module';
import {
  AuditSanitizerService,
  CreateAuditService,
  GetAuditsService,
  ClaimTicketService,
  AdvanceStageService,
  FindingsService,
  CommentsService,
} from './services';

@Module({
  imports: [AuthModule, BlockchainModule],
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
  ],
})
export class AuditModule {}
