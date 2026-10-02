import { Module, forwardRef } from '@nestjs/common';
import { AuditController, FindingController } from './audit.controller';
import { ReportsController } from './reports.controller';
import { AuditService } from './audit.service';
import { AuthModule } from '../auth/auth.module';
import { BlockchainModule } from '../blockchain/blockchain.module';
import { ScannerModule } from '../scanner/scanner.module';
import { IntegrationsModule } from '../integrations/integrations.module';
import { IpfsModule } from '../ipfs/ipfs.module';
import {
  AuditSanitizerService,
  CreateAuditService,
  GetAuditsService,
  ClaimTicketService,
  AdvanceStageService,
  FindingsService,
  CommentsService,
  AutoAssignService,
  ReportGeneratorService,
} from './services';

@Module({
  imports: [
    AuthModule,
    BlockchainModule,
    IpfsModule,
    forwardRef(() => ScannerModule),
    forwardRef(() => IntegrationsModule),
  ],
  controllers: [AuditController, FindingController, ReportsController],
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
    ReportGeneratorService,
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
    ReportGeneratorService,
  ],
})
export class AuditModule {}
