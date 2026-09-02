import { Module } from '@nestjs/common';
import { AuditController, FindingController } from './audit.controller';
import { AuditService } from './audit.service';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [AuthModule],
  controllers: [AuditController, FindingController],
  providers: [AuditService],
  exports: [AuditService],
})
export class AuditModule {}
