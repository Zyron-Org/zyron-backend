import { Module } from '@nestjs/common';
import { StorageService } from './storage.service';
import { StorageController } from './storage.controller';
import { AuthModule } from '../auth/auth.module';
import { ContractValidatorService, S3StorageService } from './services';

@Module({
  imports: [AuthModule],
  controllers: [StorageController],
  providers: [StorageService, ContractValidatorService, S3StorageService],
  exports: [StorageService, ContractValidatorService, S3StorageService],
})
export class AwsModule {}
