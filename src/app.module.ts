import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard } from '@nestjs/throttler';
import { DatabaseModule } from './database/database.module';
import { AuthModule } from './auth/auth.module';
import { AuditModule } from './audit/audit.module';
import { AwsModule } from './aws/aws.module';
import { IntegrationsModule } from './integrations/integrations.module';
import { PaymentModule } from './payment/payment.module';
import { BlockchainModule } from './blockchain/blockchain.module';
import { OrganizationModule } from './organization/organization.module';
import { ScannerModule } from './scanner/scanner.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    ThrottlerModule.forRoot([{
      ttl: 60000,
      limit: 100,
    }]),
    DatabaseModule,
    BlockchainModule,
    AuthModule,
    AuditModule,
    AwsModule,
    IntegrationsModule,
    PaymentModule,
    OrganizationModule,
    ScannerModule,
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}
