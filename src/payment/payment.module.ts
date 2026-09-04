import { Module } from '@nestjs/common';
import { PaymentController } from './payment.controller';
import { PaymentService } from './payment.service';
import { AuthModule } from '../auth/auth.module';
import { BlockchainModule } from '../blockchain/blockchain.module';
import { EscrowPaymentService, InvoicePaymentService } from './services';

@Module({
  imports: [AuthModule, BlockchainModule],
  controllers: [PaymentController],
  providers: [PaymentService, EscrowPaymentService, InvoicePaymentService],
  exports: [PaymentService, EscrowPaymentService, InvoicePaymentService],
})
export class PaymentModule {}
