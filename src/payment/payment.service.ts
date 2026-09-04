import { Injectable } from '@nestjs/common';
import { RecordEscrowDepositDto, GenerateInvoiceDto } from './dto/payment.dto';
import { EscrowPaymentService, InvoicePaymentService } from './services';

@Injectable()
export class PaymentService {
  constructor(
    private escrowPayment: EscrowPaymentService,
    private invoicePayment: InvoicePaymentService,
  ) {}

  getPaymentByAudit(auditId: string) {
    return this.escrowPayment.getPaymentByAudit(auditId);
  }

  recordEscrowDeposit(dto: RecordEscrowDepositDto) {
    return this.escrowPayment.recordEscrowDeposit(dto);
  }

  generateCorporateInvoice(dto: GenerateInvoiceDto) {
    return this.invoicePayment.generateCorporateInvoice(dto);
  }
}
