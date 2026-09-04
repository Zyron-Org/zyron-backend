import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { GenerateInvoiceDto } from '../dto/payment.dto';
import { PaymentMethod, PaymentStatus } from '../../common/enum';

@Injectable()
export class InvoicePaymentService {
  constructor(private prisma: PrismaService) {}

  async generateCorporateInvoice(dto: GenerateInvoiceDto) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: dto.auditId },
    });

    if (!audit) {
      throw new NotFoundException(`Audit engagement ${dto.auditId} not found`);
    }

    const invoiceNumber = `INV-${Date.now().toString().slice(-6)}`;
    const invoiceUrl = `/invoices/${invoiceNumber}-${dto.auditId}.pdf`;

    const payment = await this.prisma.payment.upsert({
      where: { auditId: dto.auditId },
      create: {
        auditId: dto.auditId,
        method: PaymentMethod.CORPORATE_INVOICE,
        amount: dto.amount,
        currency: 'USD',
        invoiceUrl,
        status: PaymentStatus.PENDING,
      },
      update: {
        method: PaymentMethod.CORPORATE_INVOICE,
        amount: dto.amount,
        currency: 'USD',
        invoiceUrl,
        status: PaymentStatus.PENDING,
      },
    });

    return {
      payment,
      invoiceNumber,
      invoiceUrl,
    };
  }
}
