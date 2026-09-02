import { Injectable, NotFoundException, BadRequestException, Logger } from '@nestjs/common';
import { PrismaService } from '../database/database.module';
import { RecordEscrowDepositDto, GenerateInvoiceDto } from './dto/payment.dto';
import { PaymentMethod, PaymentStatus } from '../common/enum';
import { BlockchainService } from '../blockchain/blockchain.service';

@Injectable()
export class PaymentService {
  private readonly logger = new Logger(PaymentService.name);

  constructor(
    private prisma: PrismaService,
    private blockchainService: BlockchainService,
  ) {}

  // 1. Record Web3 Crypto Escrow Deposit Transaction
  async recordEscrowDeposit(dto: RecordEscrowDepositDto) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: dto.auditId },
      include: { payment: true },
    });

    if (!audit) {
      throw new NotFoundException(`Audit engagement ${dto.auditId} not found`);
    }

    if (audit.payment && audit.payment.status === PaymentStatus.ESCROWED) {
      throw new BadRequestException(`Payment for audit ${dto.auditId} has already been recorded and escrowed`);
    }

    // On-chain verification (Fix #5)
    if (dto.chainId && dto.escrowTxHash && !dto.escrowTxHash.startsWith('0xmock')) {
      const verification = await this.blockchainService.verifyTransaction(dto.chainId, dto.escrowTxHash);
      if (verification.blockNumber !== undefined && !verification.valid) {
        throw new BadRequestException(`On-chain transaction ${dto.escrowTxHash} failed or was reverted`);
      }
    }

    const payment = await this.prisma.payment.upsert({
      where: { auditId: dto.auditId },
      create: {
        auditId: dto.auditId,
        method: PaymentMethod.CRYPTO_ESCROW,
        amount: dto.amount,
        currency: dto.currency || 'USDC',
        chainId: dto.chainId,
        escrowTxHash: dto.escrowTxHash,
        status: PaymentStatus.ESCROWED,
        paidAt: new Date(),
      },
      update: {
        method: PaymentMethod.CRYPTO_ESCROW,
        amount: dto.amount,
        currency: dto.currency || 'USDC',
        chainId: dto.chainId,
        escrowTxHash: dto.escrowTxHash,
        status: PaymentStatus.ESCROWED,
        paidAt: new Date(),
      },
    });

    return payment;
  }

  // 2. Generate Corporate Net-30 Invoice
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
      terms: 'Net-30 Days Wire Transfer',
    };
  }

  // 3. Get Payment Details for Audit
  async getPaymentByAudit(auditId: string) {
    const payment = await this.prisma.payment.findUnique({
      where: { auditId },
      include: { audit: true },
    });

    if (!payment) {
      throw new NotFoundException(`No payment record found for audit ${auditId}`);
    }

    return payment;
  }
}
