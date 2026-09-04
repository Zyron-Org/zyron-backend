import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { RecordEscrowDepositDto } from '../dto/payment.dto';
import { PaymentMethod, PaymentStatus } from '../../common/enum';
import { BlockchainService } from '../../blockchain/blockchain.service';

@Injectable()
export class EscrowPaymentService {
  constructor(
    private prisma: PrismaService,
    private blockchainService: BlockchainService,
  ) {}

  async getPaymentByAudit(auditId: string) {
    const payment = await this.prisma.payment.findUnique({
      where: { auditId },
    });

    if (!payment) {
      throw new NotFoundException(`Payment details for audit ${auditId} not found`);
    }

    return payment;
  }

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
}
