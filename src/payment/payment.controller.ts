import { Controller, Post, Get, Body, Param, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { PaymentService } from './payment.service';
import { RecordEscrowDepositDto, GenerateInvoiceDto } from './dto/payment.dto';
import { JwtAuthGuard } from '../common/guards';

@ApiTags('Payments & Escrow Settlement')
@ApiBearerAuth()
@Controller('payments')
@UseGuards(JwtAuthGuard)
export class PaymentController {
  constructor(private readonly paymentService: PaymentService) {}

  @Post('escrow')
  @ApiOperation({ summary: 'Record Web3 crypto escrow deposit transaction hash (USDC/USDT)' })
  @ApiResponse({ status: 201, description: 'Payment recorded and escrow status set to ESCROWED' })
  async recordEscrowDeposit(@Body() dto: RecordEscrowDepositDto) {
    return this.paymentService.recordEscrowDeposit(dto);
  }

  @Post('invoice')
  @ApiOperation({ summary: 'Generate corporate Net-30 wire transfer PDF invoice' })
  @ApiResponse({ status: 201, description: 'Invoice generated with download URL and Net-30 payment terms' })
  async generateCorporateInvoice(@Body() dto: GenerateInvoiceDto) {
    return this.paymentService.generateCorporateInvoice(dto);
  }

  @Get('audit/:auditId')
  @ApiOperation({ summary: 'Get payment status & transaction details for an audit' })
  async getPaymentByAudit(@Param('auditId') auditId: string) {
    return this.paymentService.getPaymentByAudit(auditId);
  }
}
