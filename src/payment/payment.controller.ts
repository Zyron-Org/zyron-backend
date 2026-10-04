import { Controller, Post, Get, Body, Param, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { PaymentService } from './payment.service';
import { RecordEscrowDepositDto, GenerateInvoiceDto } from './dto/payment.dto';
import { JwtAuthGuard } from '../common/guards';
import { Public } from '../common/decorators';

@ApiTags('Payments & Access Model')
@ApiBearerAuth()
@Controller('payments')
@UseGuards(JwtAuthGuard)
export class PaymentController {
  constructor(private readonly paymentService: PaymentService) {}

  @Public()
  @Get('model')
  @ApiOperation({ summary: 'Get current platform payment and pricing model' })
  async getPaymentModel() {
    return {
      isFreeBeta: true,
      model: 'FREE_PUBLIC_BETA',
      message: 'All smart contract security audits and on-chain attestations are currently 100% free.',
    };
  }

  @Post('escrow')
  @ApiOperation({ summary: 'Deprecated: Web3 crypto escrow deposit' })
  @ApiResponse({ status: 200, description: 'Platform is free — no escrow required' })
  async recordEscrowDeposit(@Body() dto: RecordEscrowDepositDto) {
    return {
      isFreeBeta: true,
      message: 'Zyron is currently 100% free. No escrow deposit required.',
      auditId: dto.auditId,
    };
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
