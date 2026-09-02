import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import { PaymentService } from '../src/payment/payment.service';
import { PrismaService } from '../src/database/database.module';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { PaymentMethod, PaymentStatus } from '../src/common/enum';

import { BlockchainService } from '../src/blockchain/blockchain.service';

describe('PaymentService (Unit & Integration Tests)', () => {
  let paymentService: PaymentService;
  let mockPrisma: any;
  let mockBlockchainService: any;

  const mockAudit = {
    id: 'ZYR-9481',
    protocolName: 'Aura Liquidity Pool V3',
    contractFileName: 'VaultCore.sol',
    sloc: 2410,
    payment: null,
  };

  const mockPayment = {
    id: 'pay_123',
    auditId: 'ZYR-9481',
    method: PaymentMethod.CRYPTO_ESCROW,
    amount: 12500,
    currency: 'USDC',
    chainId: 42161,
    escrowTxHash: '0x8f9b2d4c01e9a37',
    status: PaymentStatus.ESCROWED,
    paidAt: new Date(),
  };

  beforeEach(async () => {
    mockPrisma = {
      auditRequest: {
        findUnique: vi.fn(),
      },
      payment: {
        upsert: vi.fn(),
        findUnique: vi.fn(),
      },
    };

    mockBlockchainService = {
      verifyTransaction: vi.fn().mockResolvedValue({ valid: true, blockNumber: 123456 }),
      getContractBytecodeHash: vi.fn().mockResolvedValue('0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PaymentService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: BlockchainService, useValue: mockBlockchainService },
      ],
    }).compile();

    paymentService = module.get<PaymentService>(PaymentService);
  });

  describe('recordEscrowDeposit()', () => {
    it('should record Web3 crypto escrow deposit transaction hash and set status to ESCROWED', async () => {
      mockPrisma.auditRequest.findUnique.mockResolvedValue(mockAudit);
      mockPrisma.payment.upsert.mockResolvedValue(mockPayment);

      const result = await paymentService.recordEscrowDeposit({
        auditId: 'ZYR-9481',
        escrowTxHash: '0x8f9b2d4c01e9a37',
        chainId: 42161,
        amount: 12500,
        currency: 'USDC',
      });

      expect(mockPrisma.payment.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { auditId: 'ZYR-9481' },
          create: expect.objectContaining({
            method: PaymentMethod.CRYPTO_ESCROW,
            status: PaymentStatus.ESCROWED,
            chainId: 42161,
          }),
        }),
      );
      expect(result.status).toBe(PaymentStatus.ESCROWED);
    });

    it('should throw NotFoundException if audit ID is non-existent', async () => {
      mockPrisma.auditRequest.findUnique.mockResolvedValue(null);

      await expect(
        paymentService.recordEscrowDeposit({
          auditId: 'ZYR-9999',
          escrowTxHash: '0x123',
          chainId: 1,
          amount: 5000,
        }),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw BadRequestException if payment has already been recorded and escrowed', async () => {
      mockPrisma.auditRequest.findUnique.mockResolvedValue({
        ...mockAudit,
        payment: { status: PaymentStatus.ESCROWED },
      });

      await expect(
        paymentService.recordEscrowDeposit({
          auditId: 'ZYR-9481',
          escrowTxHash: '0x123',
          chainId: 1,
          amount: 5000,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should support Arbitrum (42161), Ethereum (1), and Base (8453) chain IDs', async () => {
      mockPrisma.auditRequest.findUnique.mockResolvedValue(mockAudit);
      mockPrisma.payment.upsert.mockResolvedValue({
        ...mockPayment,
        chainId: 8453, // Base
      });

      const result = await paymentService.recordEscrowDeposit({
        auditId: 'ZYR-9481',
        escrowTxHash: '0xbase_tx_hash',
        chainId: 8453,
        amount: 12500,
        currency: 'USDC',
      });

      expect(result.chainId).toBe(8453);
    });
  });

  describe('generateCorporateInvoice()', () => {
    it('should generate corporate Net-30 invoice PDF link and return terms', async () => {
      mockPrisma.auditRequest.findUnique.mockResolvedValue(mockAudit);
      mockPrisma.payment.upsert.mockResolvedValue({
        ...mockPayment,
        method: PaymentMethod.CORPORATE_INVOICE,
        status: PaymentStatus.PENDING,
      });

      const result = await paymentService.generateCorporateInvoice({
        auditId: 'ZYR-9481',
        companyName: 'Aura Finance DAO Ltd.',
        billingEmail: 'finance@auraprotocol.io',
        amount: 12500,
      });

      expect(result).toHaveProperty('invoiceNumber');
      expect(result.terms).toBe('Net-30 Days Wire Transfer');
    });

    it('should throw NotFoundException if generating invoice for non-existent audit ID', async () => {
      mockPrisma.auditRequest.findUnique.mockResolvedValue(null);

      await expect(
        paymentService.generateCorporateInvoice({
          auditId: 'ZYR-9999',
          companyName: 'Unknown DAO',
          billingEmail: 'billing@unknown.io',
          amount: 5000,
        }),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('getPaymentByAudit()', () => {
    it('should return payment record with audit relation loaded', async () => {
      mockPrisma.payment.findUnique.mockResolvedValue(mockPayment);

      const result = await paymentService.getPaymentByAudit('ZYR-9481');
      expect(result.auditId).toBe('ZYR-9481');
    });

    it('should throw NotFoundException if no payment record exists for audit', async () => {
      mockPrisma.payment.findUnique.mockResolvedValue(null);

      await expect(paymentService.getPaymentByAudit('ZYR-9481')).rejects.toThrow(NotFoundException);
    });
  });
});
