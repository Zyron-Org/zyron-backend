import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import { AuditService } from '../src/audit/audit.service';
import { PrismaService } from '../src/database/database.module';
import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { AuditStage, UserRole, FindingSeverity, FindingStatus } from '../src/common/enum';

import { BlockchainService } from '../src/blockchain/blockchain.service';

describe('AuditService (Unit Tests)', () => {
  let auditService: AuditService;
  let mockPrisma: any;
  let mockBlockchainService: any;

  const mockAudit = {
    id: 'ZYR-9481',
    protocolName: 'Aura Liquidity Pool V3',
    contractFileName: 'VaultCore.sol',
    compilerVersion: 'v0.8.20',
    sloc: 2410,
    stage: AuditStage.PENDING,
    stageNumber: 1,
    network: 'Ethereum Mainnet',
    submittedById: 'usr_client',
    leadAuditorId: null,
    peerAuditorId: null,
    findings: [],
    submittedBy: { id: 'usr_client', email: 'client@auraprotocol.io', name: 'Aura DAO' },
  };

  beforeEach(async () => {
    mockPrisma = {
      auditRequest: {
        count: vi.fn().mockResolvedValue(0),
        create: vi.fn(),
        findMany: vi.fn(),
        findUnique: vi.fn(),
        update: vi.fn(),
      },
      finding: {
        create: vi.fn(),
        findUnique: vi.fn(),
        findMany: vi.fn(),
        update: vi.fn(),
      },
      comment: {
        create: vi.fn(),
        findMany: vi.fn(),
      },
    };

    mockBlockchainService = {
      verifyTransaction: vi.fn().mockResolvedValue({ valid: true, blockNumber: 123456 }),
      getContractBytecodeHash: vi.fn().mockResolvedValue('0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuditService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: BlockchainService, useValue: mockBlockchainService },
      ],
    }).compile();

    auditService = module.get<AuditService>(AuditService);
  });

  describe('createAudit()', () => {
    it('should generate ticket ID ZYR-9481 for first audit', async () => {
      mockPrisma.auditRequest.count.mockResolvedValue(0);
      mockPrisma.auditRequest.create.mockResolvedValue(mockAudit);

      const result = await auditService.createAudit('usr_client', 'org_123', {
        protocolName: 'Aura Liquidity Pool V3',
        contractFileName: 'VaultCore.sol',
        compilerVersion: 'v0.8.20',
        sloc: 2410,
      });

      expect(mockPrisma.auditRequest.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            id: 'ZYR-9481',
            stage: AuditStage.PENDING,
            stageNumber: 1,
          }),
        }),
      );
      expect(result.id).toBe('ZYR-9481');
    });
  });

  describe('claimTicket()', () => {
    it('should assign auditor as leadAuditor and advance stage to IN_REVIEW', async () => {
      mockPrisma.auditRequest.findUnique.mockResolvedValue({ ...mockAudit, leadAuditorId: null });
      mockPrisma.auditRequest.update.mockResolvedValue({
        ...mockAudit,
        leadAuditorId: 'usr_auditor',
        stage: AuditStage.IN_REVIEW,
        stageNumber: 3,
      });

      const result = await auditService.claimTicket('ZYR-9481', 'usr_auditor');
      expect(result.stage).toBe(AuditStage.IN_REVIEW);
      expect(result.leadAuditorId).toBe('usr_auditor');
    });

    it('should throw ConflictException if audit ticket is already claimed', async () => {
      mockPrisma.auditRequest.findUnique.mockResolvedValue({
        ...mockAudit,
        leadAuditorId: 'existing_auditor',
      });

      await expect(auditService.claimTicket('ZYR-9481', 'usr_auditor')).rejects.toThrow(ConflictException);
    });
  });

  describe('advanceStage()', () => {
    it('should throw BadRequestException when attempting to set stage to COMPLETED with open Critical findings', async () => {
      mockPrisma.auditRequest.findUnique.mockResolvedValue({
        ...mockAudit,
        findings: [
          {
            id: 'find_1',
            severity: FindingSeverity.CRITICAL,
            status: FindingStatus.OPEN,
          },
        ],
      });

      await expect(
        auditService.advanceStage('ZYR-9481', { stage: AuditStage.COMPLETED }),
      ).rejects.toThrow(BadRequestException);
    });
  });
});
