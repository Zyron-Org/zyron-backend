import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import { AuditService } from '../src/audit/audit.service';
import { CreateAuditService } from '../src/audit/services/create-audit.service';
import { GetAuditsService } from '../src/audit/services/get-audits.service';
import { ClaimTicketService } from '../src/audit/services/claim-ticket.service';
import { AdvanceStageService } from '../src/audit/services/advance-stage.service';
import { FindingsService } from '../src/audit/services/findings.service';
import { CommentsService } from '../src/audit/services/comments.service';
import { AuditSanitizerService } from '../src/audit/services/audit-sanitizer.service';
import { PrismaService } from '../src/database/database.module';
import { BadRequestException, ConflictException } from '@nestjs/common';
import { AuditStage, UserRole, FindingSeverity, FindingStatus } from '../src/common/enum';
import { BlockchainService } from '../src/blockchain/blockchain.service';
import { ScanOrchestratorService } from '../src/scanner/services/scan-orchestrator.service';

import { AutoAssignService } from '../src/audit/services/auto-assign.service';
import { GithubService } from '../src/integrations/github.service';

describe('AuditService (Unit Tests)', () => {
  let auditService: AuditService;
  let mockPrisma: any;
  let mockBlockchainService: any;
  let mockScanOrchestrator: any;

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
        findMany: vi.fn().mockResolvedValue([]),
        findUnique: vi.fn(),
        update: vi.fn(),
      },
      user: {
        findMany: vi.fn().mockResolvedValue([]),
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

    mockScanOrchestrator = {
      runScan: vi.fn().mockResolvedValue({ scanJob: { id: 'job_1' }, findingsCount: 0 }),
    };

    const mockGithubService = {
      getRepositorySolidityContracts: vi.fn().mockResolvedValue({
        contracts: ['contracts/VaultCore.sol'],
        total: 1,
        hasBlockchainFiles: true,
        isInspected: true,
      }),
      parseRepoUrl: vi.fn().mockReturnValue({ owner: 'aura-finance', repo: 'core-vaults' }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuditService,
        CreateAuditService,
        GetAuditsService,
        ClaimTicketService,
        AdvanceStageService,
        FindingsService,
        CommentsService,
        AutoAssignService,
        AuditSanitizerService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: BlockchainService, useValue: mockBlockchainService },
        { provide: ScanOrchestratorService, useValue: mockScanOrchestrator },
        { provide: GithubService, useValue: mockGithubService },
      ],
    }).compile();

    auditService = module.get<AuditService>(AuditService);
  });

  describe('createAudit()', () => {
    it('should generate ticket ID ZYR-9481 for first audit with valid smart contract', async () => {
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

    it('should reject non-blockchain file when no blockchain markers exist', async () => {
      await expect(
        auditService.createAudit('usr_client', 'org_123', {
          protocolName: 'React Todo App',
          contractFileName: 'index.tsx',
          compilerVersion: 'v0.8.20',
          sloc: 500,
          sourceCode: 'import React from "react"; export default function App() {}',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject audit if GitHub repository contains zero blockchain contract files', async () => {
      const moduleRef = await Test.createTestingModule({
        providers: [
          AuditService,
          CreateAuditService,
          GetAuditsService,
          ClaimTicketService,
          AdvanceStageService,
          FindingsService,
          CommentsService,
          AutoAssignService,
          AuditSanitizerService,
          { provide: PrismaService, useValue: mockPrisma },
          { provide: BlockchainService, useValue: mockBlockchainService },
          { provide: ScanOrchestratorService, useValue: mockScanOrchestrator },
          {
            provide: GithubService,
            useValue: {
              getRepositorySolidityContracts: vi.fn().mockResolvedValue({
                contracts: [],
                total: 0,
                hasBlockchainFiles: false,
                isInspected: true,
              }),
            },
          },
        ],
      }).compile();

      const service = moduleRef.get<AuditService>(AuditService);
      await expect(
        service.createAudit('usr_client', 'org_123', {
          protocolName: 'Frontend Web App',
          contractFileName: 'Contract.sol',
          compilerVersion: 'v0.8.20',
          sloc: 200,
          githubRepoUrl: 'https://github.com/someone/react-app',
        }),
      ).rejects.toThrow(BadRequestException);
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
