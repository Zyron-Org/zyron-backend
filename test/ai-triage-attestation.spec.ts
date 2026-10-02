import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import { AiAuditService } from '../src/scanner/ai-audit.service';
import { AiLocalReasonerService } from '../src/scanner/services/ai-local-reasoner.service';
import { AiGeminiClientService } from '../src/scanner/services/ai-gemini-client.service';
import { AdvanceStageService } from '../src/audit/services/advance-stage.service';
import { PrismaService } from '../src/database/database.module';
import { BlockchainService } from '../src/blockchain/blockchain.service';
import { AuditSanitizerService } from '../src/audit/services/audit-sanitizer.service';
import { AuditStage, FindingSeverity, FindingStatus } from '../src/common/enum';

describe('AI Review & On-Chain Attestation Pipeline (Topic 2)', () => {
  let aiAuditService: AiAuditService;
  let advanceStageService: AdvanceStageService;
  let mockPrisma: any;
  let mockBlockchainService: any;
  let mockGeminiClient: any;

  const mockAudit = {
    id: 'ZYR-9481',
    protocolName: 'Uniswap V2 Clone',
    contractFileName: 'Pair.sol',
    gitCommit: 'abc1234',
    sloc: 500,
    stage: AuditStage.IN_REVIEW,
    stageNumber: 3,
    findings: [
      {
        id: 'find_1',
        displayId: 'ZYR-9481-001',
        severity: FindingSeverity.CRITICAL,
        status: FindingStatus.RESOLVED,
        falsePositive: false,
      },
      {
        id: 'find_2',
        displayId: 'ZYR-9481-002',
        severity: FindingSeverity.MEDIUM,
        status: FindingStatus.RESOLVED,
        falsePositive: false,
      },
    ],
  };

  beforeEach(async () => {
    mockPrisma = {
      auditRequest: {
        findUnique: vi.fn().mockResolvedValue(mockAudit),
        update: vi.fn().mockImplementation((args) => Promise.resolve({ ...mockAudit, ...args.data })),
      },
      auditRound: {
        updateMany: vi.fn().mockResolvedValue({ count: 1 }),
      },
    };

    mockBlockchainService = {
      computeFindingsMerkleRoot: vi.fn().mockReturnValue('0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'),
      submitAutomatedAttestation: vi.fn().mockResolvedValue({
        txHash: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        chainId: 421614,
      }),
      getContractBytecodeHash: vi.fn().mockResolvedValue(null),
    };

    mockGeminiClient = {
      callGeminiApi: vi.fn().mockImplementation((fileName, code, apiKey, staticFindings, context) => {
        return Promise.resolve(
          new AiLocalReasonerService(null as any).runLocalAiAnalysis(
            fileName,
            code,
            'Gemini 1.5 Pro',
            staticFindings,
            context,
          ),
        );
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AiAuditService,
        AiLocalReasonerService,
        AdvanceStageService,
        AuditSanitizerService,
        { provide: AiGeminiClientService, useValue: mockGeminiClient },
        { provide: PrismaService, useValue: mockPrisma },
        { provide: BlockchainService, useValue: mockBlockchainService },
      ],
    }).compile();

    aiAuditService = module.get<AiAuditService>(AiAuditService);
    advanceStageService = module.get<AdvanceStageService>(AdvanceStageService);
  });

  describe('AI Contextual Triage of Static Findings', () => {
    it('should triage Flash Swap reentrancy as an intended design pattern when lock modifier is present', async () => {
      const code = `
        contract UniswapV2Pair {
          uint private unlocked = 1;
          modifier lock() {
            require(unlocked == 1);
            unlocked = 0;
            _;
            unlocked = 1;
          }
          function swap() external lock {
            token.call("");
            reserve0 = 100;
          }
        }
      `;

      const candidateStaticFindings = [
        {
          ruleId: 'ZYRON-08-001',
          title: 'State-Change After External Call (Reentrancy Vulnerability)',
          severity: 'CRITICAL',
          line: 12,
          description: 'External call before reserve update.',
        },
      ];

      const triageResult = await aiAuditService.triageStaticFindingsWithAi(
        'UniswapV2Pair.sol',
        code,
        candidateStaticFindings,
        { protocolName: 'Uniswap V2', businessGoals: 'Decentralized AMM with Flash Swaps' },
      );

      expect(triageResult.findings.length).toBe(1);
      const reentrancyTriage = triageResult.findings[0];

      // Confirms AI contextual triage marked it as an intended design pattern / false positive
      expect(reentrancyTriage.decision).toBe('DISMISS_INTENDED_DESIGN');
      expect(reentrancyTriage.falsePositive).toBe(true);
      expect(reentrancyTriage.severity).toBe(FindingSeverity.LOW);
      expect(reentrancyTriage.fpJustification).toContain('Flash Swap');
      expect(reentrancyTriage.pocScenario).toContain('Safety Proof');
    });

    it('should triage modular timestamp downcasting as intended protocol overflow in TWAP', async () => {
      const code = `
        contract UniswapV2Pair {
          function _update() private {
            uint32 blockTimestamp = uint32(block.timestamp % 2**32);
          }
        }
      `;

      const candidateStaticFindings = [
        {
          ruleId: 'ZYRON-02-003',
          title: 'Unsafe Type Downcasting',
          severity: 'MEDIUM',
          line: 4,
          description: 'Explicit cast to uint32 without safeCast.',
        },
      ];

      const triageResult = await aiAuditService.triageStaticFindingsWithAi(
        'UniswapV2Pair.sol',
        code,
        candidateStaticFindings,
      );

      const downcastTriage = triageResult.findings[0];
      expect(downcastTriage.decision).toBe('DISMISS_INTENDED_DESIGN');
      expect(downcastTriage.falsePositive).toBe(true);
      expect(downcastTriage.fpJustification).toContain('136-year');
    });
  });

  describe('On-Chain Cryptographic Attestation on Stage Completion', () => {
    it('should compute Merkle root from resolved findings and submit attestation upon completion', async () => {
      const result = await advanceStageService.advanceStage('ZYR-9481', {
        stage: AuditStage.COMPLETED,
      });

      // 1. Verifies that computeFindingsMerkleRoot was called with audit findings
      expect(mockBlockchainService.computeFindingsMerkleRoot).toHaveBeenCalledWith(
        expect.arrayContaining([
          expect.objectContaining({ displayId: 'ZYR-9481-001', severity: FindingSeverity.CRITICAL }),
          expect.objectContaining({ displayId: 'ZYR-9481-002', severity: FindingSeverity.MEDIUM }),
        ]),
      );

      // 2. Verifies that submitAutomatedAttestation was triggered
      expect(mockBlockchainService.submitAutomatedAttestation).toHaveBeenCalledWith('ZYR-9481');

      // 3. Verifies that returned audit object contains attestation proof
      expect(result.onChainTxHash).toBe('0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef');
      expect(result.attestationStatus).toBe('CONFIRMED');
      expect(result.merkleRoot).toBe('0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890');
    });

    it('should block transition to COMPLETED if open critical findings exist', async () => {
      mockPrisma.auditRequest.findUnique.mockResolvedValueOnce({
        ...mockAudit,
        findings: [
          {
            id: 'find_unresolved',
            displayId: 'ZYR-9481-001',
            severity: FindingSeverity.CRITICAL,
            status: FindingStatus.OPEN,
            falsePositive: false,
          },
        ],
      });

      await expect(
        advanceStageService.advanceStage('ZYR-9481', { stage: AuditStage.COMPLETED }),
      ).rejects.toThrow(/Open Critical or High severity findings must be resolved/i);
    });
  });
});
