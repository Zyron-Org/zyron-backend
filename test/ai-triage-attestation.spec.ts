import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import { AiAuditService } from '../src/scanner/ai-audit.service';
import {
  AiProviderFactory,
  GeminiProviderService,
  AnthropicProviderService,
  OpenAiProviderService,
  DeepSeekProviderService,
} from '../src/scanner/ai-providers';
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
  let mockGeminiProvider: any;

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

    mockGeminiProvider = {
      id: 'gemini',
      displayName: 'Google Gemini',
      isAvailable: vi.fn().mockReturnValue(true),
      getMissingConfigReason: vi.fn().mockReturnValue(null),
      analyzeContract: vi.fn().mockImplementation((contractFileName, code, staticFindings) => {
        const findings: any[] = [];
        for (const sf of staticFindings || []) {
          if (sf.ruleId === 'ZYRON-08-001') {
            findings.push({
              title: sf.title,
              severity: FindingSeverity.LOW,
              ruleId: sf.ruleId,
              decision: 'DISMISS_INTENDED_DESIGN',
              falsePositive: true,
              fpJustification: 'Flash Swap pattern with lock modifier.',
              pocScenario: 'Safety Proof: lock modifier prevents recursive reentry.',
            });
          } else if (sf.ruleId === 'ZYRON-02-003') {
            findings.push({
              title: sf.title,
              severity: FindingSeverity.INFORMATIONAL,
              ruleId: sf.ruleId,
              decision: 'DISMISS_INTENDED_DESIGN',
              falsePositive: true,
              fpJustification: 'Intentional 136-year modular wrap-around in TWAP.',
              pocScenario: 'Safety Proof: modular arithmetic ensures deterministic calculation.',
            });
          } else {
            findings.push({
              title: sf.title,
              severity: sf.severity,
              ruleId: sf.ruleId,
              decision: 'CONFIRMED',
              falsePositive: false,
            });
          }
        }
        return Promise.resolve({
          provider: 'gemini',
          modelUsed: 'Gemini (gemini-2.0-flash)',
          contractFileName,
          analysisSummary: `Gemini verified ${contractFileName}.`,
          findings,
        });
      }),
    };

    const mockEmptyProvider = (id: string, name: string) => ({
      id,
      displayName: name,
      isAvailable: vi.fn().mockReturnValue(false),
      getMissingConfigReason: vi.fn().mockReturnValue('Key not set'),
      analyzeContract: vi.fn(),
    });

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AiAuditService,
        AiProviderFactory,
        AdvanceStageService,
        AuditSanitizerService,
        { provide: GeminiProviderService, useValue: mockGeminiProvider },
        { provide: AnthropicProviderService, useValue: mockEmptyProvider('anthropic', 'Claude') },
        { provide: OpenAiProviderService, useValue: mockEmptyProvider('openai', 'OpenAI') },
        { provide: DeepSeekProviderService, useValue: mockEmptyProvider('deepseek', 'DeepSeek') },
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

      // 2. Verifies that the real Merkle root was persisted to Prisma
      expect(mockPrisma.auditRequest.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'ZYR-9481' },
          data: expect.objectContaining({
            merkleRoot: '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
          }),
        }),
      );

      // 3. Verifies that submitAutomatedAttestation was triggered
      expect(mockBlockchainService.submitAutomatedAttestation).toHaveBeenCalledWith('ZYR-9481');

      // 4. Verifies response contains the transaction hash and chain ID
      expect(result.onChainTxHash).toBe('0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef');
      expect(result.onChainChainId).toBe(421614);
    });

    it('should block advancing to COMPLETED if any OPEN critical vulnerability exists', async () => {
      mockPrisma.auditRequest.findUnique.mockResolvedValueOnce({
        ...mockAudit,
        findings: [
          {
            id: 'crit_open',
            displayId: 'ZYR-9481-003',
            severity: FindingSeverity.CRITICAL,
            status: FindingStatus.OPEN,
            falsePositive: false,
          },
        ],
      });

      await expect(
        advanceStageService.advanceStage('ZYR-9481', { stage: AuditStage.COMPLETED }),
      ).rejects.toThrow(/Open Critical or High severity findings/);
    });
  });
});
