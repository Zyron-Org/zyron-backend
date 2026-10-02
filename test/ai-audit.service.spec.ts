import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import { ServiceUnavailableException } from '@nestjs/common';
import { AiAuditService } from '../src/scanner/ai-audit.service';
import {
  AiProviderFactory,
  GeminiProviderService,
  AnthropicProviderService,
  OpenAiProviderService,
  DeepSeekProviderService,
} from '../src/scanner/ai-providers';
import { PrismaService } from '../src/database/database.module';

describe('AiAuditService (Multi-Model Cloud Architecture)', () => {
  let aiAuditService: AiAuditService;
  let mockPrisma: any;
  let mockGemini: any;
  let mockAnthropic: any;
  let mockOpenAi: any;
  let mockDeepSeek: any;

  const sampleContract = `
    pragma solidity ^0.8.20;
    contract VaultCore {
      mapping(address => uint256) public balances;
      function withdrawAll() external {
        uint256 amount = balances[msg.sender];
        (bool s, ) = msg.sender.call{value: amount}("");
        require(s);
        balances[msg.sender] = 0;
      }
    }
  `;

  beforeEach(async () => {
    mockPrisma = {
      auditRequest: {
        findUnique: vi.fn(),
        update: vi.fn().mockResolvedValue({ id: 'ZYR-9481' }),
      },
    };

    mockGemini = {
      id: 'gemini',
      displayName: 'Google Gemini',
      isAvailable: vi.fn().mockReturnValue(true),
      getMissingConfigReason: vi.fn().mockReturnValue(null),
      analyzeContract: vi.fn().mockResolvedValue({
        provider: 'gemini',
        modelUsed: 'Gemini (gemini-2.0-flash)',
        contractFileName: 'VaultCore.sol',
        analysisSummary: 'Gemini identified reentrancy vulnerability.',
        findings: [
          {
            title: 'CRITICAL: Classic State-Reentrancy Vulnerability',
            severity: 'CRITICAL',
            cvss: 'CVSS 9.8',
            taxonomy: 'SWC-107 · CWE-841',
            location: 'VaultCore.sol:16',
            impact: 'Drainage of contract balances',
            description: 'State variable updated after external transfer.',
            decision: 'CONFIRMED',
            pocScenario: 'Attacker contracts reenter withdrawAll()',
            remediatedCode: 'balances[msg.sender] = 0;\n(bool s, ) = msg.sender.call{value: amount}("");',
          },
        ],
      }),
    };

    mockAnthropic = {
      id: 'anthropic',
      displayName: 'Anthropic Claude',
      isAvailable: vi.fn().mockReturnValue(true),
      getMissingConfigReason: vi.fn().mockReturnValue(null),
      analyzeContract: vi.fn().mockResolvedValue({
        provider: 'anthropic',
        modelUsed: 'Claude (claude-3-7-sonnet-20250219)',
        contractFileName: 'VaultCore.sol',
        analysisSummary: 'Claude verified contract.',
        findings: [],
      }),
    };

    mockOpenAi = {
      id: 'openai',
      displayName: 'OpenAI',
      isAvailable: vi.fn().mockReturnValue(true),
      getMissingConfigReason: vi.fn().mockReturnValue(null),
      analyzeContract: vi.fn().mockResolvedValue({
        provider: 'openai',
        modelUsed: 'OpenAI (gpt-4o)',
        contractFileName: 'VaultCore.sol',
        analysisSummary: 'GPT-4o audit complete.',
        findings: [],
      }),
    };

    mockDeepSeek = {
      id: 'deepseek',
      displayName: 'DeepSeek',
      isAvailable: vi.fn().mockReturnValue(false),
      getMissingConfigReason: vi.fn().mockReturnValue('Missing DEEPSEEK_API_KEY in environment variables.'),
      analyzeContract: vi.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AiAuditService,
        AiProviderFactory,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: GeminiProviderService, useValue: mockGemini },
        { provide: AnthropicProviderService, useValue: mockAnthropic },
        { provide: OpenAiProviderService, useValue: mockOpenAi },
        { provide: DeepSeekProviderService, useValue: mockDeepSeek },
      ],
    }).compile();

    aiAuditService = module.get<AiAuditService>(AiAuditService);
  });

  describe('Multi-Model Provider Routing', () => {
    it('should route to Gemini by default and return triaged findings', async () => {
      const result = await aiAuditService.analyzeContractWithAi('VaultCore.sol', sampleContract);

      expect(mockGemini.analyzeContract).toHaveBeenCalled();
      expect(result.provider).toBe('gemini');
      expect(result.findings.length).toBe(1);
      expect(result.findings[0].decision).toBe('CONFIRMED');
    });

    it('should dynamically route to Anthropic Claude when requested', async () => {
      const result = await aiAuditService.analyzeContractWithAi('VaultCore.sol', sampleContract, 'anthropic');

      expect(mockAnthropic.analyzeContract).toHaveBeenCalled();
      expect(result.provider).toBe('anthropic');
    });

    it('should dynamically route to OpenAI GPT-4o when requested', async () => {
      const result = await aiAuditService.analyzeContractWithAi('VaultCore.sol', sampleContract, 'openai');

      expect(mockOpenAi.analyzeContract).toHaveBeenCalled();
      expect(result.provider).toBe('openai');
    });

    it('should list all supported providers and their availability status', () => {
      const providers = aiAuditService.getSupportedProviders();

      expect(providers).toHaveLength(4);
      expect(providers.find((p) => p.id === 'gemini')?.available).toBe(true);
      expect(providers.find((p) => p.id === 'anthropic')?.available).toBe(true);
      expect(providers.find((p) => p.id === 'deepseek')?.available).toBe(false);
    });
  });

  describe('Cloud Failure & Audit Pausing', () => {
    it('should pause the audit and throw ServiceUnavailableException when all cloud providers are offline', async () => {
      mockGemini.isAvailable.mockReturnValue(false);
      mockAnthropic.isAvailable.mockReturnValue(false);
      mockOpenAi.isAvailable.mockReturnValue(false);
      mockDeepSeek.isAvailable.mockReturnValue(false);

      await expect(
        aiAuditService.analyzeContractWithAi(
          'VaultCore.sol',
          sampleContract,
          'gemini',
          [],
          undefined,
          'ZYR-9481',
        ),
      ).rejects.toThrow(ServiceUnavailableException);

      expect(mockPrisma.auditRequest.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'ZYR-9481' },
          data: expect.objectContaining({
            stage: 'FAILED',
            failureReason: expect.stringContaining('AI Review Paused'),
          }),
        }),
      );
    });

    it('should allow admin to resume a previously paused audit job once key is restored', async () => {
      mockPrisma.auditRequest.findUnique.mockResolvedValue({
        id: 'ZYR-9481',
        contractFileName: 'VaultCore.sol',
        sourceCode: sampleContract,
        findings: [],
      });

      const res = await aiAuditService.resumeAuditAi('ZYR-9481', 'openai');

      expect(mockPrisma.auditRequest.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'ZYR-9481' },
          data: expect.objectContaining({
            stage: 'IN_REVIEW',
            failureReason: null,
          }),
        }),
      );
      expect(res.provider).toBe('openai');
    });
  });
});
