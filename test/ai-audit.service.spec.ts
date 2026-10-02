import { describe, it, expect, beforeEach } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import { AiAuditService } from '../src/scanner/ai-audit.service';
import { AiLocalReasonerService } from '../src/scanner/services/ai-local-reasoner.service';
import { AiGeminiClientService } from '../src/scanner/services/ai-gemini-client.service';

describe('AiAuditService (Unit Tests)', () => {
  let aiAuditService: AiAuditService;

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
    const mockGeminiClient = {
      callGeminiApi: vi.fn().mockResolvedValue({
        modelUsed: 'Gemini 1.5 Pro',
        findings: [
          {
            title: 'CRITICAL: Classic State-Reentrancy Vulnerability',
            severity: 'CRITICAL',
            cvss: 'CVSS 9.8',
            taxonomy: 'SWC-107 · CWE-841',
            location: 'VaultCore.sol:withdrawAll',
            impact: 'DRAINAGE OF ENTIRE CONTRACT FUNDS VIA RECURSIVE REENTRANCY',
            description: 'The contract sends ETH before updating balances.',
            vulnerableCode: 'msg.sender.call{value: amount}("");',
            remediatedCode: 'balances[msg.sender] = 0;\n(bool s, ) = msg.sender.call{value: amount}("");',
          },
        ],
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AiAuditService,
        AiLocalReasonerService,
        { provide: AiGeminiClientService, useValue: mockGeminiClient },
      ],
    }).compile();

    aiAuditService = module.get<AiAuditService>(AiAuditService);
  });

  describe('analyzeContractWithAi()', () => {
    it('should analyze smart contract source code and return AI-generated vulnerability findings', async () => {
      const result = await aiAuditService.analyzeContractWithAi('VaultCore.sol', sampleContract);

      expect(result).toHaveProperty('modelUsed');
      expect(result).toHaveProperty('findings');
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.findings[0]).toHaveProperty('title');
      expect(result.findings[0]).toHaveProperty('severity');
      expect(result.findings[0]).toHaveProperty('remediatedCode');
    });

    it('should handle multi-file contract analysis seamlessly', async () => {
      const result = await aiAuditService.analyzeContractWithAi('VaultCore.sol', sampleContract, 'Gemini 1.5 Pro');

      expect(result.modelUsed).toContain('Gemini');
      expect(result.findings[0].severity).toBeDefined();
    });
  });
});
