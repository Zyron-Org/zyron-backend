import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import { AiAuditService } from '../src/scanner/ai-audit.service';
import { FindingSeverity } from '../src/common/enum';

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
    const module: TestingModule = await Test.createTestingModule({
      providers: [AiAuditService],
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
