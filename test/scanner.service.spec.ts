import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import { ScannerService } from '../src/scanner/scanner.service';
import { TokenScannerService } from '../src/scanner/token-scanner.service';
import { PrismaService } from '../src/database/database.module';
import { GithubService } from '../src/integrations/github.service';
import { AuditStage, FindingSeverity, FindingStatus } from '../src/common/enum';

import { AiAuditService } from '../src/scanner/ai-audit.service';

describe('ScannerService & TokenScannerService (Unit Tests)', () => {
  let scannerService: ScannerService;
  let tokenScannerService: TokenScannerService;
  let mockPrisma: any;
  let mockGithubService: any;

  const mockAudit = {
    id: 'ZYR-9481',
    protocolName: 'Aura Liquidity Pool V3',
    contractFileName: 'VaultCore.sol',
    compilerVersion: 'v0.8.20',
    sloc: 2410,
    stage: AuditStage.PENDING,
    stageNumber: 1,
    findings: [],
  };

  const mockTokenCodeWithHoneypot = `
    pragma solidity ^0.8.20;
    contract VulnerableToken {
      mapping(address => uint256) public balanceOf;
      address public owner;
      bool public isPaused;

      function mint(address to, uint256 amount) external {
        require(msg.sender == owner);
        balanceOf[to] += amount;
      }

      function pause() external {
        require(msg.sender == owner);
        isPaused = true;
      }

      function transfer(address to, uint256 amount) external returns (bool) {
        require(!isPaused, "Paused");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount * 50 / 100; // 50% sell tax!
        return true;
      }
    }
  `;

  beforeEach(async () => {
    mockPrisma = {
      auditRequest: {
        findUnique: vi.fn().mockResolvedValue(mockAudit),
        update: vi.fn().mockResolvedValue({ ...mockAudit, stage: AuditStage.IN_REVIEW, stageNumber: 3 }),
        count: vi.fn().mockResolvedValue(0),
        create: vi.fn().mockResolvedValue({ ...mockAudit, id: 'ZYR-9482' }),
      },
      scanJob: {
        create: vi.fn().mockResolvedValue({ id: 'job_123', tool: 'slither', status: 'queued' }),
        update: vi.fn().mockResolvedValue({ id: 'job_123', status: 'completed' }),
        findMany: vi.fn().mockResolvedValue([]),
      },
      finding: {
        create: vi.fn().mockImplementation((args) => Promise.resolve({ id: 'find_1', ...args.data })),
        findMany: vi.fn().mockResolvedValue([]),
      },
    };

    mockGithubService = {
      parseRepoUrl: vi.fn().mockReturnValue({ owner: 'auraprotocol', repo: 'aura-contracts' }),
      fetchRepoTree: vi.fn().mockResolvedValue(['VaultCore.sol', 'Token.sol']),
      fetchFileContent: vi.fn().mockResolvedValue(mockTokenCodeWithHoneypot),
      postCommentToIssue: vi.fn().mockResolvedValue({ id: 12345, html_url: 'https://github.com/auraprotocol/aura-contracts/issues/1#issuecomment-123' }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ScannerService,
        TokenScannerService,
        AiAuditService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: GithubService, useValue: mockGithubService },
      ],
    }).compile();

    scannerService = module.get<ScannerService>(ScannerService);
    tokenScannerService = module.get<TokenScannerService>(TokenScannerService);
  });

  describe('TokenScannerService', () => {
    it('should detect minting privileges, pause control, and transfer tax in token code', () => {
      const result = tokenScannerService.analyzeTokenCode('VulnerableToken.sol', mockTokenCodeWithHoneypot);

      expect(result.tokenRiskScore).toBeGreaterThanOrEqual(40);
      expect(result.findings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ title: expect.stringMatching(/Minting/i) }),
          expect.objectContaining({ title: expect.stringMatching(/Pause/i) }),
          expect.objectContaining({ title: expect.stringMatching(/Tax/i) }),
        ]),
      );
    });

    it('should pass clean standard ERC-20 contract without flags', () => {
      const cleanCode = `
        pragma solidity ^0.8.20;
        contract CleanToken {
          mapping(address => uint256) public balanceOf;
          function transfer(address to, uint256 amount) external returns (bool) {
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
            return true;
          }
        }
      `;

      const result = tokenScannerService.analyzeTokenCode('CleanToken.sol', cleanCode);
      expect(result.tokenRiskScore).toBe(0);
      expect(result.findings).toHaveLength(0);
    });
  });

  describe('ScannerService', () => {
    it('should create ScanJob, run analysis rules, and populate findings into database', async () => {
      const scanJob = await scannerService.runScan('ZYR-9481', mockTokenCodeWithHoneypot);

      expect(mockPrisma.scanJob.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            auditId: 'ZYR-9481',
            status: 'running',
          }),
        }),
      );
      expect(mockPrisma.finding.create).toHaveBeenCalled();
      expect(mockPrisma.scanJob.update).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'job_123' },
          data: expect.objectContaining({ status: 'completed' }),
        }),
      );
    });

    it('should handle @zyron-bot audit mention from GitHub webhook and reply with findings comment', async () => {
      const webhookPayload = {
        action: 'created',
        issue: { number: 42 },
        comment: {
          id: 999,
          body: '@zyron-bot audit please review VaultCore.sol',
          user: { login: 'alex-vance' },
        },
        repository: {
          html_url: 'https://github.com/auraprotocol/aura-contracts',
          name: 'aura-contracts',
          owner: { login: 'auraprotocol' },
        },
      };

      const result = await scannerService.processGithubBotMention(webhookPayload);

      expect(result.processed).toBe(true);
      expect(mockGithubService.postCommentToIssue).toHaveBeenCalledWith(
        'auraprotocol',
        'aura-contracts',
        42,
        expect.stringMatching(/Zyron AI Security Bot/i),
      );
    });
  });
});
