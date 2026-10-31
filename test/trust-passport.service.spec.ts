import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import { TrustPassportService } from '../src/auth/services/trust-passport.service';
import { PrismaService } from '../src/database/database.module';
import { EvidenceHasherService } from '../src/blockchain/services/evidence-hasher.service';
import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { ZYRON_AI_AUDITOR_001 } from '../src/auth/constants/ai-auditor.constant';

describe('TrustPassportService – Trust Passport & Trust Claims (TDD)', () => {
  let service: TrustPassportService;
  let mockPrisma: any;
  let hasher: EvidenceHasherService;

  const mockUser = {
    id: 'user_123',
    email: 'dev@zyron.security',
    name: 'Monad Developer',
    role: 'CLIENT',
    walletAddress: '0x1111111111111111111111111111111111111111',
    privyDid: 'did:privy:cm1234567890',
    githubLogin: 'monad-dev',
  };

  const mockOtherUser = {
    id: 'user_999',
    email: 'other@zyron.security',
    name: 'Other Dev',
    role: 'CLIENT',
    walletAddress: '0x9999999999999999999999999999999999999999',
    privyDid: 'did:privy:cm9999999999',
  };

  const mockPassport = {
    id: 'pass_123',
    userId: 'user_123',
    handle: 'monad-dev',
    title: 'Zyron Trust Passport',
    bio: 'Core Solidity Engineer',
    reputationScore: 200,
    isVerified: true,
    user: mockUser,
    claims: [],
  };

  beforeEach(async () => {
    hasher = new EvidenceHasherService();

    mockPrisma = {
      user: {
        findUnique: vi.fn().mockImplementation(({ where }) => {
          if (where.id === 'user_123') return Promise.resolve(mockUser);
          if (where.id === 'user_999') return Promise.resolve(mockOtherUser);
          return Promise.resolve(null);
        }),
      },
      trustPassport: {
        findUnique: vi.fn().mockImplementation(({ where }) => {
          if (where.userId === 'user_123' || where.id === 'pass_123' || where.handle === 'monad-dev') {
            return Promise.resolve(mockPassport);
          }
          if (where.id === 'pass_other') {
            return Promise.resolve({
              id: 'pass_other',
              userId: 'user_999',
              handle: 'other-dev',
              user: mockOtherUser,
              claims: [],
            });
          }
          return Promise.resolve(null);
        }),
        create: vi.fn().mockImplementation(({ data }) =>
          Promise.resolve({
            id: 'pass_new',
            ...data,
            claims: [],
          }),
        ),
        update: vi.fn().mockImplementation(({ data }) =>
          Promise.resolve({
            ...mockPassport,
            ...data,
          }),
        ),
      },
      trustClaim: {
        create: vi.fn().mockImplementation(({ data }) =>
          Promise.resolve({
            id: 'claim_new',
            ...data,
          }),
        ),
        findMany: vi.fn().mockResolvedValue([]),
        update: vi.fn().mockImplementation(({ data }) => Promise.resolve({ id: 'claim_1', ...data })),
      },
      auditRequest: {
        findUnique: vi.fn(),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TrustPassportService,
        EvidenceHasherService,
        { provide: PrismaService, useValue: mockPrisma },
      ],
    }).compile();

    service = module.get<TrustPassportService>(TrustPassportService);
  });

  describe('getOrCreatePassport()', () => {
    it('returns existing passport with reputation score and identity details', async () => {
      const passport = await service.getOrCreatePassport('user_123');
      expect(passport).toBeDefined();
      expect(passport.userId).toBe('user_123');
      expect(passport.reputationScore).toBeGreaterThanOrEqual(100);
      expect(passport.aiAuditor).toEqual(ZYRON_AI_AUDITOR_001);
    });

    it('provisions new passport and default claims if user does not have one', async () => {
      mockPrisma.trustPassport.findUnique.mockResolvedValueOnce(null);

      const passport = await service.getOrCreatePassport('user_123');
      expect(mockPrisma.trustPassport.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            userId: 'user_123',
            isVerified: true,
          }),
        }),
      );
      expect(passport).toBeDefined();
    });

    it('throws NotFoundException if user does not exist', async () => {
      await expect(service.getOrCreatePassport('user_unknown')).rejects.toThrow(NotFoundException);
    });
  });

  describe('Authorization: User A cannot modify User B passport', () => {
    it('throws ForbiddenException when User A attempts to issue claim on User B passport', async () => {
      await expect(
        service.issueClaim('user_123', 'pass_other', {
          claimType: 'DEVELOPER_VERIFIED',
          subject: '0xattacker',
          evidence: { note: 'malicious claim injection' },
        }),
      ).rejects.toThrow(ForbiddenException);
    });

    it('allows User A to issue claim on their own passport with canonical evidence hash', async () => {
      const claim = await service.issueClaim('user_123', 'pass_123', {
        claimType: 'DEVELOPER_VERIFIED',
        subject: mockUser.walletAddress,
        evidence: { verifiedBy: 'Privy', timestamp: Date.now() },
      });

      expect(claim).toBeDefined();
      expect(claim.evidenceHash).toMatch(/^0x[a-f0-9]{64}$/);
      expect(mockPrisma.trustClaim.create).toHaveBeenCalled();
    });
  });

  describe('AI Agent Provenance & Audit Claims (Section 14 & 15)', () => {
    it('records automated AUDIT_COMPLETED, CONTRACT_VERIFIED, and AI_AGENT_VERIFIED claims attributed to Zyron AI Auditor #001', async () => {
      const mockCompletedAudit = {
        id: 'ZYR-9481',
        protocolName: 'Monad Liquid Vault',
        contractFileName: 'VaultCore.sol',
        contractAddress: '0x1234567890123456789012345678901234567890',
        gitCommit: '7a10be8',
        bytecodeHash: '0xabcd1234',
        merkleRoot: '0x5555666677778888',
        sloc: 420,
        submittedById: 'user_123',
        onChainTxHash: '0xmonad_tx_hash_123',
        onChainChainId: 10143,
        findings: [{ displayId: 'ZYR-9481-001', severity: 'CRITICAL', status: 'RESOLVED' }],
      };

      mockPrisma.auditRequest.findUnique.mockResolvedValue(mockCompletedAudit);

      const claims = await service.recordAuditCompletionClaims('ZYR-9481', {
        onChainTxHash: '0xmonad_tx_hash_123',
        onChainChainId: 10143,
        onChainTokenId: 42,
      });

      expect(claims.length).toBe(3);

      const auditClaim = claims.find((c) => c.claimType === 'AUDIT_COMPLETED');
      expect(auditClaim).toBeDefined();
      expect(auditClaim!.issuer).toBe(ZYRON_AI_AUDITOR_001.id);
      expect(auditClaim!.onChainChainId).toBe(10143);
      expect(auditClaim!.onChainTokenId).toBe(42);
      expect(auditClaim!.onChainTxHash).toBe('0xmonad_tx_hash_123');

      const aiAgentClaim = claims.find((c) => c.claimType === 'AI_AGENT_VERIFIED');
      expect(aiAgentClaim).toBeDefined();
      expect(aiAgentClaim!.issuer).toBe(ZYRON_AI_AUDITOR_001.name);
    });
  });
});
