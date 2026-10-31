import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import { PrivyAuthService } from '../src/auth/services/privy-auth.service';
import { PrismaService } from '../src/database/database.module';
import { JwtService } from '@nestjs/jwt';
import { TrustPassportService } from '../src/auth/services/trust-passport.service';
import { UnauthorizedException } from '@nestjs/common';

describe('PrivyAuthService – Privy Identity Security (TDD Section 11)', () => {
  let service: PrivyAuthService;
  let mockPrisma: any;
  let mockJwtService: any;
  let mockPassportService: any;

  const validPrivyDid = 'did:privy:cm1234567890abcdef';
  const validWallet = '0x1234567890123456789012345678901234567890';
  const attackerWallet = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

  beforeEach(async () => {
    mockPrisma = {
      user: {
        findUnique: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
      },
    };

    mockJwtService = {
      sign: vi.fn().mockReturnValue('mock_zyron_jwt_session_token'),
      verify: vi.fn(),
    };

    mockPassportService = {
      getOrCreatePassport: vi.fn().mockResolvedValue({
        id: 'pass_123',
        userId: 'user_123',
        reputationScore: 150,
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PrivyAuthService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: JwtService, useValue: mockJwtService },
        { provide: TrustPassportService, useValue: mockPassportService },
      ],
    }).compile();

    service = module.get<PrivyAuthService>(PrivyAuthService);
  });

  it('rejects missing authentication with UnauthorizedException', async () => {
    await expect(
      service.authenticateWithPrivy({ privyToken: '' }),
    ).rejects.toThrow(UnauthorizedException);

    await expect(
      service.authenticateWithPrivy({ privyToken: null as any }),
    ).rejects.toThrow(UnauthorizedException);
  });

  it('rejects invalid authentication (malformed or expired token) with UnauthorizedException', async () => {
    await expect(
      service.authenticateWithPrivy({ privyToken: 'invalid.jwt.token' }),
    ).rejects.toThrow(UnauthorizedException);
  });

  it('rejects authentication when wallet address does not belong to the authenticated identity', async () => {
    // Generate valid Privy token mock that is for validWallet
    const validToken = service.generateTestPrivyToken({
      sub: validPrivyDid,
      walletAddress: validWallet,
    });

    // Attacker passes attackerWallet which doesn't match the authenticated token's wallet
    await expect(
      service.authenticateWithPrivy({
        privyToken: validToken,
        walletAddress: attackerWallet,
      }),
    ).rejects.toThrow(UnauthorizedException);
  });

  it('accepts valid Privy identity and returns Zyron JWT session + Trust Passport', async () => {
    const validToken = service.generateTestPrivyToken({
      sub: validPrivyDid,
      walletAddress: validWallet,
      email: 'builder@monad.xyz',
    });

    const mockExistingUser = {
      id: 'user_123',
      email: 'builder@monad.xyz',
      walletAddress: validWallet,
      privyDid: validPrivyDid,
      role: 'CLIENT',
      name: 'Monad Builder',
    };

    mockPrisma.user.findUnique.mockResolvedValue(mockExistingUser);

    const result = await service.authenticateWithPrivy({
      privyToken: validToken,
      walletAddress: validWallet,
    });

    expect(result).toBeDefined();
    expect(result.accessToken).toBe('mock_zyron_jwt_session_token');
    expect(result.user.privyDid).toBe(validPrivyDid);
    expect(result.passport).toBeDefined();
    expect(mockPassportService.getOrCreatePassport).toHaveBeenCalledWith('user_123');
  });

  it('auto-provisions new user and Trust Passport for first-time Privy sign-in', async () => {
    const validToken = service.generateTestPrivyToken({
      sub: validPrivyDid,
      walletAddress: validWallet,
    });

    mockPrisma.user.findUnique.mockResolvedValue(null);
    mockPrisma.user.create.mockResolvedValue({
      id: 'user_new',
      email: `${validPrivyDid}@privy.user`,
      walletAddress: validWallet,
      privyDid: validPrivyDid,
      role: 'CLIENT',
      name: '0x1234...7890',
    });

    const result = await service.authenticateWithPrivy({
      privyToken: validToken,
      walletAddress: validWallet,
    });

    expect(mockPrisma.user.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          privyDid: validPrivyDid,
          walletAddress: validWallet,
        }),
      }),
    );
    expect(result.user.id).toBe('user_new');
  });
});
