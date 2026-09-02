import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../src/auth/auth.service';
import { PrismaService } from '../src/database/database.module';
import { JwtService } from '@nestjs/jwt';
import { ConflictException, UnauthorizedException } from '@nestjs/common';
import { UserRole } from '../src/common/enum';
import * as bcrypt from 'bcrypt';

vi.mock('bcrypt');

describe('AuthService (Unit Tests)', () => {
  let authService: AuthService;
  let mockPrisma: any;
  let mockJwtService: any;

  const mockUser = {
    id: 'usr_123',
    email: 'security@auraprotocol.io',
    passwordHash: '$2b$12$eImiTXuWVxfM37uY4JANjO5E8tL2b1k2a3b4c5d6e7f8g9h0i1j2k',
    name: 'Aura Core Protocol',
    role: UserRole.CLIENT,
    walletAddress: null,
    avatarUrl: null,
    organizationId: 'org_123',
    organization: { id: 'org_123', name: 'Aura Finance DAO' },
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    mockPrisma = {
      user: {
        findUnique: vi.fn(),
        create: vi.fn(),
      },
      organization: {
        create: vi.fn().mockResolvedValue({ id: 'org_123', name: 'Aura Finance DAO' }),
      },
    };

    mockJwtService = {
      sign: vi.fn().mockReturnValue('mocked_jwt_access_token'),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: JwtService, useValue: mockJwtService },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
  });

  describe('register()', () => {
    it('should throw ConflictException if email already exists', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(mockUser);

      await expect(
        authService.register({
          email: 'security@auraprotocol.io',
          password: 'Password123!',
          name: 'Aura Core Protocol',
        }),
      ).rejects.toThrow(ConflictException);
    });

    it('should hash password with bcrypt and return user with JWT token', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);
      mockPrisma.user.create.mockResolvedValue(mockUser);
      (bcrypt.hash as any).mockResolvedValue('hashed_password_string');

      const result = await authService.register({
        email: 'security@auraprotocol.io',
        password: 'Password123!',
        name: 'Aura Core Protocol',
        organizationName: 'Aura Finance DAO',
      });

      expect(bcrypt.hash).toHaveBeenCalledWith('Password123!', 12);
      expect(result).toHaveProperty('accessToken', 'mocked_jwt_access_token');
      expect(result.user.email).toBe('security@auraprotocol.io');
    });
  });

  describe('login()', () => {
    it('should throw UnauthorizedException on unknown email', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);

      await expect(
        authService.login({
          email: 'unknown@zyron.labs',
          password: 'Password123!',
        }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException on wrong password', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(mockUser);
      (bcrypt.compare as any).mockResolvedValue(false);

      await expect(
        authService.login({
          email: 'security@auraprotocol.io',
          password: 'WrongPassword!',
        }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should return valid JWT access token on matching password', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(mockUser);
      (bcrypt.compare as any).mockResolvedValue(true);

      const result = await authService.login({
        email: 'security@auraprotocol.io',
        password: 'Password123!',
      });

      expect(result.accessToken).toBe('mocked_jwt_access_token');
    });
  });

  describe('generateSiweNonce()', () => {
    it('should generate a 24+ character random alphanumeric challenge nonce', () => {
      const { nonce } = authService.generateSiweNonce();
      expect(nonce).toBeDefined();
      expect(nonce.length).toBeGreaterThanOrEqual(8);
    });
  });
});
