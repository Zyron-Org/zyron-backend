import { describe, it, expect, beforeEach, vi } from 'vitest';
import { EmailTemplateService } from '../src/email/services/email-template.service';
import { EmailDispatcherService } from '../src/email/services/email-dispatcher.service';
import { PasswordResetService } from '../src/auth/services/password-reset.service';
import { BadRequestException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

vi.mock('bcrypt');

describe('Email & Password Reset (Unit Tests)', () => {
  describe('EmailTemplateService', () => {
    let templateService: EmailTemplateService;

    beforeEach(() => {
      templateService = new EmailTemplateService();
      templateService.onModuleInit();
    });

    it('should discover and compile welcome and password-reset templates', () => {
      const templates = templateService.getAvailableTemplates();
      expect(templates).toContain('welcome');
      expect(templates).toContain('password-reset');
    });

    it('should render welcome email with user name and organization', () => {
      const html = templateService.render('welcome', {
        userName: 'Satoshi Nakamoto',
        orgName: 'Bitcoin Protocol',
        loginUrl: 'http://localhost:3000/auth/login',
      });

      expect(html).toContain('Satoshi Nakamoto');
      expect(html).toContain('Bitcoin Protocol');
      expect(html).toContain('ZYRON // PROTOCOL SECURITY');
      expect(html).toContain('http://localhost:3000/auth/login');
    });

    it('should render password reset email with reset link and expiry', () => {
      const html = templateService.render('password-reset', {
        userName: 'Vitalik Buterin',
        resetUrl: 'http://localhost:3000/auth/reset-password?token=secure_tok_123',
        expiresInMinutes: 60,
      });

      expect(html).toContain('Vitalik Buterin');
      expect(html).toContain('secure_tok_123');
      expect(html).toContain('60 minutes');
      expect(html).toContain('ZYRON // CREDENTIAL RECOVERY');
    });

    it('should return fallback message for unknown template', () => {
      const html = templateService.render('non-existent-template');
      expect(html).toContain('not found');
    });
  });

  describe('EmailDispatcherService', () => {
    let dispatcher: EmailDispatcherService;
    let mockTransport: any;
    let mockTemplates: any;

    beforeEach(() => {
      mockTransport = {
        sendMail: vi.fn().mockResolvedValue('https://ethereal.email/message/msg123'),
      };
      mockTemplates = {
        render: vi.fn().mockReturnValue('<html>Test Email</html>'),
      };
      dispatcher = new EmailDispatcherService(mockTransport, mockTemplates);
    });

    it('should handle welcome email event without blocking or throwing', async () => {
      await dispatcher.handleWelcomeEmail({
        email: 'security@auraprotocol.io',
        userName: 'Aura Lead',
        orgName: 'Aura Finance DAO',
      });

      expect(mockTemplates.render).toHaveBeenCalledWith('welcome', expect.objectContaining({
        userName: 'Aura Lead',
        orgName: 'Aura Finance DAO',
      }));
      expect(mockTransport.sendMail).toHaveBeenCalledWith(
        'security@auraprotocol.io',
        'Welcome to Zyron Security Protocol',
        '<html>Test Email</html>',
      );
    });

    it('should handle password reset email event without blocking or throwing', async () => {
      await dispatcher.handlePasswordResetEmail({
        email: 'security@auraprotocol.io',
        userName: 'Aura Lead',
        resetUrl: 'http://localhost:3000/auth/reset-password?token=abc',
        expiresInMinutes: 60,
      });

      expect(mockTemplates.render).toHaveBeenCalledWith('password-reset', expect.objectContaining({
        userName: 'Aura Lead',
        resetUrl: 'http://localhost:3000/auth/reset-password?token=abc',
      }));
      expect(mockTransport.sendMail).toHaveBeenCalledWith(
        'security@auraprotocol.io',
        'Zyron Security — Password Reset Request',
        '<html>Test Email</html>',
      );
    });
  });

  describe('PasswordResetService', () => {
    let resetService: PasswordResetService;
    let mockPrisma: any;
    let mockEventEmitter: any;

    beforeEach(() => {
      mockPrisma = {
        user: {
          findUnique: vi.fn(),
          update: vi.fn().mockResolvedValue({ id: 'usr_1' }),
        },
        passwordResetToken: {
          updateMany: vi.fn(),
          create: vi.fn().mockResolvedValue({ id: 'tok_1', token: 'hex_tok' }),
          findUnique: vi.fn(),
          update: vi.fn().mockResolvedValue({ id: 'tok_1' }),
        },
        $transaction: vi.fn().mockImplementation((promises) => Promise.all(promises)),
      };
      mockEventEmitter = {
        emit: vi.fn(),
      };
      resetService = new PasswordResetService(mockPrisma, mockEventEmitter);
    });

    it('should generate token and dispatch event for registered email', async () => {
      mockPrisma.user.findUnique.mockResolvedValue({
        id: 'usr_123',
        email: 'security@auraprotocol.io',
        name: 'Aura Lead',
      });

      const res = await resetService.requestPasswordReset('security@auraprotocol.io');

      expect(res.message).toContain('password reset link has been dispatched');
      expect(mockPrisma.passwordResetToken.create).toHaveBeenCalled();
      expect(mockEventEmitter.emit).toHaveBeenCalledWith('email.password-reset', expect.objectContaining({
        email: 'security@auraprotocol.io',
        userName: 'Aura Lead',
        expiresInMinutes: 60,
      }));
    });

    it('should return success message without emitting email if user does not exist (enumeration safe)', async () => {
      mockPrisma.user.findUnique.mockResolvedValue(null);

      const res = await resetService.requestPasswordReset('nonexistent@domain.com');

      expect(res.message).toContain('password reset link has been dispatched');
      expect(mockPrisma.passwordResetToken.create).not.toHaveBeenCalled();
      expect(mockEventEmitter.emit).not.toHaveBeenCalled();
    });

    it('should reset password with valid token', async () => {
      (bcrypt.hash as any).mockResolvedValue('new_hashed_password');

      mockPrisma.passwordResetToken.findUnique.mockResolvedValue({
        id: 'tok_123',
        token: 'valid_token_str',
        userId: 'usr_123',
        usedAt: null,
        expiresAt: new Date(Date.now() + 30 * 60 * 1000), // 30m in future
        user: { id: 'usr_123', email: 'security@auraprotocol.io' },
      });

      const res = await resetService.resetPassword('valid_token_str', 'BrandNewSecretPass123!');

      expect(res.message).toContain('successfully reset');
      expect(mockPrisma.user.update).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'usr_123' },
        data: { passwordHash: 'new_hashed_password' },
      }));
      expect(mockPrisma.passwordResetToken.update).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'tok_123' },
        data: expect.objectContaining({ usedAt: expect.any(Date) }),
      }));
    });

    it('should throw BadRequestException for already used token', async () => {
      mockPrisma.passwordResetToken.findUnique.mockResolvedValue({
        id: 'tok_123',
        usedAt: new Date(),
        expiresAt: new Date(Date.now() + 30 * 60 * 1000),
      });

      await expect(
        resetService.resetPassword('used_token', 'NewPass123!'),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException for expired token', async () => {
      mockPrisma.passwordResetToken.findUnique.mockResolvedValue({
        id: 'tok_123',
        usedAt: null,
        expiresAt: new Date(Date.now() - 1000), // Expired
      });

      await expect(
        resetService.resetPassword('expired_token', 'NewPass123!'),
      ).rejects.toThrow(BadRequestException);
    });
  });
});
