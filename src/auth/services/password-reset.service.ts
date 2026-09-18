import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { PrismaService } from '../../database/database.module';
import { APP_URL } from '../../config';
import * as crypto from 'crypto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class PasswordResetService {
  private readonly logger = new Logger(PasswordResetService.name);

  constructor(
    private prisma: PrismaService,
    private eventEmitter: EventEmitter2,
  ) {}

  async requestPasswordReset(email: string): Promise<{ message: string }> {
    const normalizedEmail = email.toLowerCase().trim();
    const user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (user) {
      // Invalidate existing unused tokens for this user
      await this.prisma.passwordResetToken.updateMany({
        where: {
          userId: user.id,
          usedAt: null,
        },
        data: {
          usedAt: new Date(),
        },
      });

      // Generate a cryptographically secure token
      const token = crypto.randomBytes(32).toString('hex');
      const expiresInMinutes = 60;
      const expiresAt = new Date(Date.now() + expiresInMinutes * 60 * 1000);

      await this.prisma.passwordResetToken.create({
        data: {
          token,
          userId: user.id,
          expiresAt,
        },
      });

      const resetUrl = `${APP_URL}/auth/reset-password?token=${token}`;

      // Dispatch event to background email service without blocking
      this.eventEmitter.emit('email.password-reset', {
        email: user.email,
        userName: user.name,
        resetUrl,
        expiresInMinutes,
      });

      this.logger.log(`Password reset token generated and email dispatched for ${user.email}`);
    } else {
      this.logger.debug(`Password reset requested for non-existent email: ${normalizedEmail}`);
    }

    // Always return uniform response to prevent user enumeration
    return {
      message: 'If an account exists with this email address, a password reset link has been dispatched.',
    };
  }

  async resetPassword(token: string, newPassword: string): Promise<{ message: string }> {
    if (!token || !newPassword) {
      throw new BadRequestException('Token and new password are required');
    }

    const resetToken = await this.prisma.passwordResetToken.findUnique({
      where: { token },
      include: { user: true },
    });

    if (!resetToken) {
      throw new BadRequestException('Invalid or expired password reset token');
    }

    if (resetToken.usedAt) {
      throw new BadRequestException('This password reset token has already been used');
    }

    if (new Date() > resetToken.expiresAt) {
      throw new BadRequestException('This password reset token has expired');
    }

    // Hash new password with 12 salt rounds (matching register.service)
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(newPassword, saltRounds);

    // Update user password and mark token used in a transaction
    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: resetToken.userId },
        data: { passwordHash },
      }),
      this.prisma.passwordResetToken.update({
        where: { id: resetToken.id },
        data: { usedAt: new Date() },
      }),
    ]);

    this.logger.log(`Password successfully reset for user ${resetToken.user.email}`);

    return {
      message: 'Your password has been successfully reset. You may now log in with your new credentials.',
    };
  }
}
