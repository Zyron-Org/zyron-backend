import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { PrismaService } from '../../database/database.module';
import { APP_URL } from '../../config';
import * as crypto from 'crypto';

@Injectable()
export class EmailVerificationService {
  private readonly logger = new Logger(EmailVerificationService.name);

  constructor(
    private prisma: PrismaService,
    private eventEmitter: EventEmitter2,
  ) {}

  async createVerificationToken(user: { id: string; email: string; name: string }): Promise<string> {
    // Invalidate any previous unused verification tokens for this user
    await this.prisma.emailVerificationToken.updateMany({
      where: {
        userId: user.id,
        usedAt: null,
      },
      data: {
        usedAt: new Date(),
      },
    });

    // Generate cryptographically secure token
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    await this.prisma.emailVerificationToken.create({
      data: {
        token,
        userId: user.id,
        expiresAt,
      },
    });

    const verificationUrl = `${APP_URL}/auth/verify-email?token=${token}`;

    // Dispatch background verification email event
    this.eventEmitter.emit('email.verify', {
      email: user.email,
      name: user.name,
      verificationUrl,
    });

    this.logger.log(`Verification token created and email dispatched for user ${user.email}`);
    return token;
  }

  async verifyEmail(token: string): Promise<{ message: string }> {
    if (!token) {
      throw new BadRequestException('Verification token is required');
    }

    const verificationToken = await this.prisma.emailVerificationToken.findUnique({
      where: { token },
      include: { user: true },
    });

    if (!verificationToken) {
      throw new BadRequestException('Invalid or expired verification token');
    }

    if (verificationToken.usedAt) {
      throw new BadRequestException('This verification token has already been used');
    }

    if (new Date() > verificationToken.expiresAt) {
      throw new BadRequestException('This verification token has expired. Please request a new verification email.');
    }

    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: verificationToken.userId },
        data: {
          emailVerified: true,
          emailVerifiedAt: new Date(),
        },
      }),
      this.prisma.emailVerificationToken.update({
        where: { id: verificationToken.id },
        data: { usedAt: new Date() },
      }),
    ]);

    this.logger.log(`Email successfully verified for user ${verificationToken.user.email}`);

    return {
      message: 'Email address successfully verified. You can now log in to your account.',
    };
  }

  async resendVerification(email: string): Promise<{ message: string }> {
    const normalizedEmail = email.toLowerCase().trim();
    const user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (user) {
      if (user.emailVerified) {
        return {
          message: 'Your email address is already verified. You can sign in directly.',
        };
      }

      await this.createVerificationToken({
        id: user.id,
        email: user.email,
        name: user.name,
      });
    } else {
      this.logger.debug(`Verification resend requested for non-existent email: ${normalizedEmail}`);
    }

    return {
      message: 'If an account exists with this email address and is pending verification, a new verification link has been dispatched.',
    };
  }
}
