import { Injectable, Logger } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { EmailTransportService } from './email-transport.service';
import { EmailTemplateService } from './email-template.service';

export interface WelcomeEmailPayload {
  email: string;
  userName: string;
  orgName?: string;
}

export interface PasswordResetEmailPayload {
  email: string;
  userName: string;
  resetUrl: string;
  expiresInMinutes: number;
}

export interface VerificationEmailPayload {
  email: string;
  name: string;
  verificationUrl: string;
}

@Injectable()
export class EmailDispatcherService {
  private readonly logger = new Logger(EmailDispatcherService.name);

  constructor(
    private transport: EmailTransportService,
    private templates: EmailTemplateService,
  ) {}

  @OnEvent('email.verify', { async: true })
  async handleVerificationEmail(payload: VerificationEmailPayload) {
    try {
      this.logger.log(`Dispatching verification email to ${payload.email}`);
      const html = this.templates.render('email-verification', {
        name: payload.name,
        verificationUrl: payload.verificationUrl,
        currentYear: new Date().getFullYear(),
      });

      await this.transport.sendMail(
        payload.email,
        'Zyron Security — Verify Your Email Address',
        html,
      );
    } catch (err: any) {
      this.logger.error(`Failed to dispatch verification email to ${payload.email}: ${err.message}`);
    }
  }

  @OnEvent('email.welcome', { async: true })
  async handleWelcomeEmail(payload: WelcomeEmailPayload) {
    try {
      this.logger.log(`Dispatching welcome email to ${payload.email}`);
      const html = this.templates.render('welcome', {
        userName: payload.userName,
        orgName: payload.orgName,
        loginUrl: `${process.env.APP_URL || 'http://localhost:3000'}/auth/login`,
      });

      await this.transport.sendMail(
        payload.email,
        'Welcome to Zyron Security Protocol',
        html,
      );
    } catch (err: any) {
      this.logger.error(`Failed to dispatch welcome email to ${payload.email}: ${err.message}`);
    }
  }

  @OnEvent('email.password-reset', { async: true })
  async handlePasswordResetEmail(payload: PasswordResetEmailPayload) {
    try {
      this.logger.log(`Dispatching password reset email to ${payload.email}`);
      const html = this.templates.render('password-reset', {
        userName: payload.userName,
        resetUrl: payload.resetUrl,
        expiresInMinutes: payload.expiresInMinutes,
      });

      await this.transport.sendMail(
        payload.email,
        'Zyron Security — Password Reset Request',
        html,
      );
    } catch (err: any) {
      this.logger.error(`Failed to dispatch password reset email to ${payload.email}: ${err.message}`);
    }
  }
}

