import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { NODE_ENV, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM } from '../../config';

@Injectable()
export class EmailTransportService implements OnModuleInit {
  private readonly logger = new Logger(EmailTransportService.name);
  private transporter: Transporter;
  private fromAddress: string = SMTP_FROM;

  async onModuleInit() {
    if (NODE_ENV === 'development' && !SMTP_HOST) {
      // Auto-create Ethereal test account in background without blocking server startup
      this.initEtherealAccount().catch((err) => {
        this.logger.warn(`Failed to create Ethereal account: ${err.message}. Email sending disabled.`);
      });
    } else if (SMTP_HOST) {
      // Production SMTP transport
      this.transporter = nodemailer.createTransport({
        host: SMTP_HOST,
        port: SMTP_PORT,
        secure: SMTP_PORT === 465,
        auth: {
          user: SMTP_USER,
          pass: SMTP_PASS,
        },
      });
      this.fromAddress = SMTP_FROM;
      this.logger.log(`📧 SMTP transport configured: ${SMTP_HOST}:${SMTP_PORT}`);
    } else {
      this.logger.warn('📧 No email transport configured. Email sending disabled.');
    }
  }

  private async initEtherealAccount() {
    try {
      const testAccount = await nodemailer.createTestAccount();
      this.transporter = nodemailer.createTransport({
        host: testAccount.smtp.host,
        port: testAccount.smtp.port,
        secure: testAccount.smtp.secure,
        auth: {
          user: testAccount.user,
          pass: testAccount.pass,
        },
      });
      this.fromAddress = `"Zyron Security" <${testAccount.user}>`;
      this.logger.log(`📧 Ethereal test email account created`);
      this.logger.log(`   User: ${testAccount.user}`);
      this.logger.log(`   Pass: ${testAccount.pass}`);
      this.logger.log(`   Preview URL: https://ethereal.email/login`);
    } catch (err: any) {
      this.logger.warn(`Failed to create Ethereal account: ${err.message}. Email sending disabled.`);
    }
  }

  async sendMail(to: string, subject: string, html: string): Promise<string | null> {
    if (!this.transporter) {
      this.logger.warn(`Email skipped (no transport): to=${to} subject="${subject}"`);
      return null;
    }

    try {
      const info = await this.transporter.sendMail({
        from: this.fromAddress,
        to,
        subject,
        html,
      });

      // In development with Ethereal, log the preview URL
      const previewUrl = nodemailer.getTestMessageUrl(info);
      if (previewUrl) {
        this.logger.log(`📧 Email sent to ${to} — Preview: ${previewUrl}`);
      } else {
        this.logger.log(`📧 Email sent to ${to} — MessageId: ${info.messageId}`);
      }

      return (previewUrl as string) || info.messageId;
    } catch (err: any) {
      this.logger.error(`📧 Failed to send email to ${to}: ${err.message}`);
      return null;
    }
  }
}
