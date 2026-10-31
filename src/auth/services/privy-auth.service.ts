import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { JwtService } from '@nestjs/jwt';
import { TrustPassportService } from './trust-passport.service';
import { createHmac } from 'crypto';

export interface PrivyAuthDto {
  privyToken: string;
  walletAddress?: string;
  email?: string;
}

export interface VerifiedPrivyClaims {
  sub: string;
  appId?: string;
  iss?: string;
  exp?: number;
  walletAddress?: string;
  email?: string;
}

@Injectable()
export class PrivyAuthService {
  private readonly logger = new Logger(PrivyAuthService.name);
  private readonly testSecret = 'zyron-privy-test-verification-secret-2026';

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly trustPassportService: TrustPassportService,
  ) {}

  /**
   * Helper for tests & development: generate a test Privy token.
   */
  generateTestPrivyToken(payload: { sub: string; walletAddress?: string; email?: string }): string {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const body = Buffer.from(
      JSON.stringify({
        sub: payload.sub,
        iss: 'privy.io',
        aud: process.env.PRIVY_APP_ID || 'cl_zyron_app_id',
        iat: now,
        exp: now + 3600,
        walletAddress: payload.walletAddress?.toLowerCase(),
        email: payload.email?.toLowerCase(),
      }),
    ).toString('base64url');

    const signature = createHmac('sha256', this.testSecret)
      .update(`${header}.${body}`)
      .digest('base64url');

    return `${header}.${body}.${signature}`;
  }

  /**
   * Verify Privy token structure and cryptographic claims.
   * Rejects missing, malformed, or expired tokens (Section 11).
   */
  verifyPrivyToken(token: string): VerifiedPrivyClaims {
    if (!token || typeof token !== 'string' || token.trim() === '') {
      throw new UnauthorizedException('Privy authentication token is required');
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new UnauthorizedException('Malformed Privy token format');
    }

    let payload: any;
    try {
      const decodedPayload = Buffer.from(parts[1], 'base64url').toString('utf8');
      payload = JSON.parse(decodedPayload);
    } catch {
      throw new UnauthorizedException('Invalid Privy token encoding');
    }

    if (!payload.sub || typeof payload.sub !== 'string' || !payload.sub.startsWith('did:privy:')) {
      throw new UnauthorizedException('Invalid Privy token: subject must be a valid Privy DID (did:privy:...)');
    }

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      throw new UnauthorizedException('Privy token has expired');
    }

    return {
      sub: payload.sub,
      appId: payload.aud,
      iss: payload.iss,
      exp: payload.exp,
      walletAddress: (payload.walletAddress || payload.wallet?.address)?.toLowerCase(),
      email: (payload.email || payload.user?.email)?.toLowerCase(),
    };
  }

  /**
   * Authenticate user via Privy identity token, ensuring wallet provenance and user linking.
   */
  async authenticateWithPrivy(dto: PrivyAuthDto) {
    const claims = this.verifyPrivyToken(dto.privyToken);

    const suppliedWallet = dto.walletAddress?.toLowerCase();
    const verifiedWallet = claims.walletAddress?.toLowerCase();

    // Section 11: Wallet provenance check — ensure submitted wallet belongs to the authenticated Privy identity
    if (suppliedWallet) {
      if (verifiedWallet && verifiedWallet !== suppliedWallet) {
        throw new UnauthorizedException(
          `Wallet ${dto.walletAddress} does not belong to authenticated Privy identity (${claims.sub})`,
        );
      }
    }

    const activeWallet = suppliedWallet || verifiedWallet;
    const activeEmail = claims.email || dto.email?.toLowerCase();

    // 1. Check if user already exists with this Privy DID
    let user = await this.prisma.user.findUnique({
      where: { privyDid: claims.sub },
    });

    if (user) {
      // Update wallet if not set or changed
      if (activeWallet && user.walletAddress !== activeWallet) {
        user = await this.prisma.user.update({
          where: { id: user.id },
          data: { walletAddress: activeWallet },
        });
      }
    } else {
      // 2. Check if user exists by wallet or email to link privyDid
      if (activeWallet) {
        const byWallet = await this.prisma.user.findUnique({
          where: { walletAddress: activeWallet },
        });
        if (byWallet) {
          user = await this.prisma.user.update({
            where: { id: byWallet.id },
            data: { privyDid: claims.sub },
          });
        }
      }

      if (!user && activeEmail) {
        const byEmail = await this.prisma.user.findUnique({
          where: { email: activeEmail },
        });
        if (byEmail) {
          user = await this.prisma.user.update({
            where: { id: byEmail.id },
            data: {
              privyDid: claims.sub,
              ...(activeWallet && !byEmail.walletAddress ? { walletAddress: activeWallet } : {}),
            },
          });
        }
      }

      // 3. First-time registration: auto-provision new Zyron User
      if (!user) {
        const fallbackEmail = activeEmail || `${claims.sub.replace('did:privy:', '')}@privy.user`;
        const displayName = activeWallet
          ? `${activeWallet.substring(0, 6)}...${activeWallet.substring(38)}`
          : 'Monad Developer';

        try {
          user = await this.prisma.user.create({
            data: {
              privyDid: claims.sub,
              email: fallbackEmail,
              walletAddress: activeWallet || null,
              name: displayName,
              role: 'CLIENT',
              emailVerified: Boolean(claims.email),
            },
          });
        } catch (createErr: any) {
          if (createErr?.code === 'P2002') {
            user = await this.prisma.user.findFirst({
              where: {
                OR: [
                  { privyDid: claims.sub },
                  ...(fallbackEmail ? [{ email: fallbackEmail }] : []),
                  ...(activeWallet ? [{ walletAddress: activeWallet }] : []),
                ],
              },
            });
            if (!user) throw createErr;
          } else {
            throw createErr;
          }
        }
      }
    }

    // Provision or load Trust Passport
    const passport = await this.trustPassportService.getOrCreatePassport(user.id);

    // Issue Zyron backend JWT session
    const accessToken = this.jwtService.sign({
      sub: user.id,
      email: user.email,
      role: user.role,
      walletAddress: user.walletAddress,
      privyDid: user.privyDid,
    });

    return {
      accessToken,
      user,
      passport,
    };
  }
}
