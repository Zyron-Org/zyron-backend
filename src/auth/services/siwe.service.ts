import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../database/database.module';
import { SiweVerifyDto } from '../dto/auth.dto';
import { UserRole } from '../../common/enum';
import { generateNonce, SiweMessage } from 'siwe';
import { verifyMessage, isAddress } from 'ethers';

@Injectable()
export class SiweService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  generateSiweNonce(): { nonce: string } {
    return { nonce: generateNonce() };
  }

  async verifySiwe(dto: SiweVerifyDto) {
    try {
      let walletAddress: string;

      try {
        const siweMessage = new SiweMessage(dto.message);
        const fields = await siweMessage.verify({ signature: dto.signature });
        walletAddress = fields.data.address.toLowerCase();
      } catch (siweErr: any) {
        // Resilient fallback: If line 2 was unchecksummed (EIP-55 casing mismatch),
        // recover signer directly from the raw message using ECDSA.
        const lines = dto.message.split('\n');
        const statedAddress = lines.length > 1 ? lines[1].trim() : '';
        const recovered = verifyMessage(dto.message, dto.signature);

        if (
          statedAddress &&
          isAddress(statedAddress) &&
          recovered.toLowerCase() === statedAddress.toLowerCase()
        ) {
          walletAddress = recovered.toLowerCase();
        } else {
          throw siweErr;
        }
      }

      let user = await this.prisma.user.findUnique({
        where: { walletAddress },
        include: { organization: true },
      });

      if (!user) {
        user = await this.prisma.user.create({
          data: {
            email: `${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}@wallet.zyron`,
            walletAddress,
            name: `Wallet_${walletAddress.slice(0, 6)}`,
            role: UserRole.CLIENT,
            emailVerified: true,
            emailVerifiedAt: new Date(),
          },
          include: { organization: true },
        });
      }

      const token = this.generateJwt(user);
      const { passwordHash: _, ...safeUser } = user;

      return {
        user: safeUser,
        accessToken: token,
      };
    } catch (e: any) {
      throw new UnauthorizedException(`SIWE verification failed: ${e.message || 'Invalid signature'}`);
    }
  }


  private generateJwt(user: any): string {
    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role,
      organizationId: user.organizationId,
      walletAddress: user.walletAddress,
    };

    return this.jwtService.sign(payload);
  }
}
