import { Injectable, ConflictException, UnauthorizedException, NotFoundException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../database/database.module';
import { RegisterDto, LoginDto, SiweVerifyDto, UpdateRoleDto } from './dto/auth.dto';
import { UserRole } from '../common/enum';
import * as bcrypt from 'bcrypt';
import { generateNonce, SiweMessage } from 'siwe';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async register(dto: RegisterDto) {
    const existing = await this.prisma.user.findUnique({
      where: { email: dto.email.toLowerCase() },
    });

    if (existing) {
      throw new ConflictException('User with this email address already exists');
    }

    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(dto.password, saltRounds);

    let organizationId: string | undefined = undefined;

    if (dto.organizationName) {
      const org = await this.prisma.organization.create({
        data: {
          name: dto.organizationName,
          tier: 'standard',
        },
      });
      organizationId = org.id;
    }

    const user = await this.prisma.user.create({
      data: {
        email: dto.email.toLowerCase(),
        passwordHash,
        name: dto.name,
        role: UserRole.CLIENT,
        organizationId,
      },
      include: {
        organization: true,
      },
    });

    const token = this.generateJwt(user);
    const { passwordHash: _, ...safeUser } = user;

    return {
      user: safeUser,
      accessToken: token,
    };
  }

  async login(dto: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email.toLowerCase() },
      include: { organization: true },
    });

    if (!user || !user.passwordHash) {
      throw new UnauthorizedException('Invalid email address or password');
    }

    const isValidPassword = await bcrypt.compare(dto.password, user.passwordHash);

    if (!isValidPassword) {
      throw new UnauthorizedException('Invalid email address or password');
    }

    const token = this.generateJwt(user);
    const { passwordHash: _, ...safeUser } = user;

    return {
      user: safeUser,
      accessToken: token,
    };
  }

  generateSiweNonce(): { nonce: string } {
    return { nonce: generateNonce() };
  }

  async verifySiwe(dto: SiweVerifyDto) {
    try {
      const siweMessage = new SiweMessage(dto.message);
      const fields = await siweMessage.verify({ signature: dto.signature });

      const walletAddress = fields.data.address.toLowerCase();

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

  async getUserProfile(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { organization: true },
    });

    if (!user) {
      throw new NotFoundException('User profile not found');
    }

    const { passwordHash: _, ...safeUser } = user;
    return safeUser;
  }

  async listUsers(roleFilter?: UserRole) {
    const where = roleFilter ? { role: roleFilter } : {};
    const users = await this.prisma.user.findMany({
      where,
      include: { organization: true },
      orderBy: { createdAt: 'desc' },
    });

    return users.map(({ passwordHash: _, ...safeUser }) => safeUser);
  }

  async updateUserRole(userId: string, dto: UpdateRoleDto) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const updated = await this.prisma.user.update({
      where: { id: userId },
      data: { role: dto.role },
      include: { organization: true },
    });

    const { passwordHash: _, ...safeUser } = updated;
    return safeUser;
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
