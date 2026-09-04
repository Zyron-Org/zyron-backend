import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../database/database.module';
import { LoginDto } from '../dto/auth.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class LoginService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

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
