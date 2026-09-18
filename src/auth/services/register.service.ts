import { Injectable, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../database/database.module';
import { RegisterDto } from '../dto/auth.dto';
import { UserRole } from '../../common/enum';
import { EmailVerificationService } from './email-verification.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class RegisterService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private emailVerificationService: EmailVerificationService,
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
        emailVerified: false,
      },
      include: {
        organization: true,
      },
    });

    // Generate single-use verification token & dispatch verification email
    await this.emailVerificationService.createVerificationToken({
      id: user.id,
      email: user.email,
      name: user.name,
    });

    const { passwordHash: _, ...safeUser } = user;

    return {
      user: safeUser,
      message: 'Registration successful. Please check your email to verify your account before logging in.',
      requiresEmailVerification: true,
    };
  }


  generateJwt(user: any): string {
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
