import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { CreateOrganizationDto } from '../dto/organization.dto';

function sanitizeUser(user: any) {
  if (!user) return user;
  const { passwordHash, ...sanitized } = user;
  return sanitized;
}

@Injectable()
export class CreateOrganizationService {
  constructor(private prisma: PrismaService) {}

  async createOrganization(userId: string, dto: CreateOrganizationDto) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new NotFoundException(`User ${userId} not found`);
    }

    if (user.organizationId) {
      throw new ConflictException('User already belongs to an organization');
    }

    const org = await this.prisma.organization.create({
      data: {
        name: dto.name,
        billingEmail: dto.billingEmail,
        taxId: dto.taxId,
        tier: dto.tier || 'standard',
      },
      include: {
        users: true,
        audits: true,
      },
    });

    await this.prisma.user.update({
      where: { id: userId },
      data: { organizationId: org.id },
    });

    if (org.users) {
      org.users = org.users.map(sanitizeUser);
    }

    return org;
  }
}
