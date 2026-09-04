import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';

function sanitizeUser(user: any) {
  if (!user) return user;
  const { passwordHash, ...sanitized } = user;
  return sanitized;
}

@Injectable()
export class GetOrganizationService {
  constructor(private prisma: PrismaService) {}

  async getOrganizationForUser(userId: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.organizationId) {
      throw new NotFoundException('User does not belong to any organization');
    }

    const org = await this.prisma.organization.findUnique({
      where: { id: user.organizationId },
      include: {
        users: true,
        audits: {
          orderBy: { createdAt: 'desc' },
          include: { payment: true },
        },
      },
    });

    if (!org) {
      throw new NotFoundException(`Organization ${user.organizationId} not found`);
    }

    if (org.users) {
      org.users = org.users.map(sanitizeUser);
    }

    return org;
  }
}
