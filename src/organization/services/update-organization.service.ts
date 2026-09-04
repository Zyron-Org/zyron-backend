import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { UpdateOrganizationDto } from '../dto/organization.dto';

function sanitizeUser(user: any) {
  if (!user) return user;
  const { passwordHash, ...sanitized } = user;
  return sanitized;
}

@Injectable()
export class UpdateOrganizationService {
  constructor(private prisma: PrismaService) {}

  async updateOrganization(orgId: string, requesterUserId: string, dto: UpdateOrganizationDto) {
    const org = await this.prisma.organization.findUnique({ where: { id: orgId } });
    if (!org) {
      throw new NotFoundException(`Organization ${orgId} not found`);
    }

    const data: any = {};
    if (dto.name) data.name = dto.name;
    if (dto.billingEmail) data.billingEmail = dto.billingEmail;
    if (dto.taxId) data.taxId = dto.taxId;
    if (dto.tier) data.tier = dto.tier;

    const updatedOrg = await this.prisma.organization.update({
      where: { id: orgId },
      data,
      include: {
        users: true,
        audits: true,
      },
    });

    if (updatedOrg.users) {
      updatedOrg.users = updatedOrg.users.map(sanitizeUser);
    }

    return updatedOrg;
  }
}
