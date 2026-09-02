import { Injectable, NotFoundException, ConflictException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../database/database.module';
import { CreateOrganizationDto, UpdateOrganizationDto } from './dto/organization.dto';

function sanitizeUser(user: any) {
  if (!user) return user;
  const { passwordHash, ...sanitized } = user;
  return sanitized;
}

@Injectable()
export class OrganizationService {
  constructor(private prisma: PrismaService) {}

  // 1. Create Organization & Link Current User
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

    // Link user to org
    await this.prisma.user.update({
      where: { id: userId },
      data: { organizationId: org.id },
    });

    if (org.users) {
      org.users = org.users.map(sanitizeUser);
    }

    return org;
  }

  // 2. Get Organization Details & Team Members for User
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

  // 3. Add / Invite Member by Email
  async addMember(orgId: string, requesterUserId: string, email: string) {
    const org = await this.prisma.organization.findUnique({ where: { id: orgId } });
    if (!org) {
      throw new NotFoundException(`Organization ${orgId} not found`);
    }

    const memberToInvite = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (!memberToInvite) {
      throw new NotFoundException(`No registered user found with email address "${email}"`);
    }

    if (memberToInvite.organizationId === orgId) {
      throw new ConflictException(`User ${email} is already a member of this organization`);
    }

    const updatedUser = await this.prisma.user.update({
      where: { id: memberToInvite.id },
      data: { organizationId: orgId },
      include: { organization: true },
    });

    return sanitizeUser(updatedUser);
  }

  // 4. Update Organization Settings / Tier
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
