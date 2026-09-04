import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';

function sanitizeUser(user: any) {
  if (!user) return user;
  const { passwordHash, ...sanitized } = user;
  return sanitized;
}

@Injectable()
export class ManageMemberService {
  constructor(private prisma: PrismaService) {}

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
}
