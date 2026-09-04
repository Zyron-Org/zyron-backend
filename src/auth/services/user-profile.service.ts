import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { UpdateRoleDto } from '../dto/auth.dto';
import { UserRole } from '../../common/enum';

@Injectable()
export class UserProfileService {
  constructor(private prisma: PrismaService) {}

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
}
