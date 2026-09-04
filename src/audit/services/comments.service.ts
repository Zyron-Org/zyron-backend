import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { CreateCommentDto } from '../dto/audit.dto';
import { FindingStatus } from '../../common/enum';
import { AuditSanitizerService } from './audit-sanitizer.service';

@Injectable()
export class CommentsService {
  constructor(
    private prisma: PrismaService,
    private sanitizer: AuditSanitizerService,
  ) {}

  async createFindingComment(findingId: string, senderId: string, dto: CreateCommentDto) {
    const finding = await this.prisma.finding.findUnique({
      where: { id: findingId },
      include: { audit: true },
    });

    if (!finding) {
      throw new NotFoundException(`Finding ${findingId} not found`);
    }

    const comment = await this.prisma.comment.create({
      data: {
        message: dto.message,
        commitRef: dto.commitRef,
        senderId,
        findingId,
        auditId: finding.auditId,
      },
      include: {
        sender: true,
      },
    });

    if (dto.commitRef && dto.commitRef.trim().length > 0) {
      await this.prisma.finding.update({
        where: { id: findingId },
        data: { status: FindingStatus.FIX_SUBMITTED },
      });

      await this.prisma.auditRequest.update({
        where: { id: finding.auditId },
        data: { gitCommit: dto.commitRef.trim() },
      });
    }

    if (comment.sender) {
      comment.sender = this.sanitizer.sanitizeUser(comment.sender);
    }

    return comment;
  }

  async findCommentsByFinding(findingId: string) {
    const comments = await this.prisma.comment.findMany({
      where: { findingId },
      include: { sender: true },
      orderBy: { createdAt: 'asc' },
    });

    return comments.map((c) => {
      if (c.sender) c.sender = this.sanitizer.sanitizeUser(c.sender);
      return c;
    });
  }
}
