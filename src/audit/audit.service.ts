import { Injectable } from '@nestjs/common';
import { CreateAuditDto, AdvanceStageDto, CreateFindingDto, UpdateFindingDto, CreateCommentDto } from './dto/audit.dto';
import { AuditStage, UserRole } from '../common/enum';
import {
  CreateAuditService,
  GetAuditsService,
  ClaimTicketService,
  AdvanceStageService,
  FindingsService,
  CommentsService,
} from './services';

@Injectable()
export class AuditService {
  constructor(
    private createAuditService: CreateAuditService,
    private getAuditsService: GetAuditsService,
    private claimTicketService: ClaimTicketService,
    private advanceStageService: AdvanceStageService,
    private findingsService: FindingsService,
    private commentsService: CommentsService,
  ) {}

  createAudit(userId: string, organizationId: string | undefined, dto: CreateAuditDto) {
    return this.createAuditService.createAudit(userId, organizationId, dto);
  }

  findAllAudits(userId: string, role: UserRole, organizationId?: string, stageFilter?: AuditStage) {
    return this.getAuditsService.findAllAudits(userId, role, organizationId, stageFilter);
  }

  findOneAudit(auditId: string, userId: string, role: UserRole, organizationId?: string) {
    return this.getAuditsService.findOneAudit(auditId, userId, role, organizationId);
  }

  claimTicket(auditId: string, auditorId: string) {
    return this.claimTicketService.claimTicket(auditId, auditorId);
  }

  advanceStage(auditId: string, dto: AdvanceStageDto) {
    return this.advanceStageService.advanceStage(auditId, dto);
  }

  createFinding(auditId: string, dto: CreateFindingDto) {
    return this.findingsService.createFinding(auditId, dto);
  }

  updateFinding(findingId: string, dto: UpdateFindingDto, userRole: UserRole) {
    return this.findingsService.updateFinding(findingId, dto, userRole);
  }

  findFindingsByAudit(auditId: string) {
    return this.findingsService.findFindingsByAudit(auditId);
  }

  createFindingComment(findingId: string, senderId: string, dto: CreateCommentDto) {
    return this.commentsService.createFindingComment(findingId, senderId, dto);
  }

  findCommentsByFinding(findingId: string) {
    return this.commentsService.findCommentsByFinding(findingId);
  }
}
