import { Controller, Post, Get, Patch, Body, Param, Query, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { AuditService } from './audit.service';
import { CreateAuditDto, AdvanceStageDto, CreateFindingDto, UpdateFindingDto, CreateCommentDto } from './dto/audit.dto';
import { JwtAuthGuard, RolesGuard } from '../common/guards';
import { CurrentUser, CurrentUserPayload, Roles } from '../common/decorators';
import { AuditStage, UserRole } from '../common/enum';

@ApiTags('Audit Engagements')
@ApiBearerAuth()
@Controller('audits')
@UseGuards(JwtAuthGuard, RolesGuard)
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  @Post()
  @ApiOperation({ summary: 'Submit new smart contract audit request' })
  @ApiResponse({ status: 201, description: 'Audit request submitted, ticket allocated (e.g. ZYR-9481)' })
  async createAudit(@CurrentUser() user: CurrentUserPayload, @Body() dto: CreateAuditDto) {
    return this.auditService.createAudit(user.id, user.organizationId, dto);
  }

  @Get()
  @ApiOperation({ summary: 'List audit engagements for current user / organization' })
  @ApiQuery({ name: 'stage', enum: AuditStage, required: false })
  async findAllAudits(
    @CurrentUser() user: CurrentUserPayload,
    @Query('stage') stage?: AuditStage,
  ) {
    return this.auditService.findAllAudits(user.id, user.role, user.organizationId, stage);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get audit engagement details, scope, findings, & timeline' })
  async findOneAudit(@Param('id') id: string, @CurrentUser() user: CurrentUserPayload) {
    return this.auditService.findOneAudit(id, user.id, user.role, user.organizationId);
  }

  @Patch(':id/claim')
  @Roles(UserRole.AUDITOR, UserRole.ADMIN)
  @ApiOperation({ summary: 'Claim audit ticket as lead auditor (Auditor / Admin only)' })
  async claimTicket(@Param('id') id: string, @CurrentUser() user: CurrentUserPayload) {
    return this.auditService.claimTicket(id, user.id);
  }

  @Patch(':id/stage')
  @Roles(UserRole.AUDITOR, UserRole.ADMIN)
  @ApiOperation({ summary: 'Advance audit lifecycle stage (Auditor / Admin only)' })
  async advanceStage(@Param('id') id: string, @Body() dto: AdvanceStageDto) {
    return this.auditService.advanceStage(id, dto);
  }

  @Post(':id/findings')
  @Roles(UserRole.AUDITOR, UserRole.ADMIN)
  @ApiOperation({ summary: 'Add vulnerability finding to audit engagement (Auditor / Admin only)' })
  async createFinding(@Param('id') auditId: string, @Body() dto: CreateFindingDto) {
    return this.auditService.createFinding(auditId, dto);
  }

  @Get(':id/findings')
  @ApiOperation({ summary: 'List all findings for an audit engagement' })
  async findFindingsByAudit(@Param('id') auditId: string) {
    return this.auditService.findFindingsByAudit(auditId);
  }
}

@ApiTags('Vulnerability Findings')
@ApiBearerAuth()
@Controller('findings')
@UseGuards(JwtAuthGuard, RolesGuard)
export class FindingController {
  constructor(private readonly auditService: AuditService) {}

  @Patch(':id')
  @Roles(UserRole.AUDITOR, UserRole.ADMIN, UserRole.CLIENT)
  @ApiOperation({ summary: 'Update vulnerability finding status or remediation details' })
  async updateFinding(
    @Param('id') findingId: string,
    @Body() dto: UpdateFindingDto,
    @CurrentUser() user: CurrentUserPayload,
  ) {
    return this.auditService.updateFinding(findingId, dto, user.role);
  }

  @Post(':id/comments')
  @ApiOperation({ summary: 'Post remediation comment thread on a finding (with optional commitRef)' })
  async createComment(
    @Param('id') findingId: string,
    @CurrentUser() user: CurrentUserPayload,
    @Body() dto: CreateCommentDto,
  ) {
    return this.auditService.createFindingComment(findingId, user.id, dto);
  }

  @Get(':id/comments')
  @ApiOperation({ summary: 'Get remediation comment thread for a finding' })
  async findComments(@Param('id') findingId: string) {
    return this.auditService.findCommentsByFinding(findingId);
  }
}
