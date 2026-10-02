import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateAuditDto, AdvanceStageDto, CreateFindingDto, UpdateFindingDto, CreateCommentDto } from './dto/audit.dto';
import { AuditStage, UserRole } from '../common/enum';
import { PrismaService } from '../database/database.module';
import { IpfsService } from '../ipfs/ipfs.service';
import {
  CreateAuditService,
  GetAuditsService,
  ClaimTicketService,
  AdvanceStageService,
  FindingsService,
  CommentsService,
  AutoAssignService,
  ReportGeneratorService,
} from './services';

@Injectable()
export class AuditService {
  constructor(
    private prisma: PrismaService,
    private ipfsService: IpfsService,
    private reportGenerator: ReportGeneratorService,
    private createAuditService: CreateAuditService,
    private getAuditsService: GetAuditsService,
    private claimTicketService: ClaimTicketService,
    private advanceStageService: AdvanceStageService,
    private findingsService: FindingsService,
    private commentsService: CommentsService,
    private autoAssignService: AutoAssignService,
  ) {}

  createAudit(userId: string, organizationId: string | undefined, dto: CreateAuditDto) {
    return this.createAuditService.createAudit(userId, organizationId, dto);
  }

  autoAssignAudit(auditId: string) {
    return this.autoAssignService.autoAssignAudit(auditId);
  }

  findAllAudits(userId: string, role: UserRole, organizationId?: string, stageFilter?: AuditStage) {
    return this.getAuditsService.findAllAudits(userId, role, organizationId, stageFilter);
  }

  getOverviewStats() {
    return this.getAuditsService.getOverviewStats();
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

  deleteFinding(findingId: string, userRole: UserRole) {
    return this.findingsService.deleteFinding(findingId, userRole);
  }

  findFindingsByAudit(auditId: string, role?: UserRole) {
    return this.findingsService.findFindingsByAudit(auditId, role);
  }

  createFindingComment(findingId: string, senderId: string, dto: CreateCommentDto) {
    return this.commentsService.createFindingComment(findingId, senderId, dto);
  }

  findCommentsByFinding(findingId: string) {
    return this.commentsService.findCommentsByFinding(findingId);
  }

  async getAuditReportPdf(auditIdOrFilename: string): Promise<{ buffer: Buffer; fileName: string; ipfsCid?: string }> {
    // Check if filename was provided, e.g. "ZYR-9481-VaultCore.sol.pdf"
    let auditId = auditIdOrFilename.replace(/\.pdf$/i, '');
    if (auditId.includes('-')) {
      const parts = auditId.split('-');
      // If it looks like ZYR-XXXX-...
      if (parts.length >= 2 && parts[0] === 'ZYR') {
        auditId = `${parts[0]}-${parts[1]}`;
      }
    }

    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: {
        findings: true,
        leadAuditor: true,
      },
    });

    if (!audit) {
      throw new NotFoundException(`Audit report for ${auditIdOrFilename} not found`);
    }

    const fileName = `${audit.id}-${audit.contractFileName}.pdf`;

    // Try finding in local IPFS store by CID
    if (audit.ipfsCid) {
      const local = this.ipfsService.getLocalFile(audit.ipfsCid);
      if (local) {
        return { buffer: local.buffer, fileName, ipfsCid: audit.ipfsCid };
      }
    }

    // Synthesize on the fly
    const buffer = await this.reportGenerator.generateAuditReportPdf({
      id: audit.id,
      protocolName: audit.protocolName,
      contractFileName: audit.contractFileName,
      contractAddress: audit.contractAddress,
      gitCommit: audit.gitCommit,
      compilerVersion: audit.compilerVersion,
      network: audit.network,
      sloc: audit.sloc,
      bytecodeHash: audit.bytecodeHash,
      merkleRoot: audit.merkleRoot,
      onChainTxHash: audit.onChainTxHash,
      onChainChainId: audit.onChainChainId,
      ipfsCid: audit.ipfsCid,
      leadAuditorName: audit.leadAuditor?.name || audit.leadAuditor?.auditorHandle || 'Zyron Lead Auditor',
      leadAuditorWallet: audit.leadAuditor?.walletAddress,
      completedAt: audit.completedAt,
      findings: audit.findings.map((f) => ({
        displayId: f.displayId,
        title: f.title,
        severity: f.severity,
        status: f.status,
        taxonomy: f.taxonomy,
        impact: f.impact,
        description: f.description,
        remediationNote: f.remediationNote,
      })),
    });

    return { buffer, fileName, ipfsCid: audit.ipfsCid || undefined };
  }

  async getIpfsAttestation(auditId: string) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      select: {
        id: true,
        protocolName: true,
        contractFileName: true,
        contractAddress: true,
        gitCommit: true,
        bytecodeHash: true,
        merkleRoot: true,
        onChainTxHash: true,
        onChainChainId: true,
        attestationStatus: true,
        ipfsCid: true,
        ipfsReportUrl: true,
        ipfsGatewayUrl: true,
        ipfsMetadataCid: true,
        ipfsPinnedAt: true,
        completedAt: true,
      },
    });

    if (!audit) throw new NotFoundException(`Audit ${auditId} not found`);
    return audit;
  }
}

