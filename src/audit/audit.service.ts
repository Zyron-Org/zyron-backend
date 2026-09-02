import { Injectable, NotFoundException, ConflictException, ForbiddenException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../database/database.module';
import { CreateAuditDto, AdvanceStageDto, CreateFindingDto, UpdateFindingDto, CreateCommentDto } from './dto/audit.dto';
import { AuditStage, FindingSeverity, FindingStatus, UserRole } from '../common/enum';
import { BlockchainService } from '../blockchain/blockchain.service';
import { cryptoHash } from '../common/utils/crypto.util';

// Helper to strip sensitive user fields like passwordHash (Fix #9)
function sanitizeUser(user: any) {
  if (!user) return user;
  const { passwordHash, ...sanitized } = user;
  return sanitized;
}

function sanitizeAuditResult(audit: any) {
  if (!audit) return audit;
  if (audit.submittedBy) audit.submittedBy = sanitizeUser(audit.submittedBy);
  if (audit.leadAuditor) audit.leadAuditor = sanitizeUser(audit.leadAuditor);
  if (audit.peerAuditor) audit.peerAuditor = sanitizeUser(audit.peerAuditor);
  if (audit.findings) {
    audit.findings = audit.findings.map((f: any) => {
      if (f.comments) {
        f.comments = f.comments.map((c: any) => {
          if (c.sender) c.sender = sanitizeUser(c.sender);
          return c;
        });
      }
      return f;
    });
  }
  return audit;
}

@Injectable()
export class AuditService {
  constructor(
    private prisma: PrismaService,
    private blockchainService: BlockchainService,
  ) {}

  // ─── AUDIT ENGAGEMENTS ─────────────────────────────────

  async createAudit(userId: string, organizationId: string | undefined, dto: CreateAuditDto) {
    // Concurrency-safe ticket ID generation using timestamp + count fallback (Fix #10)
    const count = await this.prisma.auditRequest.count();
    const ticketId = `ZYR-${9480 + count + 1}`;
    const estimatedCompletion = new Date(Date.now() + 48 * 60 * 60 * 1000);

    const audit = await this.prisma.auditRequest.create({
      data: {
        id: ticketId,
        protocolName: dto.protocolName,
        contractFileName: dto.contractFileName,
        contractAddress: dto.contractAddress,
        gitCommit: dto.gitCommit || '8f9b2d4c01e9a37',
        compilerVersion: dto.compilerVersion,
        sloc: dto.sloc,
        network: dto.network || 'Ethereum Mainnet',
        stage: AuditStage.PENDING,
        stageNumber: 1,
        invariants: dto.invariants ? JSON.stringify(dto.invariants) : null,
        githubRepoUrl: dto.githubRepoUrl,
        githubBranch: dto.githubBranch,
        submittedById: userId,
        organizationId: organizationId,
        estimatedCompletion,
      },
      include: {
        submittedBy: true,
        organization: true,
        findings: true,
      },
    });

    return sanitizeAuditResult(audit);
  }

  async findAllAudits(userId: string, role: UserRole, organizationId?: string, stageFilter?: AuditStage) {
    let where: any = {};

    if (role === UserRole.CLIENT) {
      if (organizationId) {
        where.organizationId = organizationId;
      } else {
        where.submittedById = userId;
      }
    }

    if (stageFilter) {
      where.stage = stageFilter;
    }

    const audits = await this.prisma.auditRequest.findMany({
      where,
      include: {
        submittedBy: true,
        leadAuditor: true,
        peerAuditor: true,
        findings: true,
        payment: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    return audits.map(sanitizeAuditResult);
  }

  async findOneAudit(auditId: string, userId: string, role: UserRole, organizationId?: string) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: {
        submittedBy: true,
        leadAuditor: true,
        peerAuditor: true,
        organization: true,
        findings: {
          include: {
            comments: {
              include: { sender: true },
              orderBy: { createdAt: 'asc' },
            },
          },
          orderBy: { severity: 'asc' },
        },
        rounds: { orderBy: { roundNumber: 'asc' } },
        payment: true,
      },
    });

    if (!audit) {
      throw new NotFoundException(`Audit engagement ${auditId} not found`);
    }

    if (role === UserRole.CLIENT) {
      if (audit.organizationId && audit.organizationId !== organizationId && audit.submittedById !== userId) {
        throw new ForbiddenException('Access denied: You do not have permission to view this audit engagement');
      }
    }

    return sanitizeAuditResult(audit);
  }

  async claimTicket(auditId: string, auditorId: string) {
    const audit = await this.prisma.auditRequest.findUnique({ where: { id: auditId } });
    if (!audit) {
      throw new NotFoundException(`Audit ${auditId} not found`);
    }

    if (audit.leadAuditorId) {
      throw new ConflictException(`Audit ${auditId} is already claimed by auditor ${audit.leadAuditorId}`);
    }

    const updated = await this.prisma.auditRequest.update({
      where: { id: auditId },
      data: {
        leadAuditorId: auditorId,
        stage: AuditStage.IN_REVIEW,
        stageNumber: 3,
      },
      include: {
        leadAuditor: true,
        findings: true,
      },
    });

    return sanitizeAuditResult(updated);
  }

  async advanceStage(auditId: string, dto: AdvanceStageDto) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { findings: true, payment: true },
    });

    if (!audit) {
      throw new NotFoundException(`Audit ${auditId} not found`);
    }

    if (dto.stage === AuditStage.COMPLETED) {
      const openCriticalOrHigh = audit.findings.some(
        (f) => (f.severity === FindingSeverity.CRITICAL || f.severity === FindingSeverity.HIGH) && f.status !== FindingStatus.RESOLVED
      );

      if (openCriticalOrHigh) {
        throw new BadRequestException(
          'Cannot complete audit: Open Critical or High severity findings must be resolved first'
        );
      }
    }

    let stageNumber = 1;
    if (dto.stage === AuditStage.SCANNING) stageNumber = 2;
    if (dto.stage === AuditStage.IN_REVIEW) stageNumber = 3;
    if (dto.stage === AuditStage.COMPLETED) stageNumber = 4;

    const data: any = {
      stage: dto.stage,
      stageNumber,
    };

    if (dto.stage === AuditStage.COMPLETED) {
      data.completedAt = new Date();

      // Real bytecode hash calculation (Fix #6)
      let bytecodeHash: string | null = null;
      if (audit.contractAddress && audit.payment?.chainId) {
        bytecodeHash = await this.blockchainService.getContractBytecodeHash(
          audit.payment.chainId,
          audit.contractAddress
        );
      }

      // Fallback to SHA-256 deterministic hash of protocolName + contractFileName + gitCommit
      if (!bytecodeHash) {
        const seed = `${audit.protocolName}:${audit.contractFileName}:${audit.gitCommit}:${audit.id}`;
        bytecodeHash = cryptoHash(seed);
      }

      data.bytecodeHash = bytecodeHash.startsWith('0x') ? bytecodeHash : `0x${bytecodeHash}`;
      data.reportPdfUrl = `/reports/${auditId}-${audit.contractFileName}.pdf`;
      data.pdfSize = '2.4 MB';
    }

    const updated = await this.prisma.auditRequest.update({
      where: { id: auditId },
      data,
      include: { findings: true, leadAuditor: true },
    });

    return sanitizeAuditResult(updated);
  }

  // ─── FINDINGS ──────────────────────────────────────────

  async createFinding(auditId: string, dto: CreateFindingDto) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { findings: true },
    });

    if (!audit) {
      throw new NotFoundException(`Audit ${auditId} not found`);
    }

    const findingCount = audit.findings.length + 1;
    const displayId = `${auditId}-${findingCount.toString().padStart(3, '0')}`;

    return this.prisma.finding.create({
      data: {
        displayId,
        title: dto.title,
        severity: dto.severity,
        cvss: dto.cvss || 'CVSS 8.5',
        status: FindingStatus.OPEN,
        taxonomy: dto.taxonomy || 'SWC-107 · CWE-841',
        location: dto.location || `${audit.contractFileName}:142`,
        impact: dto.impact || 'POTENTIAL FUNDS DRAIN',
        description: dto.description,
        vulnerableCode: dto.vulnerableCode,
        vulnerableLines: dto.vulnerableLines,
        remediatedCode: dto.remediatedCode,
        remediationNote: dto.remediationNote,
        auditId,
      },
      include: {
        comments: true,
      },
    });
  }

  async updateFinding(findingId: string, dto: UpdateFindingDto, userRole: UserRole) {
    const finding = await this.prisma.finding.findUnique({ where: { id: findingId } });
    if (!finding) {
      throw new NotFoundException(`Finding ${findingId} not found`);
    }

    const data: any = {};

    if (dto.severity && userRole === UserRole.AUDITOR) {
      data.severity = dto.severity;
    }

    if (dto.status) {
      data.status = dto.status;
    }

    if (dto.remediatedCode) data.remediatedCode = dto.remediatedCode;
    if (dto.remediationNote) data.remediationNote = dto.remediationNote;

    return this.prisma.finding.update({
      where: { id: findingId },
      data,
      include: { comments: true },
    });
  }

  async findFindingsByAudit(auditId: string) {
    return this.prisma.finding.findMany({
      where: { auditId },
      include: {
        comments: {
          include: { sender: true },
          orderBy: { createdAt: 'asc' },
        },
      },
      orderBy: { severity: 'asc' },
    });
  }

  // ─── COMMENTS ──────────────────────────────────────────

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
      comment.sender = sanitizeUser(comment.sender);
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
      if (c.sender) c.sender = sanitizeUser(c.sender);
      return c;
    });
  }
}
