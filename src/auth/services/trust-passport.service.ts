import { Injectable, NotFoundException, ForbiddenException, BadRequestException, Logger } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { EvidenceHasherService } from '../../blockchain/services/evidence-hasher.service';
import { ZYRON_AI_AUDITOR_001 } from '../constants/ai-auditor.constant';

export interface IssueClaimDto {
  claimType: string;
  subject: string;
  evidence: Record<string, any>;
  issuer?: string;
  onChainTxHash?: string;
  onChainChainId?: number;
  onChainTokenId?: number;
  auditId?: string;
}

@Injectable()
export class TrustPassportService {
  private readonly logger = new Logger(TrustPassportService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly evidenceHasher: EvidenceHasherService,
  ) {}

  /**
   * Retrieve existing Trust Passport or auto-provision one for the user.
   */
  async getOrCreatePassport(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new NotFoundException(`User with ID ${userId} not found`);
    }

    let passport = await this.prisma.trustPassport.findUnique({
      where: { userId },
      include: {
        user: true,
        claims: {
          orderBy: { issuedAt: 'desc' },
        },
      },
    });

    if (!passport) {
      const handle =
        user.githubLogin ||
        user.auditorHandle ||
        (user.walletAddress ? `dev-${user.walletAddress.substring(2, 8).toLowerCase()}` : `user-${user.id.substring(0, 8)}`);

      passport = await this.prisma.trustPassport.create({
        data: {
          userId,
          handle,
          title: `${user.name}'s Trust Passport`,
          isVerified: Boolean(user.privyDid || user.githubLogin || user.walletAddress),
          reputationScore: this.calculateInitialReputation(user),
        },
        include: {
          user: true,
          claims: true,
        },
      });

      // Automatically create baseline credential claims
      if (user.privyDid) {
        await this.createInitialClaim(passport.id, {
          claimType: 'DEVELOPER_VERIFIED',
          subject: user.privyDid,
          issuer: 'ZYRON_SYSTEM',
          evidence: {
            method: 'PRIVY_EMBEDDED_IDENTITY',
            walletAddress: user.walletAddress,
            verifiedAt: new Date().toISOString(),
          },
        });
      }

      if (user.githubLogin) {
        await this.createInitialClaim(passport.id, {
          claimType: 'GITHUB_VERIFIED',
          subject: user.githubLogin,
          issuer: 'ZYRON_SYSTEM',
          evidence: {
            githubId: user.githubId,
            githubLogin: user.githubLogin,
            verifiedAt: new Date().toISOString(),
          },
        });
      }
    }

    return {
      ...passport,
      aiAuditor: ZYRON_AI_AUDITOR_001,
    };
  }

  /**
   * Retrieve public Trust Passport by handle or ID.
   */
  async getPassport(idOrHandle: string) {
    const passport = await this.prisma.trustPassport.findFirst({
      where: {
        OR: [
          { id: idOrHandle },
          { handle: idOrHandle },
          { userId: idOrHandle },
          { user: { auditorHandle: idOrHandle } },
          { user: { walletAddress: idOrHandle } },
        ],
      },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            walletAddress: true,
            privyDid: true,
            githubLogin: true,
            githubAvatarUrl: true,
            role: true,
            auditorHandle: true,
          },
        },
        claims: {
          where: { status: 'VERIFIED' },
          orderBy: { issuedAt: 'desc' },
          include: {
            audit: {
              select: {
                id: true,
                protocolName: true,
                contractFileName: true,
                gitCommit: true,
                sloc: true,
                stage: true,
                bytecodeHash: true,
                merkleRoot: true,
                onChainTxHash: true,
                onChainChainId: true,
              },
            },
          },
        },
      },
    });

    if (!passport) {
      throw new NotFoundException(`Trust Passport '${idOrHandle}' not found`);
    }

    return {
      ...passport,
      aiAuditor: ZYRON_AI_AUDITOR_001,
    };
  }

  /**
   * Issue a generic Trust Claim on a passport with authorization check (User A cannot modify User B).
   */
  async issueClaim(authorizedUserId: string, targetPassportId: string, dto: IssueClaimDto) {
    const passport = await this.prisma.trustPassport.findUnique({
      where: { id: targetPassportId },
      include: { user: true },
    });

    if (!passport) {
      throw new NotFoundException(`Passport ${targetPassportId} not found`);
    }

    // Security check: User A cannot modify User B's passport
    if (passport.userId !== authorizedUserId && passport.user?.role !== 'ADMIN') {
      throw new ForbiddenException("Cannot modify another user's Trust Passport");
    }

    const canonicalEvidence = {
      claimType: dto.claimType,
      subject: dto.subject,
      issuer: dto.issuer || 'ZYRON_SYSTEM',
      ...dto.evidence,
    };

    const evidenceHash = this.evidenceHasher.hashEvidence(canonicalEvidence);

    const claim = await this.prisma.trustClaim.create({
      data: {
        passportId: targetPassportId,
        claimType: dto.claimType,
        subject: dto.subject,
        issuer: dto.issuer || 'ZYRON_SYSTEM',
        evidence: JSON.stringify(canonicalEvidence),
        evidenceHash,
        status: 'VERIFIED',
        onChainTxHash: dto.onChainTxHash,
        onChainChainId: dto.onChainChainId || 10143,
        onChainTokenId: dto.onChainTokenId,
        auditId: dto.auditId,
      },
    });

    // Update passport reputation score
    await this.recalculateReputation(targetPassportId);

    return claim;
  }

  /**
   * Automatically issue AUDIT_COMPLETED, CONTRACT_VERIFIED, and AI_AGENT_VERIFIED claims
   * when an audit engagement is completed and attested.
   */
  async recordAuditCompletionClaims(
    auditId: string,
    onChainData?: { onChainTxHash?: string; onChainChainId?: number; onChainTokenId?: number },
  ) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { submittedBy: true, findings: true },
    });

    if (!audit) {
      throw new NotFoundException(`Audit ${auditId} not found`);
    }

    const passport = await this.getOrCreatePassport(audit.submittedById);

    const auditEvidence = this.evidenceHasher.buildAuditClaimEvidence({
      auditId: audit.id,
      protocolName: audit.protocolName,
      contractFileName: audit.contractFileName,
      gitCommit: audit.gitCommit || undefined,
      bytecodeHash: audit.bytecodeHash || undefined,
      merkleRoot: audit.merkleRoot || '0x' + '0'.repeat(64),
      sloc: audit.sloc,
      aiAuditorId: ZYRON_AI_AUDITOR_001.id,
      extraMetadata: {
        findingsCount: audit.findings.length,
        resolvedFindings: audit.findings.filter((f) => f.status === 'RESOLVED').length,
        onChainTxHash: onChainData?.onChainTxHash || audit.onChainTxHash,
        onChainChainId: onChainData?.onChainChainId || audit.onChainChainId || 10143,
      },
    });

    const txHash = onChainData?.onChainTxHash || audit.onChainTxHash || undefined;
    const chainId = onChainData?.onChainChainId || audit.onChainChainId || 10143;
    const tokenId = onChainData?.onChainTokenId;

    // 1. AUDIT_COMPLETED claim
    const auditClaim = await this.prisma.trustClaim.create({
      data: {
        passportId: passport.id,
        claimType: 'AUDIT_COMPLETED',
        subject: audit.contractFileName,
        issuer: ZYRON_AI_AUDITOR_001.id,
        evidence: JSON.stringify(auditEvidence.canonicalPayload),
        evidenceHash: auditEvidence.evidenceHash,
        status: 'VERIFIED',
        onChainTxHash: txHash,
        onChainChainId: chainId,
        onChainTokenId: tokenId,
        auditId: audit.id,
      },
    });

    // 2. CONTRACT_VERIFIED claim
    const contractClaim = await this.prisma.trustClaim.create({
      data: {
        passportId: passport.id,
        claimType: 'CONTRACT_VERIFIED',
        subject: audit.contractAddress || audit.contractFileName,
        issuer: 'ZYRON_SYSTEM',
        evidence: JSON.stringify({
          contractFileName: audit.contractFileName,
          protocolName: audit.protocolName,
          compilerVersion: audit.compilerVersion,
          sloc: audit.sloc,
          merkleRoot: audit.merkleRoot,
        }),
        evidenceHash: this.evidenceHasher.hashEvidence({
          contract: audit.contractAddress || audit.contractFileName,
          merkleRoot: audit.merkleRoot,
        }),
        status: 'VERIFIED',
        onChainTxHash: txHash,
        onChainChainId: chainId,
        onChainTokenId: tokenId,
        auditId: audit.id,
      },
    });

    // 3. AI_AGENT_VERIFIED claim
    const aiClaim = await this.prisma.trustClaim.create({
      data: {
        passportId: passport.id,
        claimType: 'AI_AGENT_VERIFIED',
        subject: audit.id,
        issuer: ZYRON_AI_AUDITOR_001.name,
        evidence: JSON.stringify({
          agentId: ZYRON_AI_AUDITOR_001.id,
          agentName: ZYRON_AI_AUDITOR_001.name,
          engineVersion: ZYRON_AI_AUDITOR_001.version,
          capabilities: ZYRON_AI_AUDITOR_001.capabilities,
          verified: true,
        }),
        evidenceHash: this.evidenceHasher.hashEvidence({
          agent: ZYRON_AI_AUDITOR_001.id,
          auditId: audit.id,
        }),
        status: 'VERIFIED',
        onChainTxHash: txHash,
        onChainChainId: chainId,
        onChainTokenId: tokenId,
        auditId: audit.id,
      },
    });

    await this.recalculateReputation(passport.id);

    return [auditClaim, contractClaim, aiClaim];
  }

  private async createInitialClaim(passportId: string, params: { claimType: string; subject: string; issuer: string; evidence: any }) {
    const evidenceHash = this.evidenceHasher.hashEvidence(params.evidence);
    return this.prisma.trustClaim.create({
      data: {
        passportId,
        claimType: params.claimType,
        subject: params.subject,
        issuer: params.issuer,
        evidence: JSON.stringify(params.evidence),
        evidenceHash,
        status: 'VERIFIED',
      },
    });
  }

  private calculateInitialReputation(user: any): number {
    let score = 100;
    if (user.privyDid) score += 50;
    if (user.walletAddress) score += 25;
    if (user.githubLogin) score += 50;
    return score;
  }

  private async recalculateReputation(passportId: string) {
    const passport = await this.prisma.trustPassport.findUnique({
      where: { id: passportId },
      include: {
        user: true,
        claims: { where: { status: 'VERIFIED' } },
      },
    });

    if (!passport) return;

    let score = this.calculateInitialReputation(passport.user);

    for (const claim of passport.claims) {
      if (claim.claimType === 'AUDIT_COMPLETED') score += 100;
      else if (claim.claimType === 'CONTRACT_VERIFIED') score += 50;
      else if (claim.claimType === 'AI_AGENT_VERIFIED') score += 30;
      else score += 15;
    }

    await this.prisma.trustPassport.update({
      where: { id: passportId },
      data: {
        reputationScore: score,
        isVerified: true,
      },
    });
  }
}
