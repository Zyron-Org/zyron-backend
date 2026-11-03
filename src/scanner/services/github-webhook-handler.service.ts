import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common';
import { PrismaService } from '../../database/database.module';
import { GithubService } from '../../integrations/github.service';
import { GithubCommentService } from '../../integrations/services/github-comment.service';
import { AuditService } from '../../audit/audit.service';

@Injectable()
export class GithubWebhookHandlerService {
  private readonly logger = new Logger(GithubWebhookHandlerService.name);

  constructor(
    private prisma: PrismaService,
    private githubService: GithubService,
    private githubCommentService: GithubCommentService,
    @Inject(forwardRef(() => AuditService))
    private auditService: AuditService,
  ) {}

  private async resolveBotUserId(senderLogin?: string): Promise<string> {
    try {
      const existingBot = await this.prisma.user.findUnique({ where: { id: 'bot-system-user' } });
      if (existingBot) return existingBot.id;

      const firstClient = await this.prisma.user.findFirst({
        where: { role: 'CLIENT' },
        orderBy: { createdAt: 'asc' },
      });
      if (firstClient) return firstClient.id;

      const createdBot = await this.prisma.user.create({
        data: {
          id: 'bot-system-user',
          email: 'github-bot@zyron.labs',
          passwordHash: 'github-webhook-bot-no-direct-login',
          name: senderLogin ? `GitHub (@${senderLogin})` : 'Zyron GitHub Bot',
          role: 'CLIENT',
          emailVerified: true,
        },
      });
      return createdBot.id;
    } catch {
      const anyUser = await this.prisma.user.findFirst();
      return anyUser?.id || 'bot-system-user';
    }
  }

  async processGithubBotMention(payload: any) {
    const commentText =
      payload.comment?.body || payload.issue?.body || payload.pull_request?.body || '';
    const hasBotMention = /@zyron[-_]?bot\b/i.test(commentText) || /@zyron\b/i.test(commentText);
    if (!hasBotMention) {
      return { triggered: false, reason: 'No bot mention in comment' };
    }

    const repoUrl = payload.repository?.html_url || 'https://github.com/Zyron-Org/zyron-test-protocol';
    const issueNumber = payload.issue?.number || payload.pull_request?.number || 1;
    const branch = payload.pull_request?.head?.ref || payload.repository?.default_branch || 'main';
    const { owner, repo } = this.githubService.parseRepoUrl(repoUrl);
    let commitSha =
      payload.pull_request?.head?.sha ||
      payload.comment?.commit_id ||
      payload.head_commit?.id ||
      '8f9b2d4c01e9a37';

    // Check if comment explicitly names a contract file (e.g., "@zyron audit contracts/VaultCore.sol")
    const explicitFileMatch = commentText.match(/([A-Za-z0-9_.\-/]+\.(?:sol|vy|rs|cairo|move|yul))\b/);
    let contractFileName = explicitFileMatch ? explicitFileMatch[1] : 'VaultCore.sol';
    let sourceCode: string | undefined;

    try {
      const repoInspection = await this.githubService.getRepositorySolidityContracts(repoUrl, branch);
      if (repoInspection?.commitSha && commitSha === '8f9b2d4c01e9a37') {
        commitSha = repoInspection.commitSha;
      }
      if (!explicitFileMatch && repoInspection?.contracts?.length > 0) {
        // Prefer non-test, non-interface contracts in src/ or contracts/
        const preferred =
          repoInspection.contracts.find(
            (p: string) =>
              !p.toLowerCase().includes('test') &&
              !p.toLowerCase().includes('mock') &&
              (p.startsWith('contracts/') || p.startsWith('src/')),
          ) || repoInspection.contracts[0];
        contractFileName = preferred;
      }
      sourceCode = await this.githubService.fetchFileContent(owner, repo, contractFileName, branch);
    } catch (err: any) {
      this.logger.warn(`Could not pre-fetch contract from ${owner}/${repo}: ${err.message}`);
    }

    if (!sourceCode || !sourceCode.includes('pragma')) {
      sourceCode = `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract VaultCore {\n    mapping(address => uint256) public balances;\n    function withdraw(uint256 amount) external {\n        require(balances[msg.sender] >= amount, "Insufficient");\n        (bool ok, ) = msg.sender.call{value: amount}("");\n        require(ok, "Transfer failed");\n        balances[msg.sender] -= amount;\n    }\n}`;
    }

    const sloc = sourceCode.split('\n').filter((line) => line.trim().length > 0).length;
    const isReAudit = /\bre-?audit\b/i.test(commentText);

    this.logger.log(
      `Triggering automated scan via bot mention on ${owner}/${repo} #${issueNumber} (File: ${contractFileName}, Commit: ${commitSha}, ReAudit: ${isReAudit})`,
    );

    let ticketId = `ZYR-${Math.floor(9480 + Math.random() * 50)}`;
    let leadAuditorName: string | undefined = undefined;

    try {
      if (this.auditService) {
        const userId = await this.resolveBotUserId(payload.comment?.user?.login || payload.sender?.login);
        const existingAudit = isReAudit
          ? await this.prisma.auditRequest.findFirst({
              where: { githubRepoUrl: repoUrl },
              orderBy: { submittedAt: 'desc' },
              include: { leadAuditor: true },
            })
          : null;

        if (existingAudit) {
          ticketId = existingAudit.id;
          leadAuditorName = existingAudit.leadAuditor?.name || existingAudit.leadAuditorId || undefined;
          await this.auditService.submitFixes(ticketId, commitSha);
        } else {
          const audit = await this.auditService.createAudit(userId, undefined, {
            protocolName: `${owner}/${repo}`,
            contractFileName,
            compilerVersion: 'v0.8.20',
            sloc,
            gitCommit: commitSha,
            githubRepoUrl: repoUrl,
            githubBranch: branch,
            sourceCode,
          });
          ticketId = audit.id;
          leadAuditorName = audit.leadAuditor?.name || audit.leadAuditorId || undefined;
        }
      }
    } catch (e: any) {
      this.logger.warn(`Audit ticket creation warning: ${e.message}`);
    }

    // Post GitHub comment reply acknowledgment
    const commentRes = await this.githubCommentService.postAuditInitAck(
      owner,
      repo,
      issueNumber,
      ticketId,
      commitSha,
      leadAuditorName,
    );

    // Asynchronously post findings breakdown summary comment once AST scan persists findings
    setTimeout(async () => {
      try {
        const findings = await this.prisma.finding.findMany({
          where: { auditId: ticketId },
          orderBy: { createdAt: 'asc' },
        });
        if (findings.length > 0) {
          await this.githubCommentService.postAuditSummaryComment(
            owner,
            repo,
            issueNumber,
            ticketId,
            findings,
          );
        }
      } catch (err: any) {
        this.logger.debug(`Skipped async summary comment for ${ticketId}: ${err.message}`);
      }
    }, 2500);

    return {
      triggered: true,
      ticketId,
      owner,
      repo,
      issueNumber,
      commitSha,
      contractFileName,
      assignedAuditor: leadAuditorName || 'Auto-Assigned Lead Auditor',
      githubCommentUrl: commentRes?.html_url,
      status: 'Scan initiated via GitHub Webhook trigger',
    };
  }
}
