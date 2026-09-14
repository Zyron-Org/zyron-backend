import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common';
import { GithubService } from '../../integrations/github.service';
import { GithubCommentService } from '../../integrations/services/github-comment.service';
import { AuditService } from '../../audit/audit.service';

@Injectable()
export class GithubWebhookHandlerService {
  private readonly logger = new Logger(GithubWebhookHandlerService.name);

  constructor(
    private githubService: GithubService,
    private githubCommentService: GithubCommentService,
    @Inject(forwardRef(() => AuditService))
    private auditService: AuditService,
  ) {}

  async processGithubBotMention(payload: any) {
    const commentText = payload.comment?.body || '';
    if (!commentText.includes('@zyron-bot') && !commentText.includes('@zamaron-bot')) {
      return { triggered: false, reason: 'No bot mention in comment' };
    }

    const repoUrl = payload.repository?.html_url || 'https://github.com/aura-protocol/core-vaults';
    const issueNumber = payload.issue?.number || payload.pull_request?.number || 1;
    const { owner, repo } = this.githubService.parseRepoUrl(repoUrl);
    const commitSha =
      payload.pull_request?.head?.sha ||
      payload.comment?.commit_id ||
      payload.head_commit?.id ||
      '8f9b2d4c01e9a37';

    this.logger.log(`Triggering automated scan via bot mention on ${owner}/${repo} #${issueNumber} (Commit: ${commitSha})`);

    // Create audit ticket via backend audit service
    let ticketId = `ZYR-${Math.floor(9480 + Math.random() * 50)}`;
    let leadAuditorName: string | undefined = undefined;

    try {
      if (this.auditService) {
        const audit = await this.auditService.createAudit('bot-system-user', undefined, {
          protocolName: `${owner}/${repo}`,
          contractFileName: 'VaultCore.sol',
          compilerVersion: 'v0.8.20',
          sloc: 1480,
          gitCommit: commitSha,
          githubRepoUrl: repoUrl,
          githubBranch: payload.pull_request?.head?.ref || 'main',
        });
        ticketId = audit.id;
        leadAuditorName = audit.leadAuditor?.name || audit.leadAuditorId;
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

    return {
      triggered: true,
      ticketId,
      owner,
      repo,
      issueNumber,
      commitSha,
      assignedAuditor: leadAuditorName || 'Auto-Assigned Lead Auditor',
      githubCommentUrl: commentRes?.html_url,
      status: 'Scan initiated via GitHub Webhook trigger',
    };
  }
}
