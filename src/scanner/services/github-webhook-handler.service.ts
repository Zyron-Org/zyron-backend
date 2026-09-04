import { Injectable, Logger } from '@nestjs/common';
import { GithubService } from '../../integrations/github.service';

@Injectable()
export class GithubWebhookHandlerService {
  private readonly logger = new Logger(GithubWebhookHandlerService.name);

  constructor(private githubService: GithubService) {}

  async processGithubBotMention(payload: any) {
    const commentText = payload.comment?.body || '';
    if (!commentText.includes('@zyron-bot') && !commentText.includes('@zamaron-bot')) {
      return { triggered: false, reason: 'No bot mention in comment' };
    }

    const repoUrl = payload.repository?.html_url || '';
    const issueNumber = payload.issue?.number || payload.pull_request?.number || 1;
    const { owner, repo } = this.githubService.parseRepoUrl(repoUrl);

    this.logger.log(`Triggering automated scan via bot mention on ${owner}/${repo} #${issueNumber}`);
    return {
      triggered: true,
      owner,
      repo,
      issueNumber,
      status: 'Scan initiated via GitHub Webhook trigger',
    };
  }
}
