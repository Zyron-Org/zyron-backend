import { Controller, Post, Body, Headers, HttpCode, HttpStatus, Logger } from '@nestjs/common';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { ScannerService } from './scanner.service';

@ApiTags('GitHub Integration')
@Controller('webhooks/github')
export class GithubWebhookController {
  private readonly logger = new Logger(GithubWebhookController.name);

  constructor(private scannerService: ScannerService) {}

  @Post()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'GitHub Webhook listener for @zyron-bot PR comment triggers' })
  async handleGithubWebhook(
    @Headers('x-github-event') event: string,
    @Body() payload: any,
  ) {
    this.logger.log(`Received GitHub Webhook event: ${event}`);

    // Listen for issue/PR comments
    if (event === 'issue_comment' || event === 'pull_request_review_comment') {
      if (payload.action === 'created') {
        return this.scannerService.processGithubBotMention(payload);
      }
    }

    return { received: true, event };
  }
}
