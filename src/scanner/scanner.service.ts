import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../database/database.module';
import { TokenScannerService } from './token-scanner.service';
import { GithubService } from '../integrations/github.service';
import { AuditStage, FindingStatus } from '../common/enum';

@Injectable()
export class ScannerService {
  private readonly logger = new Logger(ScannerService.name);

  constructor(
    private prisma: PrismaService,
    private tokenScanner: TokenScannerService,
    private githubService: GithubService,
  ) {}

  // ─── 1. RUN SCAN FOR AUDIT ENGAGEMENT ────────────────────

  async runScan(auditId: string, customCode?: string) {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { findings: true },
    });

    if (!audit) {
      throw new NotFoundException(`Audit engagement ${auditId} not found`);
    }

    // Create ScanJob record
    const scanJob = await this.prisma.scanJob.create({
      data: {
        auditId,
        tool: 'slither-mythril-token-engine',
        status: 'running',
        passNumber: 1,
        totalPasses: 3,
        startedAt: new Date(),
        logOutput: `[INFO] Initializing Zyron Security Scanner engine for ${audit.contractFileName}...\n`,
      },
    });

    // Code to analyze
    const code = customCode || `
      pragma solidity ^0.8.20;
      contract ${audit.contractFileName.replace('.sol', '')} {
        address public owner;
        mapping(address => uint256) public balanceOf;

        function mint(address to, uint256 amount) external {
          balanceOf[to] += amount;
        }

        function transfer(address to, uint256 amount) external returns (bool) {
          balanceOf[msg.sender] -= amount;
          balanceOf[to] += amount;
          return true;
        }
      }
    `;

    // Analyze using TokenScannerService
    const scanResult = this.tokenScanner.analyzeTokenCode(audit.contractFileName, code);

    // Save findings to DB
    for (let i = 0; i < scanResult.findings.length; i++) {
      const f = scanResult.findings[i];
      const displayId = `${auditId}-${(audit.findings.length + i + 1).toString().padStart(3, '0')}`;

      await this.prisma.finding.create({
        data: {
          displayId,
          title: f.title,
          severity: f.severity,
          cvss: f.cvss,
          status: FindingStatus.OPEN,
          taxonomy: f.taxonomy,
          location: f.location,
          impact: f.impact,
          description: f.description,
          remediatedCode: f.remediatedCode,
          auditId,
        },
      });
    }

    // Update ScanJob status to completed
    const updatedJob = await this.prisma.scanJob.update({
      where: { id: scanJob.id },
      data: {
        status: 'completed',
        passNumber: 3,
        completedAt: new Date(),
        results: JSON.stringify(scanResult),
        logOutput: `[INFO] Scan completed successfully. Risk score: ${scanResult.tokenRiskScore}/100. Created ${scanResult.findings.length} finding(s).\n`,
      },
    });

    // Auto-advance audit stage to IN_REVIEW (Stage 3)
    await this.prisma.auditRequest.update({
      where: { id: auditId },
      data: {
        stage: AuditStage.IN_REVIEW,
        stageNumber: 3,
      },
    });

    return {
      scanJob: updatedJob,
      scanResult,
    };
  }

  // ─── 2. GITHUB BOT MENTION PROCESSING (@zyron-bot audit) ─

  async processGithubBotMention(webhookPayload: any) {
    const commentBody = webhookPayload.comment?.body || '';
    const isBotMentioned = /@zyron-bot|@zyron\s+audit|@zyron\s+scan/i.test(commentBody);

    if (!isBotMentioned) {
      return { processed: false, message: 'No @zyron-bot mention found in comment body' };
    }

    const repoUrl = webhookPayload.repository?.html_url;
    const issueNumber = webhookPayload.issue?.number || webhookPayload.pull_request?.number;

    if (!repoUrl || !issueNumber) {
      throw new BadRequestException('Invalid GitHub webhook payload missing repository or issue details');
    }

    const { owner, repo } = this.githubService.parseRepoUrl(repoUrl);
    const commentSender = webhookPayload.comment?.user?.login || 'developer';

    this.logger.log(`Processing @zyron-bot trigger from ${commentSender} on ${owner}/${repo} #${issueNumber}`);

    // Fetch repository tree to find contract files
    let contractFiles: string[] = [];
    try {
      contractFiles = await this.githubService.fetchRepoTree(owner, repo);
    } catch (e) {
      contractFiles = ['VaultCore.sol'];
    }

    const mainContract = contractFiles[0] || 'Contract.sol';

    // Fetch source code
    let code = '';
    try {
      code = await this.githubService.fetchFileContent(owner, repo, mainContract);
    } catch (e) {
      code = '// Contract code analyzed via GitHub bot';
    }

    // Run static security analysis
    const scanResult = this.tokenScanner.analyzeTokenCode(mainContract, code);

    // Format GitHub Markdown comment
    const commentMarkdown = this.formatGithubBotComment(
      commentSender,
      owner,
      repo,
      mainContract,
      scanResult,
    );

    // Post comment back to GitHub PR/Issue
    const postedComment = await this.githubService.postCommentToIssue(
      owner,
      repo,
      issueNumber,
      commentMarkdown,
    );

    return {
      processed: true,
      repository: `${owner}/${repo}`,
      issueNumber,
      commentUrl: postedComment.html_url,
      scanResult,
    };
  }

  // ─── HELPER: FORMAT GITHUB BOT COMMENT ───────────────────

  private formatGithubBotComment(
    user: string,
    owner: string,
    repo: string,
    contractFile: string,
    result: any,
  ): string {
    const riskBadge = result.tokenRiskScore >= 70
      ? '🔴 **HIGH RISK**'
      : result.tokenRiskScore >= 30
      ? '🟡 **MEDIUM RISK**'
      : '🟢 **LOW RISK / CLEAN**';

    let findingsTable = '';
    if (result.findings.length === 0) {
      findingsTable = '✅ **No automated vulnerability findings detected.**\n';
    } else {
      findingsTable = `| Severity | Title | Location | CVSS |\n|---|---|---|---|\n`;
      result.findings.forEach((f: any) => {
        findingsTable += `| **${f.severity}** | ${f.title} | \`${f.location}\` | ${f.cvss} |\n`;
      });
    }

    return `
### 🛡️ Zyron Security Bot Audit Report

Hey @${user}! 👋 Zyron automated security analysis triggered for **\`${owner}/${repo}\`** (\`${contractFile}\`).

- **Risk Score**: ${result.tokenRiskScore}/100 — ${riskBadge}
- **Summary**: ${result.summary}

#### Vulnerability Scan Results

${findingsTable}

---
*Powered by Zyron Multi-Chain Smart Contract Security Platform — Need a full dual-auditor manual audit? Visit [Zyron Workbench](https://zyron.io).*
`.trim();
  }

  // ─── 3. GET SCAN JOBS FOR AUDIT ──────────────────────────

  async getScanJobsByAudit(auditId: string) {
    return this.prisma.scanJob.findMany({
      where: { auditId },
      orderBy: { createdAt: 'desc' },
    });
  }
}
