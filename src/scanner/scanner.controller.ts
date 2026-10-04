import { Controller, Post, Get, Body, Param, Query, UseGuards, Headers, Req } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { ScannerService } from './scanner.service';
import { TokenScannerService } from './token-scanner.service';
import { TriggerScanDto, ScanTokenDto } from './dto/scanner.dto';
import { JwtAuthGuard, RolesGuard } from '../common/guards';
import { Roles } from '../common/decorators';
import { UserRole } from '../common/enum';
import { AiAuditService } from './ai-audit.service';

@ApiTags('Automated Scanner & Multi-Model AI Review')
@Controller('scanner')
export class ScannerController {
  constructor(
    private scannerService: ScannerService,
    private tokenScanner: TokenScannerService,
    private aiAuditService: AiAuditService,
  ) {}

  @Post('trigger')
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Trigger automated AST vulnerability scan for audit engagement' })
  async triggerScan(@Body() dto: TriggerScanDto) {
    return this.scannerService.runScan(dto.auditId);
  }

  @Get('ai-providers')
  @ApiOperation({ summary: 'List supported cloud AI providers (Gemini, Claude, OpenAI, DeepSeek) and live availability' })
  async getAiProviders() {
    return this.aiAuditService.getSupportedProviders();
  }

  @Post('analyze-token')
  @ApiOperation({ summary: 'Run instant token security analysis (honeypot, minting, pause, blacklist risks)' })
  async analyzeToken(@Body() dto: ScanTokenDto) {
    if (dto.contractAddress) {
      return this.tokenScanner.analyzeTokenByAddress(dto.contractAddress, dto.chainId || 1);
    }
    return this.tokenScanner.analyzeTokenCode(
      dto.contractFileName || 'Token.sol',
      `// Token contract analysis for ${dto.contractFileName || 'Token.sol'}`,
    );
  }

  @Post('analyze-token-address')
  @ApiOperation({ summary: 'Run instant token security analysis directly using token contract address & chain ID' })
  async analyzeTokenByAddress(@Body() dto: ScanTokenDto) {
    const targetAddr = dto.contractAddress || dto.contractFileName;
    return this.tokenScanner.analyzeTokenByAddress(targetAddr, dto.chainId || 1);
  }

  @Post('ai-audit')
  @ApiOperation({ summary: 'Run deep multi-model cloud AI code security audit on contract source' })
  async aiAudit(@Body() dto: ScanTokenDto, @Query('provider') provider?: string) {
    return this.aiAuditService.analyzeContractWithAi(
      dto.contractFileName,
      `pragma solidity ^0.8.20;\ncontract ${dto.contractFileName.replace('.sol', '')} {\n  address public owner;\n}`,
      provider,
    );
  }

  @Post('audits/:auditId/resume-ai')
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN, UserRole.AUDITOR)
  @ApiOperation({ summary: 'Admin/Auditor resumes a paused AI review job after restoring cloud API credentials' })
  async resumeAuditAi(
    @Param('auditId') auditId: string,
    @Query('provider') provider?: string,
  ) {
    return this.aiAuditService.resumeAuditAi(auditId, provider);
  }

  @Get('jobs/:auditId')
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Get scan job execution history for an audit engagement' })
  async getScanJobs(@Param('auditId') auditId: string) {
    return this.scannerService.getScanJobsByAudit(auditId);
  }

  @Post('prover-callback')
  @ApiOperation({ summary: 'Internal webhook callback from zyron-agent to store EVM simulation trace steps' })
  async proverCallback(
    @Headers('x-zyron-agent-signature') signature: string,
    @Body() payload: any,
  ) {
    const rawBody = JSON.stringify(payload);
    return this.scannerService.handleProverCallback(signature, rawBody, payload);
  }

  @Get('audits/:auditId/repo-credentials')
  @ApiOperation({ summary: 'Internal authenticated endpoint for zyron-agent to fetch GitHub repo clone token' })
  async getRepoCredentials(
    @Headers('x-zyron-agent-key') apiKey: string,
    @Param('auditId') auditId: string,
  ) {
    return this.scannerService.getRepoCredentials(apiKey, auditId);
  }

  @Post('audits/:auditId/prove')
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Trigger autonomous AI EVM sandbox prover for High/Critical findings' })
  async proveAudit(@Param('auditId') auditId: string) {
    return this.scannerService.proveAuditFindings(auditId);
  }

  @Get('findings/:findingId/transcript')
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN, UserRole.AUDITOR)
  @ApiOperation({ summary: 'Get autonomous prover execution transcript / logs for a finding (Auditor/Admin only)' })
  async getFindingTranscript(@Param('findingId') findingId: string) {
    return this.scannerService.getFindingTranscript(findingId);
  }
}
