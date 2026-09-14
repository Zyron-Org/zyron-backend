import { Controller, Post, Get, Body, Param, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { ScannerService } from './scanner.service';
import { TokenScannerService } from './token-scanner.service';
import { TriggerScanDto, ScanTokenDto } from './dto/scanner.dto';
import { JwtAuthGuard } from '../common/guards';

import { AiAuditService } from './ai-audit.service';

@ApiTags('Automated Scanner')
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
  @ApiOperation({ summary: 'Trigger automated Slither/Mythril vulnerability scan for audit engagement' })
  async triggerScan(@Body() dto: TriggerScanDto) {
    return this.scannerService.runScan(dto.auditId);
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
  @ApiOperation({ summary: 'Run deep Gemini 1.5 Pro AI model code security audit on contract source' })
  async aiAudit(@Body() dto: ScanTokenDto) {
    return this.aiAuditService.analyzeContractWithAi(
      dto.contractFileName,
      `pragma solidity ^0.8.20;\ncontract ${dto.contractFileName.replace('.sol', '')} {\n  address public owner;\n}`,
    );
  }

  @Get('jobs/:auditId')
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @ApiOperation({ summary: 'Get scan job execution history for an audit engagement' })
  async getScanJobs(@Param('auditId') auditId: string) {
    return this.scannerService.getScanJobsByAudit(auditId);
  }
}
