import { Controller, Post, Get, Body, Param, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { ScannerService } from './scanner.service';
import { TokenScannerService } from './token-scanner.service';
import { TriggerScanDto, ScanTokenDto } from './dto/scanner.dto';
import { JwtAuthGuard } from '../common/guards';

@ApiTags('Automated Scanner')
@Controller('scanner')
export class ScannerController {
  constructor(
    private scannerService: ScannerService,
    private tokenScanner: TokenScannerService,
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
    return this.tokenScanner.analyzeTokenCode(
      dto.contractFileName,
      `// Token contract analysis for ${dto.contractFileName}`,
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
