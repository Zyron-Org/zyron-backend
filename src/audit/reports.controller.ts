import { Controller, Get, Param, Res } from '@nestjs/common';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { AuditService } from './audit.service';
import { Public } from '../common/decorators';

@ApiTags('Audit Reports & IPFS Delivery')
@Controller('reports')
export class ReportsController {
  constructor(private readonly auditService: AuditService) {}

  @Get(':filename')
  @Public()
  @ApiOperation({ summary: 'Public download or stream signed audit report PDF' })
  async getReportByFilename(@Param('filename') filename: string, @Res() res: any) {
    const { buffer, fileName, ipfsCid } = await this.auditService.getAuditReportPdf(filename);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="${fileName}"`);
    res.setHeader('Content-Length', buffer.length);
    if (ipfsCid) {
      res.setHeader('X-IPFS-CID', ipfsCid);
      res.setHeader('X-IPFS-URI', `ipfs://${ipfsCid}`);
    }
    res.end(buffer);
  }
}
