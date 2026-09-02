import { Controller, Post, Get, Query, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { StorageService } from './storage.service';
import { JwtAuthGuard } from '../common/guards';

@ApiTags('File Storage')
@ApiBearerAuth()
@Controller('storage')
@UseGuards(JwtAuthGuard)
export class StorageController {
  constructor(private readonly storageService: StorageService) {}

  @Post('presigned-upload')
  @ApiOperation({ summary: 'Generate S3 presigned upload URL for direct contract file upload' })
  @ApiQuery({ name: 'auditId', example: 'ZYR-9481' })
  @ApiQuery({ name: 'filename', example: 'VaultCore.sol' })
  async getPresignedUploadUrl(
    @Query('auditId') auditId: string,
    @Query('filename') filename: string,
  ) {
    return this.storageService.getPresignedUploadUrl(auditId, filename);
  }

  @Get('presigned-download')
  @ApiOperation({ summary: 'Generate S3 presigned download URL for PDF audit report' })
  @ApiQuery({ name: 'key', example: 'audits/ZYR-9481/report.pdf' })
  async getPresignedDownloadUrl(@Query('key') key: string) {
    return this.storageService.getPresignedDownloadUrl(key);
  }
}
