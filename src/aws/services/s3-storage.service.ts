import { Injectable, BadRequestException } from '@nestjs/common';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { ContractValidatorService } from './contract-validator.service';

@Injectable()
export class S3StorageService {
  private s3Client: S3Client;
  private bucketName: string;

  constructor(private validator: ContractValidatorService) {
    this.bucketName = process.env.AWS_S3_BUCKET || 'zyron-audit-artifacts';
    this.s3Client = new S3Client({
      region: process.env.AWS_REGION || 'us-east-1',
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID || 'mock_key',
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || 'mock_secret',
      },
    });
  }

  generateS3ObjectKey(auditId: string, filename: string): string {
    const timestamp = Date.now();
    const sanitizedFilename = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
    return `audits/${auditId}/${timestamp}-${sanitizedFilename}`;
  }

  async getPresignedUploadUrl(auditId: string, filename: string): Promise<{ uploadUrl: string; objectKey: string }> {
    const lowerName = filename.toLowerCase();

    if (lowerName.endsWith('.zip') || lowerName.endsWith('.tar.gz')) {
      throw new BadRequestException(
        'Archive uploads (.zip, .tar.gz) are temporarily disabled for security reasons. Please upload individual contract source files or link a GitHub repository.',
      );
    }

    const isValidExtension = this.validator.getAllowedExtensions().some((ext) => lowerName.endsWith(ext));
    if (!isValidExtension) {
      throw new BadRequestException(
        `Unsupported contract file format. Allowed extensions: ${this.validator.getAllowedExtensions().join(', ')}`,
      );
    }

    const objectKey = this.generateS3ObjectKey(auditId, filename);
    const command = new PutObjectCommand({
      Bucket: this.bucketName,
      Key: objectKey,
    });

    try {
      const uploadUrl = await getSignedUrl(this.s3Client, command, { expiresIn: 900 });
      return { uploadUrl, objectKey };
    } catch (e: any) {
      return {
        uploadUrl: `https://${this.bucketName}.s3.amazonaws.com/${objectKey}?mock-presigned=true`,
        objectKey,
      };
    }
  }

  async getPresignedDownloadUrl(key: string): Promise<{ downloadUrl: string }> {
    const command = new GetObjectCommand({
      Bucket: this.bucketName,
      Key: key,
    });
    try {
      const downloadUrl = await getSignedUrl(this.s3Client, command, { expiresIn: 3600 });
      return { downloadUrl };
    } catch (e: any) {
      return { downloadUrl: `https://${this.bucketName}.s3.amazonaws.com/${key}?mock-download=true` };
    }
  }
}
