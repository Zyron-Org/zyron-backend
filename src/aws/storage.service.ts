import { Injectable, BadRequestException } from '@nestjs/common';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

@Injectable()
export class StorageService {
  private s3Client: S3Client;
  private bucketName: string;

  // Allowed contract source extensions across EVM, Solana, Sui, Aptos, Starknet, Near
  // NOTE: Zip and compressed archives (.zip, .tar.gz) are temporarily commented out to prevent malware/zip-bomb attacks.
  private allowedExtensions = [
    '.sol',    // Solidity (EVM)
    '.rs',     // Rust (Solana, Near, Polkadot, CosmWasm)
    '.vy',     // Vyper (EVM)
    '.move',   // Move (Sui, Aptos)
    '.cairo',  // Cairo (Starknet)
    '.huff',   // Huff (EVM Assembly)
    // '.zip',    // Project Archive (Disabled for security)
    // '.tar.gz', // Compressed Archive (Disabled for security)
  ];

  constructor() {
    this.bucketName = process.env.AWS_S3_BUCKET || 'zyron-audit-artifacts';
    this.s3Client = new S3Client({
      region: process.env.AWS_REGION || 'us-east-1',
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID || 'mock_key',
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || 'mock_secret',
      },
    });
  }

  // 1. Multi-Chain File Validation (.sol, .rs, .vy, .move, .cairo, .huff)
  validateContractFile(file: { originalname: string; mimetype: string; size: number }) {
    if (!file || !file.originalname) {
      throw new BadRequestException('File payload is missing or invalid');
    }

    const lowerName = file.originalname.toLowerCase();

    // Check if zip archive is uploaded
    if (lowerName.endsWith('.zip') || lowerName.endsWith('.tar.gz')) {
      throw new BadRequestException(
        'Archive uploads (.zip, .tar.gz) are temporarily disabled for security reasons. Please upload individual contract source files or link a GitHub repository.',
      );
    }

    const isValidExtension = this.allowedExtensions.some((ext) => lowerName.endsWith(ext));

    if (!isValidExtension) {
      throw new BadRequestException(
        `Unsupported contract file format. Allowed extensions: ${this.allowedExtensions.join(', ')}`,
      );
    }

    // Max file size: 10MB for single source files
    const maxSizeBytes = 10 * 1024 * 1024;

    if (file.size > maxSizeBytes) {
      throw new BadRequestException(`File size exceeds maximum limit (${maxSizeBytes / (1024 * 1024)}MB)`);
    }
  }

  // 2. Generate S3 Object Key
  generateS3ObjectKey(auditId: string, filename: string): string {
    const timestamp = Date.now();
    const sanitizedFilename = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
    return `audits/${auditId}/${timestamp}-${sanitizedFilename}`;
  }

  // 3. Generate Presigned Upload URL for Frontend Direct Upload
  async getPresignedUploadUrl(auditId: string, filename: string): Promise<{ uploadUrl: string; objectKey: string }> {
    const lowerName = filename.toLowerCase();

    if (lowerName.endsWith('.zip') || lowerName.endsWith('.tar.gz')) {
      throw new BadRequestException(
        'Archive uploads (.zip, .tar.gz) are temporarily disabled for security reasons. Please upload individual contract source files or link a GitHub repository.',
      );
    }

    const isValidExtension = this.allowedExtensions.some((ext) => lowerName.endsWith(ext));
    if (!isValidExtension) {
      throw new BadRequestException(
        `Unsupported contract file format. Allowed extensions: ${this.allowedExtensions.join(', ')}`,
      );
    }

    const objectKey = this.generateS3ObjectKey(auditId, filename);
    const command = new PutObjectCommand({
      Bucket: this.bucketName,
      Key: objectKey,
    });

    try {
      const uploadUrl = await getSignedUrl(this.s3Client, command, { expiresIn: 900 }); // 15 mins
      return { uploadUrl, objectKey };
    } catch (e: any) {
      return {
        uploadUrl: `https://${this.bucketName}.s3.amazonaws.com/${objectKey}?mock-presigned=true`,
        objectKey,
      };
    }
  }

  // 4. Generate Presigned Download URL for PDF Report Downloads
  async getPresignedDownloadUrl(objectKey: string): Promise<{ downloadUrl: string }> {
    const command = new GetObjectCommand({
      Bucket: this.bucketName,
      Key: objectKey,
    });

    try {
      const downloadUrl = await getSignedUrl(this.s3Client, command, { expiresIn: 3600 });
      return { downloadUrl };
    } catch (e) {
      return { downloadUrl: `https://${this.bucketName}.s3.amazonaws.com/${objectKey}` };
    }
  }
}
