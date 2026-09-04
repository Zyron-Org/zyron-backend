import { Injectable } from '@nestjs/common';
import { ContractValidatorService, S3StorageService } from './services';

@Injectable()
export class StorageService {
  constructor(
    private validator: ContractValidatorService,
    private s3Storage: S3StorageService,
  ) {}

  validateContractFile(file: { originalname: string; mimetype: string; size: number }) {
    return this.validator.validateContractFile(file);
  }

  generateS3ObjectKey(auditId: string, filename: string): string {
    return this.s3Storage.generateS3ObjectKey(auditId, filename);
  }

  getPresignedUploadUrl(auditId: string, filename: string) {
    return this.s3Storage.getPresignedUploadUrl(auditId, filename);
  }

  getPresignedDownloadUrl(key: string) {
    return this.s3Storage.getPresignedDownloadUrl(key);
  }
}
