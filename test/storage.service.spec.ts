import { describe, it, expect, beforeEach } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import { StorageService } from '../src/aws/storage.service';
import { BadRequestException } from '@nestjs/common';

describe('StorageService (Unit Tests)', () => {
  let storageService: StorageService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [StorageService],
    }).compile();

    storageService = module.get<StorageService>(StorageService);
  });

  describe('validateContractFile()', () => {
    it('should allow valid single source contract extensions (.sol, .rs, .vy, .move, .cairo, .huff)', () => {
      const validExtensions = [
        'VaultCore.sol',
        'lib.rs',
        'pool.vy',
        'coin.move',
        'verifier.cairo',
        'macro.huff',
      ];

      validExtensions.forEach((filename) => {
        const file = {
          originalname: filename,
          mimetype: 'text/plain',
          size: 1024 * 50,
        };
        expect(() => storageService.validateContractFile(file as any)).not.toThrow();
      });
    });

    it('should reject zip and archive uploads (.zip, .tar.gz) for security reasons', () => {
      const archiveFiles = ['repository.zip', 'project.tar.gz'];

      archiveFiles.forEach((filename) => {
        const file = {
          originalname: filename,
          mimetype: 'application/zip',
          size: 1024 * 50,
        };
        expect(() => storageService.validateContractFile(file as any)).toThrow(BadRequestException);
      });
    });

    it('should reject unsupported non-contract files (e.g. .exe or .mp4 or .png)', () => {
      const invalidFiles = ['malicious.exe', 'video.mp4', 'image.png', 'script.sh'];

      invalidFiles.forEach((filename) => {
        const file = {
          originalname: filename,
          mimetype: 'application/octet-stream',
          size: 1024 * 10,
        };
        expect(() => storageService.validateContractFile(file as any)).toThrow(BadRequestException);
      });
    });

    it('should reject source files exceeding 10MB limit', () => {
      const oversizedFile = {
        originalname: 'HugeContract.sol',
        mimetype: 'text/plain',
        size: 1024 * 1024 * 15, // 15MB
      };

      expect(() => storageService.validateContractFile(oversizedFile as any)).toThrow(BadRequestException);
    });
  });

  describe('generateS3ObjectKey()', () => {
    it('should format clean S3 object key with audit ID and filename', () => {
      const key = storageService.generateS3ObjectKey('ZYR-9481', 'VaultCore.sol');
      expect(key).toContain('audits/ZYR-9481/');
      expect(key).toContain('VaultCore.sol');
    });
  });
});
