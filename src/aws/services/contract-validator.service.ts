import { Injectable, BadRequestException } from '@nestjs/common';

@Injectable()
export class ContractValidatorService {
  private allowedExtensions = [
    '.sol',    // Solidity (EVM)
    '.rs',     // Rust (Solana, Near, Polkadot, CosmWasm)
    '.vy',     // Vyper (EVM)
    '.move',   // Move (Sui, Aptos)
    '.cairo',  // Cairo (Starknet)
    '.huff',   // Huff (EVM Assembly)
  ];

  getAllowedExtensions(): string[] {
    return this.allowedExtensions;
  }

  validateContractFile(file: { originalname: string; mimetype: string; size: number }) {
    if (!file || !file.originalname) {
      throw new BadRequestException('File payload is missing or invalid');
    }

    const lowerName = file.originalname.toLowerCase();

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

    const maxSizeBytes = 10 * 1024 * 1024;

    if (file.size > maxSizeBytes) {
      throw new BadRequestException(`File size exceeds maximum limit (${maxSizeBytes / (1024 * 1024)}MB)`);
    }
  }
}
