import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsOptional, IsNumber, Min } from 'class-validator';
import { PaymentMethod, PaymentStatus } from '../../common/enum';

export class RecordEscrowDepositDto {
  @ApiProperty({ example: 'ZYR-9481', description: 'Ticket ID of audit engagement' })
  @IsString()
  @IsNotEmpty()
  auditId: string;

  @ApiProperty({ example: '0x8f9b2d4c01e9a37...', description: 'Transaction hash of escrow deposit' })
  @IsString()
  @IsNotEmpty()
  escrowTxHash: string;

  @ApiProperty({ example: 42161, description: 'Chain ID (e.g. 42161 for Arbitrum One, 1 for Ethereum)' })
  @IsNumber()
  chainId: number;

  @ApiProperty({ example: 12500, description: 'Amount deposited in USDC/USDT units' })
  @IsNumber()
  @Min(1)
  amount: number;

  @ApiPropertyOptional({ example: 'USDC', description: 'Settlement token symbol' })
  @IsOptional()
  @IsString()
  currency?: string;
}

export class GenerateInvoiceDto {
  @ApiProperty({ example: 'ZYR-9481', description: 'Ticket ID of audit engagement' })
  @IsString()
  @IsNotEmpty()
  auditId: string;

  @ApiProperty({ example: 'Aura Finance DAO Ltd.', description: 'Legal corporate or DAO entity name' })
  @IsString()
  @IsNotEmpty()
  companyName: string;

  @ApiProperty({ example: 'finance@auraprotocol.io', description: 'Finance billing email' })
  @IsString()
  @IsNotEmpty()
  billingEmail: string;

  @ApiPropertyOptional({ example: 'EU-948120482', description: 'VAT / Tax ID' })
  @IsOptional()
  @IsString()
  taxId?: string;

  @ApiProperty({ example: 12500, description: 'Invoice total amount in USD' })
  @IsNumber()
  @Min(1)
  amount: number;
}
