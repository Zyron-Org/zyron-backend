import { IsString, IsNotEmpty, IsOptional, IsEnum, IsNumber } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class TriggerScanDto {
  @ApiProperty({ example: 'ZYR-9481', description: 'Audit engagement ID' })
  @IsString()
  @IsNotEmpty()
  auditId: string;

  @ApiPropertyOptional({ example: 'slither', description: 'Scanner tool name (slither, mythril, token-rules, all)' })
  @IsOptional()
  @IsString()
  tool?: string;
}

export class ScanTokenDto {
  @ApiProperty({ example: 'VaultCore.sol', description: 'Token contract filename or source code' })
  @IsString()
  @IsNotEmpty()
  contractFileName: string;

  @ApiPropertyOptional({ example: '0x1234567890123456789012345678901234567890', description: 'Deployed token address (optional)' })
  @IsOptional()
  @IsString()
  contractAddress?: string;

  @ApiPropertyOptional({ example: 42161, description: 'EVM Chain ID' })
  @IsOptional()
  @IsNumber()
  chainId?: number;
}
