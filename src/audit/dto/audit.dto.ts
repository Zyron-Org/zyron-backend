import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsOptional, IsInt, Min, IsEnum, IsObject } from 'class-validator';
import { AuditStage, FindingSeverity, FindingStatus } from '../../common/enum';

export class CreateAuditDto {
  @ApiProperty({ example: 'Aura Liquidity Pool V3', description: 'Protocol or project name' })
  @IsString()
  @IsNotEmpty({ message: 'Protocol name is required' })
  protocolName: string;

  @ApiProperty({ example: 'VaultCore.sol', description: 'Primary contract filename' })
  @IsString()
  @IsNotEmpty({ message: 'Contract filename is required' })
  contractFileName: string;

  @ApiPropertyOptional({ example: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', description: 'Target deployed contract address' })
  @IsOptional()
  @IsString()
  contractAddress?: string;

  @ApiPropertyOptional({ example: '8f9b2d4', description: 'Git commit SHA hash' })
  @IsOptional()
  @IsString()
  gitCommit?: string;

  @ApiProperty({ example: 'v0.8.20', description: 'Solidity compiler version' })
  @IsString()
  @IsNotEmpty({ message: 'Solidity compiler version is required' })
  compilerVersion: string;

  @ApiProperty({ example: 2410, description: 'Source lines of code (SLOC)' })
  @IsInt()
  @Min(0, { message: 'SLOC must be a non-negative integer' })
  sloc: number;

  @ApiPropertyOptional({ example: 'pragma solidity ^0.8.20;\ncontract VaultCore {}', description: 'Raw Solidity source code' })
  @IsOptional()
  @IsString()
  sourceCode?: string;

  @ApiPropertyOptional({ example: 'Ethereum Mainnet', description: 'Target blockchain network' })
  @IsOptional()
  @IsString()
  network?: string;

  @ApiPropertyOptional({ example: { reentrancy: true, oracle: true }, description: 'Target attack vectors / invariants' })
  @IsOptional()
  @IsObject()
  invariants?: Record<string, boolean>;

  @ApiPropertyOptional({ example: 'aura-finance/core-vaults', description: 'GitHub repository full name' })
  @IsOptional()
  @IsString()
  githubRepoUrl?: string;

  @ApiPropertyOptional({ example: 'main', description: 'Target Git branch' })
  @IsOptional()
  @IsString()
  githubBranch?: string;
}

export class AdvanceStageDto {
  @ApiProperty({ enum: AuditStage, example: AuditStage.IN_REVIEW, description: 'Target pipeline stage' })
  @IsEnum(AuditStage, { message: 'Invalid audit stage' })
  stage: AuditStage;
}

export class CreateFindingDto {
  @ApiProperty({ example: 'Reentrancy in withdrawAll() allows pool liquidation', description: 'Vulnerability headline' })
  @IsString()
  @IsNotEmpty({ message: 'Title is required' })
  title: string;

  @ApiProperty({ enum: FindingSeverity, example: FindingSeverity.CRITICAL, description: 'Severity classification' })
  @IsEnum(FindingSeverity, { message: 'Invalid severity classification' })
  severity: FindingSeverity;

  @ApiPropertyOptional({ example: 'CVSS 9.1', description: 'CVSS score' })
  @IsOptional()
  @IsString()
  cvss?: string;

  @ApiPropertyOptional({ example: 'SWC-107 · CWE-841', description: 'SWC taxonomy anchor' })
  @IsOptional()
  @IsString()
  taxonomy?: string;

  @ApiPropertyOptional({ example: 'contracts/VaultCore.sol:142', description: 'File & line location' })
  @IsOptional()
  @IsString()
  location?: string;

  @ApiPropertyOptional({ example: '100% COLLATERAL DRAIN', description: 'Vulnerability exploit impact' })
  @IsOptional()
  @IsString()
  impact?: string;

  @ApiProperty({ description: 'Detailed root cause description' })
  @IsString()
  @IsNotEmpty({ message: 'Description is required' })
  description: string;

  @ApiPropertyOptional({ description: 'Vulnerable Solidity code snippet' })
  @IsOptional()
  @IsString()
  vulnerableCode?: string;

  @ApiPropertyOptional({ example: 'Line 142–144', description: 'Vulnerable line numbers' })
  @IsOptional()
  @IsString()
  vulnerableLines?: string;

  @ApiPropertyOptional({ description: 'Remediated Solidity code snippet' })
  @IsOptional()
  @IsString()
  remediatedCode?: string;

  @ApiPropertyOptional({ description: 'Auditor remediation recommendation note' })
  @IsOptional()
  @IsString()
  remediationNote?: string;
}

export class UpdateFindingDto {
  @ApiPropertyOptional({ enum: FindingSeverity })
  @IsOptional()
  @IsEnum(FindingSeverity)
  severity?: FindingSeverity;

  @ApiPropertyOptional({ enum: FindingStatus })
  @IsOptional()
  @IsEnum(FindingStatus)
  status?: FindingStatus;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  remediatedCode?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  remediationNote?: string;
}

export class CreateCommentDto {
  @ApiProperty({ example: 'Applied SafeERC20 wrapper on line 146 & updated unit tests.', description: 'Comment text' })
  @IsString()
  @IsNotEmpty({ message: 'Comment message cannot be empty' })
  message: string;

  @ApiPropertyOptional({ example: '4b8f10e', description: 'Client fix commit SHA reference' })
  @IsOptional()
  @IsString()
  commitRef?: string;
}
