import { IsString, IsNotEmpty, IsOptional, IsEmail, IsEnum } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateOrganizationDto {
  @ApiProperty({ example: 'Aura Finance DAO', description: 'Official organization or company name' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiPropertyOptional({ example: 'billing@auraprotocol.io', description: 'Corporate billing email' })
  @IsOptional()
  @IsEmail()
  billingEmail?: string;

  @ApiPropertyOptional({ example: 'US948102948', description: 'Tax identification or VAT number' })
  @IsOptional()
  @IsString()
  taxId?: string;

  @ApiPropertyOptional({ example: 'standard', description: 'Subscription tier (standard, enterprise)' })
  @IsOptional()
  @IsString()
  tier?: string;
}

export class UpdateOrganizationDto {
  @ApiPropertyOptional({ example: 'Aura Labs Ltd.', description: 'Updated organization name' })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional({ example: 'finance@auralabs.io', description: 'Updated billing email' })
  @IsOptional()
  @IsEmail()
  billingEmail?: string;

  @ApiPropertyOptional({ example: 'US948102948', description: 'Updated tax ID' })
  @IsOptional()
  @IsString()
  taxId?: string;

  @ApiPropertyOptional({ example: 'enterprise', description: 'Updated subscription tier' })
  @IsOptional()
  @IsString()
  tier?: string;
}

export class AddOrganizationMemberDto {
  @ApiProperty({ example: 'member@auraprotocol.io', description: 'User email to invite/link to organization' })
  @IsEmail()
  @IsNotEmpty()
  email: string;
}
