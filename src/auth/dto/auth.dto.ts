import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsOptional, IsString, MinLength, IsEnum } from 'class-validator';
import { UserRole } from '../../common/enum';

export class RegisterDto {
  @ApiProperty({ example: 'security@auraprotocol.io', description: 'User email address' })
  @IsEmail({}, { message: 'Invalid email address format' })
  email: string;

  @ApiProperty({ example: 'Password123!', description: 'Password (min 8 characters)' })
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  password: string;

  @ApiProperty({ example: 'Aura Core Protocol', description: 'Full name or DAO entity name' })
  @IsString()
  @IsNotEmpty({ message: 'Name is required' })
  name: string;

  @ApiPropertyOptional({ example: 'Aura Finance DAO', description: 'Organization name' })
  @IsOptional()
  @IsString()
  organizationName?: string;
}

export class LoginDto {
  @ApiProperty({ example: 'security@auraprotocol.io', description: 'Registered email' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'Password123!', description: 'User password' })
  @IsString()
  @IsNotEmpty()
  password: string;
}

export class SiweVerifyDto {
  @ApiProperty({ description: 'Full EIP-4361 SIWE message payload string' })
  @IsString()
  @IsNotEmpty()
  message: string;

  @ApiProperty({ description: 'Hex signature string from wallet' })
  @IsString()
  @IsNotEmpty()
  signature: string;
}

export class UpdateRoleDto {
  @ApiProperty({ enum: UserRole, example: UserRole.AUDITOR, description: 'Target user role' })
  @IsEnum(UserRole, { message: 'Invalid user role specified' })
  role: UserRole;
}

export class ForgotPasswordDto {
  @ApiProperty({ example: 'security@auraprotocol.io', description: 'Registered user email address' })
  @IsEmail({}, { message: 'Invalid email address format' })
  email: string;
}

export class ResetPasswordDto {
  @ApiProperty({ description: 'Secure password reset token received via email' })
  @IsString()
  @IsNotEmpty({ message: 'Reset token is required' })
  token: string;

  @ApiProperty({ example: 'NewPassword123!', description: 'New password (min 8 characters)' })
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  newPassword: string;
}

export class VerifyEmailDto {
  @ApiProperty({ description: 'Secure email verification token received via email' })
  @IsString()
  @IsNotEmpty({ message: 'Verification token is required' })
  token: string;
}

export class ResendVerificationDto {
  @ApiProperty({ example: 'security@auraprotocol.io', description: 'Registered user email address' })
  @IsEmail({}, { message: 'Invalid email address format' })
  email: string;
}


