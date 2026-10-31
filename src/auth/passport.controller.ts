import { Controller, Get, Post, Body, Param, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { TrustPassportService } from './services/trust-passport.service';
import { JwtAuthGuard } from '../common/guards';
import { CurrentUser, CurrentUserPayload, Public } from '../common/decorators';
import { IsString, IsNotEmpty, IsOptional, IsObject } from 'class-validator';

export class IssueClaimBodyDto {
  @IsString()
  @IsNotEmpty()
  claimType: string;

  @IsString()
  @IsNotEmpty()
  subject: string;

  @IsObject()
  evidence: Record<string, any>;

  @IsOptional()
  @IsString()
  issuer?: string;

  @IsOptional()
  @IsString()
  onChainTxHash?: string;
}

@ApiTags('Trust Passport')
@Controller('passport')
export class PassportController {
  constructor(private readonly passportService: TrustPassportService) {}

  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiBearerAuth()
  @ApiOperation({ summary: "Get current authenticated user's Trust Passport" })
  @ApiResponse({ status: 200, description: 'User Trust Passport returned successfully' })
  async getMyPassport(@CurrentUser() user: CurrentUserPayload) {
    return this.passportService.getOrCreatePassport(user.id);
  }

  @Public()
  @Get(':idOrHandle')
  @ApiOperation({ summary: 'Get public Trust Passport by user ID or handle' })
  @ApiResponse({ status: 200, description: 'Public Trust Passport returned successfully' })
  async getPublicPassport(@Param('idOrHandle') idOrHandle: string) {
    return this.passportService.getPassport(idOrHandle);
  }

  @UseGuards(JwtAuthGuard)
  @Post('claims')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Issue a verifiable Trust Claim on current user passport' })
  @ApiResponse({ status: 201, description: 'Trust Claim issued with canonical evidence hash' })
  async issueClaim(
    @CurrentUser() user: CurrentUserPayload,
    @Body() dto: IssueClaimBodyDto,
  ) {
    const passport = await this.passportService.getOrCreatePassport(user.id);
    return this.passportService.issueClaim(user.id, passport.id, dto);
  }
}
