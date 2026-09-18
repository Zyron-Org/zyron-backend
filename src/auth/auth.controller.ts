import { Controller, Post, Get, Patch, Body, UseGuards, Param, Query, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto, SiweVerifyDto, UpdateRoleDto, ForgotPasswordDto, ResetPasswordDto, VerifyEmailDto, ResendVerificationDto } from './dto/auth.dto';
import { JwtAuthGuard, RolesGuard } from '../common/guards';
import { CurrentUser, CurrentUserPayload, Roles, Public } from '../common/decorators';
import { UserRole } from '../common/enum';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register')
  @ApiOperation({ summary: 'Register new client or DAO account' })
  @ApiResponse({ status: 201, description: 'User registered successfully, verification email dispatched' })
  async register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Authenticate user credentials (email & password)' })
  @ApiResponse({ status: 200, description: 'Login successful, returns JWT access token' })
  async login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  @Public()
  @Post('verify-email')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify user email address using single-use cryptographic token' })
  @ApiResponse({ status: 200, description: 'Email verified successfully' })
  async verifyEmail(@Body() dto: VerifyEmailDto) {
    return this.authService.verifyEmail(dto.token);
  }

  @Public()
  @Post('resend-verification')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Resend email verification link' })
  @ApiResponse({ status: 200, description: 'Verification email dispatched if user exists and pending' })
  async resendVerification(@Body() dto: ResendVerificationDto) {
    return this.authService.resendVerification(dto.email);
  }

  @Public()
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Request password reset token link sent via background email' })
  @ApiResponse({ status: 200, description: 'Password reset email dispatched' })
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.authService.requestPasswordReset(dto.email);
  }

  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Reset password using token received via email' })
  @ApiResponse({ status: 200, description: 'Password successfully updated' })
  async resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authService.resetPassword(dto.token, dto.newPassword);
  }



  @Public()
  @Get('siwe/nonce')
  @ApiOperation({ summary: 'Generate EIP-4361 SIWE challenge nonce for Web3 wallet login' })
  async getSiweNonce() {
    return this.authService.generateSiweNonce();
  }

  @Public()
  @Post('siwe/verify')
  @ApiOperation({ summary: 'Verify Web3 wallet signature & authenticate via SIWE' })
  async verifySiwe(@Body() dto: SiweVerifyDto) {
    return this.authService.verifySiwe(dto);
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current authenticated user profile' })
  async getMe(@CurrentUser() user: CurrentUserPayload) {
    return this.authService.getUserProfile(user.id);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current authenticated user profile (alias for /me)' })
  async getProfile(@CurrentUser() user: CurrentUserPayload) {
    return this.authService.getUserProfile(user.id);
  }
}

@ApiTags('User Administration')
@ApiBearerAuth()
@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
export class UsersController {
  constructor(private readonly authService: AuthService) {}

  @Get()
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'List all platform users (Admin only)' })
  @ApiQuery({ name: 'role', enum: UserRole, required: false })
  async listUsers(@Query('role') role?: UserRole) {
    return this.authService.listUsers(role);
  }

  @Patch(':id/role')
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Update user role (Admin only)' })
  async updateRole(@Param('id') userId: string, @Body() dto: UpdateRoleDto) {
    return this.authService.updateUserRole(userId, dto);
  }
}
