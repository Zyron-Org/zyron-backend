import { Controller, Post, Get, Patch, Body, UseGuards, Param, Query, HttpCode, HttpStatus, Redirect, Res } from '@nestjs/common';
import { Response } from 'express';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto, SiweVerifyDto, UpdateRoleDto, ForgotPasswordDto, ResetPasswordDto, VerifyEmailDto, ResendVerificationDto } from './dto/auth.dto';
import { JwtAuthGuard, RolesGuard } from '../common/guards';
import { CurrentUser, CurrentUserPayload, Roles, Public } from '../common/decorators';
import { UserRole } from '../common/enum';
import { GithubOAuthService } from './services';
import axios from 'axios';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly githubOAuthService: GithubOAuthService,
  ) {}

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



  // ── GitHub OAuth ──────────────────────────────────────────────────

  @Public()
  @Get('github')
  @ApiOperation({ summary: 'Redirect user to GitHub OAuth authorization page' })
  async githubLogin(@Res() res: Response) {
    const url = this.githubOAuthService.getAuthorizationUrl();
    return res.redirect(url);
  }

  @Public()
  @Get('github/callback')
  @ApiOperation({ summary: 'GitHub OAuth callback — exchange code for user session JWT' })
  async githubCallback(@Query('code') code: string, @Query('error') error: string, @Res() res: Response) {
    if (error || !code) {
      return res.redirect(this.githubOAuthService.buildErrorRedirect(error || 'No authorization code received from GitHub'));
    }

    try {
      const accessToken = await this.githubOAuthService.exchangeCodeForToken(code);
      const user = await this.githubOAuthService.findOrCreateGithubUser(accessToken);
      const jwt = this.githubOAuthService.issueJwt(user);
      return res.redirect(this.githubOAuthService.buildSuccessRedirect(jwt, user));
    } catch (e: any) {
      return res.redirect(this.githubOAuthService.buildErrorRedirect(e.message || 'GitHub authentication failed'));
    }
  }

  @UseGuards(JwtAuthGuard)
  @Get('github/repos')
  @ApiBearerAuth()
  @ApiOperation({ summary: "List authenticated user's GitHub repos (including private)" })
  @ApiQuery({ name: 'type', enum: ['all', 'public', 'private', 'forks'], required: false })
  @ApiQuery({ name: 'per_page', type: Number, required: false })
  @ApiQuery({ name: 'page', type: Number, required: false })
  async listGithubRepos(
    @CurrentUser() user: any,
    @Query('type') type = 'all',
    @Query('per_page') perPage = 50,
    @Query('page') page = 1,
  ) {
    if (!user.githubAccessToken) {
      return { repos: [], message: 'Connect your GitHub account via GitHub login to access private repositories.' };
    }

    const res = await axios.get('https://api.github.com/user/repos', {
      headers: { Authorization: `Bearer ${user.githubAccessToken}`, 'User-Agent': 'Zyron-Security-Platform' },
      params: { type, sort: 'updated', per_page: perPage, page },
    });

    return {
      repos: res.data.map((r: any) => ({
        id: r.id,
        fullName: r.full_name,
        name: r.name,
        private: r.private,
        defaultBranch: r.default_branch,
        htmlUrl: r.html_url,
        language: r.language,
        updatedAt: r.updated_at,
        owner: { login: r.owner.login, avatarUrl: r.owner.avatar_url },
      })),
    };
  }

  @UseGuards(JwtAuthGuard)
  @Get('github/orgs')
  @ApiBearerAuth()
  @ApiOperation({ summary: "List authenticated user's GitHub organizations and their repositories" })
  async listGithubOrgs(@CurrentUser() user: any) {
    if (!user.githubAccessToken) {
      return { orgs: [], message: 'Connect your GitHub account via GitHub login to access organization repositories.' };
    }

    const orgsRes = await axios.get('https://api.github.com/user/orgs', {
      headers: { Authorization: `Bearer ${user.githubAccessToken}`, 'User-Agent': 'Zyron-Security-Platform' },
      params: { per_page: 50 },
    });

    const orgs = await Promise.all(
      orgsRes.data.map(async (org: any) => {
        try {
          const reposRes = await axios.get(`https://api.github.com/orgs/${org.login}/repos`, {
            headers: { Authorization: `Bearer ${user.githubAccessToken}`, 'User-Agent': 'Zyron-Security-Platform' },
            params: { type: 'all', sort: 'updated', per_page: 50 },
          });
          return {
            login: org.login,
            avatarUrl: org.avatar_url,
            repos: reposRes.data.map((r: any) => ({
              id: r.id,
              fullName: r.full_name,
              name: r.name,
              private: r.private,
              defaultBranch: r.default_branch,
              htmlUrl: r.html_url,
              language: r.language,
              updatedAt: r.updated_at,
            })),
          };
        } catch {
          return { login: org.login, avatarUrl: org.avatar_url, repos: [] };
        }
      }),
    );

    return { orgs };
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
