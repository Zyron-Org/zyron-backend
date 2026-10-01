import { Controller, Post, Get, Patch, Delete, Body, UseGuards, Param, Query, HttpCode, HttpStatus, Redirect, Res, HttpException } from '@nestjs/common';
import { Response } from 'express';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto, SiweVerifyDto, UpdateRoleDto, ForgotPasswordDto, ResetPasswordDto, VerifyEmailDto, ResendVerificationDto } from './dto/auth.dto';
import { JwtAuthGuard, RolesGuard } from '../common/guards';
import { CurrentUser, CurrentUserPayload, Roles, Public } from '../common/decorators';
import { UserRole } from '../common/enum';
import { GithubOAuthService } from './services';
import { GITHUB_CLIENT_ID } from '../config';
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
  async githubLogin(
    @Res() res: Response,
    @Query('redirect') redirect?: string,
    @Query('prompt') prompt?: string,
  ) {
    const url = this.githubOAuthService.getAuthorizationUrl(redirect, prompt);
    return res.redirect(url);
  }

  @Public()
  @Get('github/callback')
  @ApiOperation({ summary: 'GitHub OAuth callback — exchange code for user session JWT' })
  async githubCallback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('error') error: string,
    @Res() res: Response,
  ) {
    if (error || !code) {
      return res.redirect(this.githubOAuthService.buildErrorRedirect(error || 'No authorization code received from GitHub'));
    }

    try {
      const accessToken = await this.githubOAuthService.exchangeCodeForToken(code);
      const user = await this.githubOAuthService.findOrCreateGithubUser(accessToken);
      const jwt = this.githubOAuthService.issueJwt(user);
      return res.redirect(this.githubOAuthService.buildSuccessRedirect(jwt, user, state));
    } catch (e: any) {
      return res.redirect(this.githubOAuthService.buildErrorRedirect(e.message || 'GitHub authentication failed'));
    }
  }

  @UseGuards(JwtAuthGuard)
  @Get('github/repos')
  @ApiBearerAuth()
  @ApiOperation({ summary: "List authenticated user's GitHub repos (supports org filter and private repos)" })
  @ApiQuery({ name: 'org', type: String, required: false, description: 'Optional GitHub organization login to scope repositories' })
  @ApiQuery({ name: 'visibility', enum: ['all', 'public', 'private'], required: false })
  @ApiQuery({ name: 'per_page', type: Number, required: false })
  @ApiQuery({ name: 'page', type: Number, required: false })
  async listGithubRepos(
    @CurrentUser() user: any,
    @Query('org') org?: string,
    @Query('visibility') visibility?: 'all' | 'public' | 'private',
    @Query('per_page') perPage = 100,
    @Query('page') page = 1,
  ) {
    if (!user.githubAccessToken) {
      return { repos: [], message: 'Connect your GitHub account via GitHub login to access private repositories.' };
    }

    try {
      if (org && org !== 'personal') {
        const params: Record<string, any> = {
          type: 'all',
          sort: 'updated',
          per_page: perPage,
          page,
        };

        const res = await axios.get(`https://api.github.com/orgs/${org}/repos`, {
          headers: {
            Authorization: `Bearer ${user.githubAccessToken}`,
            'User-Agent': 'Zyron-Security-Platform',
            Accept: 'application/vnd.github.v3+json',
          },
          params,
        });

        return {
          org,
          repos: res.data.map((r: any) => ({
            id: r.id,
            fullName: r.full_name,
            name: r.name,
            private: r.private,
            defaultBranch: r.default_branch,
            htmlUrl: r.html_url,
            language: r.language,
            description: r.description,
            updatedAt: r.updated_at,
            owner: { login: r.owner.login, avatarUrl: r.owner.avatar_url, type: r.owner.type },
          })),
        };
      }

      // Default: User's personal / collaborator repositories
      const params: Record<string, any> = {
        sort: 'updated',
        per_page: perPage,
        page,
        affiliation: 'owner,collaborator',
      };
      if (visibility && visibility !== 'all') {
        params.visibility = visibility;
      }

      const res = await axios.get('https://api.github.com/user/repos', {
        headers: {
          Authorization: `Bearer ${user.githubAccessToken}`,
          'User-Agent': 'Zyron-Security-Platform',
          Accept: 'application/vnd.github.v3+json',
        },
        params,
      });

      return {
        org: 'personal',
        repos: res.data.map((r: any) => ({
          id: r.id,
          fullName: r.full_name,
          name: r.name,
          private: r.private,
          defaultBranch: r.default_branch,
          htmlUrl: r.html_url,
          language: r.language,
          description: r.description,
          updatedAt: r.updated_at,
          owner: { login: r.owner.login, avatarUrl: r.owner.avatar_url, type: r.owner.type },
        })),
      };
    } catch (err: any) {
      const status = err.response?.status;
      if (status === 401) {
        return { repos: [], message: 'GitHub token expired or revoked. Please reconnect GitHub.' };
      }
      if (status === 403) {
        const ssoHeader = err.response?.headers?.['x-github-sso'];
        return {
          repos: [],
          isRestricted: true,
          org: org || null,
          message: ssoHeader
            ? `SAML Single Sign-On authorization required for organization "${org}".`
            : `Access to organization "${org}" is restricted by third-party application policy. Ask an organization admin to grant access.`,
          approvalUrl: org
            ? `https://github.com/orgs/${org}/settings/oauth_application_policy`
            : 'https://github.com/settings/connections/applications',
        };
      }
      throw new HttpException(
        err.response?.data?.message || 'Failed to fetch GitHub repositories',
        status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @Get('github/orgs')
  @ApiBearerAuth()
  @ApiOperation({ summary: "List authenticated user's GitHub organizations" })
  async listGithubOrgs(@CurrentUser() user: any) {
    if (!user.githubAccessToken) {
      return { orgs: [], message: 'Connect your GitHub account via GitHub login to access organization repositories.' };
    }

    try {
      const orgsRes = await axios.get('https://api.github.com/user/orgs', {
        headers: {
          Authorization: `Bearer ${user.githubAccessToken}`,
          'User-Agent': 'Zyron-Security-Platform',
          Accept: 'application/vnd.github.v3+json',
        },
        params: { per_page: 100 },
      });

      const clientId = GITHUB_CLIENT_ID || process.env.GITHUB_CLIENT_ID || '';
      return {
        orgs: orgsRes.data.map((org: any) => ({
          id: org.id,
          login: org.login,
          avatarUrl: org.avatar_url,
          description: org.description || '',
        })),
        clientId,
        manageAccessUrl: `https://github.com/settings/connections/applications/${clientId}`,
      };
    } catch (err: any) {
      const status = err.response?.status;
      if (status === 401) {
        return { orgs: [], message: 'GitHub token expired or revoked. Please reconnect GitHub.' };
      }
      throw new HttpException(
        err.response?.data?.message || 'Failed to fetch GitHub organizations',
        status || HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @UseGuards(JwtAuthGuard)
  @Delete('github')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Disconnect linked GitHub account from user profile' })
  async unlinkGithub(@CurrentUser() user: any) {
    return this.authService.unlinkGithub(user.id);
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
