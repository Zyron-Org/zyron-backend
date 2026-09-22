import { Injectable, UnauthorizedException, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../database/database.module';
import {
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  GITHUB_CALLBACK_URL,
  GITHUB_FRONTEND_REDIRECT,
} from '../../config';
import axios from 'axios';

@Injectable()
export class GithubOAuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  /** Step 1 — Build the GitHub authorization URL to redirect the user to */
  getAuthorizationUrl(state?: string): string {
    if (!GITHUB_CLIENT_ID) {
      throw new UnauthorizedException('GitHub OAuth is not configured on this server. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET.');
    }

    const params = new URLSearchParams({
      client_id: GITHUB_CLIENT_ID,
      redirect_uri: GITHUB_CALLBACK_URL,
      // repo + read:org gives access to private repos AND organization repos
      scope: 'user:email read:user repo read:org',
      ...(state && { state }),
    });

    return `https://github.com/login/oauth/authorize?${params.toString()}`;
  }

  /** Step 2 — Exchange the code GitHub redirects back with for an access token */
  async exchangeCodeForToken(code: string): Promise<string> {
    const res = await axios.post(
      'https://github.com/login/oauth/access_token',
      {
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: GITHUB_CALLBACK_URL,
      },
      { headers: { Accept: 'application/json' } },
    );

    const accessToken: string = res.data?.access_token;
    if (!accessToken) {
      throw new UnauthorizedException('GitHub OAuth token exchange failed. The code may have expired.');
    }

    return accessToken;
  }

  /** Step 3 — Fetch the GitHub user profile using their access token */
  async getGithubUser(accessToken: string): Promise<{
    id: number;
    login: string;
    name: string | null;
    email: string | null;
    avatar_url: string;
  }> {
    const res = await axios.get('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'User-Agent': 'Zyron-Security-Platform',
      },
    });
    return res.data;
  }

  /** Fetch all verified emails from GitHub (primary email may not be in /user) */
  async getGithubEmails(accessToken: string): Promise<string | null> {
    try {
      const res = await axios.get('https://api.github.com/user/emails', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'User-Agent': 'Zyron-Security-Platform',
        },
      });
      const emails: Array<{ email: string; primary: boolean; verified: boolean }> = res.data;
      const primary = emails.find((e) => e.primary && e.verified);
      return primary?.email ?? emails.find((e) => e.verified)?.email ?? null;
    } catch {
      return null;
    }
  }

  /**
   * Step 4 — Find or create a Zyron user from GitHub profile,
   * link GitHub identity if email matches existing account.
   */
  async findOrCreateGithubUser(accessToken: string): Promise<any> {
    const githubUser = await this.getGithubUser(accessToken);
    const githubEmail = await this.getGithubEmails(accessToken);

    const githubId = String(githubUser.id);
    const email = githubEmail ?? githubUser.email ?? `github_${githubId}@noemail.zyron`;
    const name = githubUser.name ?? githubUser.login;

    // Case 1: User already exists with this GitHub ID
    let user = await this.prisma.user.findUnique({
      where: { githubId },
      include: { organization: true },
    });

    if (user) {
      // Refresh the access token on every login
      user = await this.prisma.user.update({
        where: { githubId },
        data: { githubAccessToken: accessToken, githubAvatarUrl: githubUser.avatar_url },
        include: { organization: true },
      });
      return user;
    }

    // Case 2: User exists with same email — link GitHub identity
    const existingByEmail = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (existingByEmail) {
      user = await this.prisma.user.update({
        where: { email: email.toLowerCase() },
        data: {
          githubId,
          githubLogin: githubUser.login,
          githubAccessToken: accessToken,
          githubAvatarUrl: githubUser.avatar_url,
          // Mark email as verified since GitHub already verified it
          emailVerified: true,
          emailVerifiedAt: existingByEmail.emailVerifiedAt ?? new Date(),
          // Use GitHub avatar if none set
          avatarUrl: existingByEmail.avatarUrl ?? githubUser.avatar_url,
        },
        include: { organization: true },
      });
      return user;
    }

    // Case 3: Brand-new user — create from GitHub profile
    user = await this.prisma.user.create({
      data: {
        email: email.toLowerCase(),
        name,
        githubId,
        githubLogin: githubUser.login,
        githubAccessToken: accessToken,
        githubAvatarUrl: githubUser.avatar_url,
        avatarUrl: githubUser.avatar_url,
        // GitHub has already verified their email
        emailVerified: true,
        emailVerifiedAt: new Date(),
        role: 'CLIENT',
      },
      include: { organization: true },
    });

    return user;
  }

  /** Step 5 — Issue a Zyron JWT for the GitHub-authenticated user */
  issueJwt(user: any): string {
    return this.jwtService.sign({
      sub: user.id,
      email: user.email,
      role: user.role,
      organizationId: user.organizationId ?? null,
      walletAddress: user.walletAddress ?? null,
    });
  }

  /** Build the frontend redirect URL after successful OAuth */
  buildSuccessRedirect(token: string, user: any): string {
    const params = new URLSearchParams({
      token,
      role: user.role,
      name: user.name,
      ...(user.githubLogin && { github: user.githubLogin }),
    });
    return `${GITHUB_FRONTEND_REDIRECT}?${params.toString()}`;
  }

  buildErrorRedirect(error: string): string {
    return `${GITHUB_FRONTEND_REDIRECT}?error=${encodeURIComponent(error)}`;
  }
}
