import { Controller, Post, Get, Patch, Body, UseGuards, Param, Query } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto, SiweVerifyDto, UpdateRoleDto } from './dto/auth.dto';
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
  @ApiResponse({ status: 201, description: 'User registered successfully with access token' })
  async register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Public()
  @Post('login')
  @ApiOperation({ summary: 'Authenticate user credentials (email & password)' })
  @ApiResponse({ status: 200, description: 'Login successful, returns JWT access token' })
  async login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
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
