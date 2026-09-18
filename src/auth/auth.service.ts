import { Injectable } from '@nestjs/common';
import { RegisterDto, LoginDto, SiweVerifyDto, UpdateRoleDto } from './dto/auth.dto';
import { UserRole } from '../common/enum';
import {
  RegisterService,
  LoginService,
  SiweService,
  UserProfileService,
  PasswordResetService,
  EmailVerificationService,
} from './services';

@Injectable()
export class AuthService {
  constructor(
    private registerService: RegisterService,
    private loginService: LoginService,
    private siweService: SiweService,
    private userProfileService: UserProfileService,
    private passwordResetService: PasswordResetService,
    private emailVerificationService: EmailVerificationService,
  ) {}

  register(dto: RegisterDto) {
    return this.registerService.register(dto);
  }

  login(dto: LoginDto) {
    return this.loginService.login(dto);
  }

  generateSiweNonce() {
    return this.siweService.generateSiweNonce();
  }

  verifySiwe(dto: SiweVerifyDto) {
    return this.siweService.verifySiwe(dto);
  }

  getUserProfile(userId: string) {
    return this.userProfileService.getUserProfile(userId);
  }

  listUsers(roleFilter?: UserRole) {
    return this.userProfileService.listUsers(roleFilter);
  }

  updateUserRole(userId: string, dto: UpdateRoleDto) {
    return this.userProfileService.updateUserRole(userId, dto);
  }

  requestPasswordReset(email: string) {
    return this.passwordResetService.requestPasswordReset(email);
  }

  resetPassword(token: string, newPass: string) {
    return this.passwordResetService.resetPassword(token, newPass);
  }

  verifyEmail(token: string) {
    return this.emailVerificationService.verifyEmail(token);
  }

  resendVerification(email: string) {
    return this.emailVerificationService.resendVerification(email);
  }
}


