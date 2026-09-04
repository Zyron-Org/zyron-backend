import { Injectable } from '@nestjs/common';
import { RegisterDto, LoginDto, SiweVerifyDto, UpdateRoleDto } from './dto/auth.dto';
import { UserRole } from '../common/enum';
import {
  RegisterService,
  LoginService,
  SiweService,
  UserProfileService,
} from './services';

@Injectable()
export class AuthService {
  constructor(
    private registerService: RegisterService,
    private loginService: LoginService,
    private siweService: SiweService,
    private userProfileService: UserProfileService,
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
}
