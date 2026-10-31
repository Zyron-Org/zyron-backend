import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthController, UsersController } from './auth.controller';
import { AuthService } from './auth.service';
import { JWT_SECRET, JWT_EXPIRES_IN } from '../config';
import {
  RegisterService,
  LoginService,
  SiweService,
  UserProfileService,
  PasswordResetService,
  EmailVerificationService,
  GithubOAuthService,
  PrivyAuthService,
  TrustPassportService,
} from './services';
import { PassportController } from './passport.controller';

@Module({
  imports: [
    JwtModule.register({
      secret: JWT_SECRET,
      signOptions: { expiresIn: JWT_EXPIRES_IN as any },
    }),
  ],
  controllers: [AuthController, UsersController, PassportController],
  providers: [
    AuthService,
    RegisterService,
    LoginService,
    SiweService,
    UserProfileService,
    PasswordResetService,
    EmailVerificationService,
    GithubOAuthService,
    PrivyAuthService,
    TrustPassportService,
  ],
  exports: [
    AuthService,
    RegisterService,
    LoginService,
    SiweService,
    UserProfileService,
    PasswordResetService,
    EmailVerificationService,
    GithubOAuthService,
    PrivyAuthService,
    TrustPassportService,
    JwtModule,
  ],
})
export class AuthModule {}


