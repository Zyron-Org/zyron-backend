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
} from './services';

@Module({
  imports: [
    JwtModule.register({
      secret: JWT_SECRET,
      signOptions: { expiresIn: JWT_EXPIRES_IN as any },
    }),
  ],
  controllers: [AuthController, UsersController],
  providers: [
    AuthService,
    RegisterService,
    LoginService,
    SiweService,
    UserProfileService,
    PasswordResetService,
    EmailVerificationService,
  ],
  exports: [
    AuthService,
    RegisterService,
    LoginService,
    SiweService,
    UserProfileService,
    PasswordResetService,
    EmailVerificationService,
    JwtModule,
  ],
})
export class AuthModule {}


