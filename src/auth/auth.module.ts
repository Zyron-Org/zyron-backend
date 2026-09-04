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
  ],
  exports: [
    AuthService,
    RegisterService,
    LoginService,
    SiweService,
    UserProfileService,
    JwtModule,
  ],
})
export class AuthModule {}
