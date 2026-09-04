import { Module } from '@nestjs/common';
import { OrganizationController } from './organization.controller';
import { OrganizationService } from './organization.service';
import { AuthModule } from '../auth/auth.module';
import {
  CreateOrganizationService,
  GetOrganizationService,
  ManageMemberService,
  UpdateOrganizationService,
} from './services';

@Module({
  imports: [AuthModule],
  controllers: [OrganizationController],
  providers: [
    OrganizationService,
    CreateOrganizationService,
    GetOrganizationService,
    ManageMemberService,
    UpdateOrganizationService,
  ],
  exports: [
    OrganizationService,
    CreateOrganizationService,
    GetOrganizationService,
    ManageMemberService,
    UpdateOrganizationService,
  ],
})
export class OrganizationModule {}
