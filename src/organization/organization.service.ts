import { Injectable } from '@nestjs/common';
import { CreateOrganizationDto, UpdateOrganizationDto } from './dto/organization.dto';
import {
  CreateOrganizationService,
  GetOrganizationService,
  ManageMemberService,
  UpdateOrganizationService,
} from './services';

@Injectable()
export class OrganizationService {
  constructor(
    private createOrgService: CreateOrganizationService,
    private getOrgService: GetOrganizationService,
    private manageMemberService: ManageMemberService,
    private updateOrgService: UpdateOrganizationService,
  ) {}

  createOrganization(userId: string, dto: CreateOrganizationDto) {
    return this.createOrgService.createOrganization(userId, dto);
  }

  getOrganizationForUser(userId: string) {
    return this.getOrgService.getOrganizationForUser(userId);
  }

  addMember(orgId: string, requesterUserId: string, email: string) {
    return this.manageMemberService.addMember(orgId, requesterUserId, email);
  }

  updateOrganization(orgId: string, requesterUserId: string, dto: UpdateOrganizationDto) {
    return this.updateOrgService.updateOrganization(orgId, requesterUserId, dto);
  }
}
