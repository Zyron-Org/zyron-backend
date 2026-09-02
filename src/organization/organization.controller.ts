import { Controller, Get, Post, Patch, Body, Param, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { OrganizationService } from './organization.service';
import { CreateOrganizationDto, UpdateOrganizationDto, AddOrganizationMemberDto } from './dto/organization.dto';
import { JwtAuthGuard } from '../common/guards';
import { CurrentUser } from '../common/decorators';

@ApiTags('Organizations')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('organizations')
export class OrganizationController {
  constructor(private orgService: OrganizationService) {}

  @Post()
  @ApiOperation({ summary: 'Create a new organization and link current user' })
  async createOrganization(@CurrentUser() user: any, @Body() dto: CreateOrganizationDto) {
    return this.orgService.createOrganization(user.id, dto);
  }

  @Get('me')
  @ApiOperation({ summary: 'Get current user organization profile, tier, and member list' })
  async getMyOrganization(@CurrentUser() user: any) {
    return this.orgService.getOrganizationForUser(user.id);
  }

  @Post(':id/members')
  @ApiOperation({ summary: 'Invite or add a registered user to the organization by email' })
  async addMember(
    @Param('id') orgId: string,
    @CurrentUser() user: any,
    @Body() dto: AddOrganizationMemberDto,
  ) {
    return this.orgService.addMember(orgId, user.id, dto.email);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update organization settings, billing info, or subscription tier' })
  async updateOrganization(
    @Param('id') orgId: string,
    @CurrentUser() user: any,
    @Body() dto: UpdateOrganizationDto,
  ) {
    return this.orgService.updateOrganization(orgId, user.id, dto);
  }
}
