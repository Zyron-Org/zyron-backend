import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { GithubService } from './github.service';
import { JwtAuthGuard } from '../common/guards';

@ApiTags('GitHub Integration')
@ApiBearerAuth()
@Controller('integrations/github')
@UseGuards(JwtAuthGuard)
export class GithubController {
  constructor(private readonly githubService: GithubService) {}

  @Get('contracts')
  @ApiOperation({ summary: 'Inspect GitHub repository and extract Solidity contract files & commit SHA' })
  @ApiQuery({ name: 'repoUrl', example: 'https://github.com/aura-finance/core-vaults' })
  @ApiQuery({ name: 'branch', example: 'main', required: false })
  async getRepositoryContracts(
    @Query('repoUrl') repoUrl: string,
    @Query('branch') branch?: string,
  ) {
    return this.githubService.getRepositorySolidityContracts(repoUrl, branch || 'main');
  }
}
