import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { GithubService } from './github.service';
import { JwtAuthGuard } from '../common/guards';
import { Public } from '../common/decorators';

@ApiTags('GitHub Integration')
@ApiBearerAuth()
@Controller('integrations/github')
@UseGuards(JwtAuthGuard)
export class GithubController {
  constructor(private readonly githubService: GithubService) {}

  @Public()
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

  @Public()
  @Get('file-content')
  @ApiOperation({ summary: 'Fetch raw contract file content from GitHub repository' })
  @ApiQuery({ name: 'owner', example: 'OpenZeppelin' })
  @ApiQuery({ name: 'repo', example: 'openzeppelin-contracts' })
  @ApiQuery({ name: 'filePath', example: 'contracts/token/ERC20/ERC20.sol' })
  @ApiQuery({ name: 'branch', example: 'main', required: false })
  async getFileContent(
    @Query('owner') owner: string,
    @Query('repo') repo: string,
    @Query('filePath') filePath: string,
    @Query('branch') branch?: string,
  ) {
    const content = await this.githubService.fetchFileContent(owner, repo, filePath, branch || 'main');
    return { content };
  }
}
