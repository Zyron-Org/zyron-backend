import { Controller, Get, Query, Req, UseGuards } from '@nestjs/common';
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
  @Get('branches')
  @ApiOperation({ summary: 'Fetch all branches for a given GitHub repository' })
  @ApiQuery({ name: 'repoUrl', example: 'https://github.com/Uniswap/v2-core', required: false })
  @ApiQuery({ name: 'owner', example: 'Uniswap', required: false })
  @ApiQuery({ name: 'repo', example: 'v2-core', required: false })
  async getRepositoryBranches(
    @Query('repoUrl') repoUrl?: string,
    @Query('owner') owner?: string,
    @Query('repo') repo?: string,
    @Req() req?: any,
  ) {
    const target = repoUrl || (owner && repo ? `${owner}/${repo}` : '');
    const userToken = req?.user?.githubAccessToken;
    const branches = await this.githubService.getBranches(target, repo, userToken);
    return { branches };
  }

  @Public()
  @Get('contracts')
  @ApiOperation({ summary: 'Inspect GitHub repository and extract Solidity contract files & commit SHA' })
  @ApiQuery({ name: 'repoUrl', example: 'https://github.com/Uniswap/v2-core' })
  @ApiQuery({ name: 'branch', example: 'master', required: false })
  async getRepositoryContracts(
    @Query('repoUrl') repoUrl: string,
    @Query('branch') branch?: string,
    @Req() req?: any,
  ) {
    const userToken = req?.user?.githubAccessToken;
    return this.githubService.getRepositorySolidityContracts(repoUrl, branch || 'main', userToken);
  }

  @Public()
  @Get('file-content')
  @ApiOperation({ summary: 'Fetch raw contract file content from GitHub repository' })
  @ApiQuery({ name: 'owner', example: 'Uniswap' })
  @ApiQuery({ name: 'repo', example: 'v2-core' })
  @ApiQuery({ name: 'filePath', example: 'contracts/UniswapV2Pair.sol' })
  @ApiQuery({ name: 'branch', example: 'master', required: false })
  async getFileContent(
    @Query('owner') owner: string,
    @Query('repo') repo: string,
    @Query('filePath') filePath: string,
    @Query('branch') branch?: string,
    @Req() req?: any,
  ) {
    const userToken = req?.user?.githubAccessToken;
    const content = await this.githubService.fetchFileContent(owner, repo, filePath, branch || 'main', userToken);
    return { content };
  }
}
