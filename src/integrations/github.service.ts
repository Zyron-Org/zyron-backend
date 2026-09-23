import { Injectable } from '@nestjs/common';
import {
  GithubParserService,
  GithubApiService,
  GithubCommentService,
  GithubRepoTreeItem,
} from './services';

@Injectable()
export class GithubService {
  constructor(
    private parser: GithubParserService,
    private api: GithubApiService,
    private comment: GithubCommentService,
  ) {}

  parseRepoUrl(repoUrl: string) {
    return this.parser.parseRepoUrl(repoUrl);
  }

  filterContractFiles(tree: GithubRepoTreeItem[]) {
    return this.parser.filterContractFiles(tree);
  }

  getBranches(repoUrlOrOwner: string, repo?: string, accessToken?: string) {
    let owner = repoUrlOrOwner;
    let repository = repo;
    if (!repository || repoUrlOrOwner.includes('/') || repoUrlOrOwner.includes('http')) {
      const parsed = this.parser.parseRepoUrl(repoUrlOrOwner);
      owner = parsed.owner;
      repository = parsed.repo;
    }
    return this.api.fetchBranches(owner, repository!, accessToken);
  }

  getRepositorySolidityContracts(repoUrl: string, branch = 'main', accessToken?: string) {
    return this.api.getRepositorySolidityContracts(repoUrl, branch, accessToken);
  }

  fetchRepoTree(owner: string, repo: string, branch = 'main', accessToken?: string) {
    return this.api.fetchRepoTree(owner, repo, branch, accessToken);
  }

  fetchFileContent(owner: string, repo: string, filePath: string, branch = 'main', accessToken?: string) {
    return this.api.fetchFileContent(owner, repo, filePath, branch, accessToken);
  }

  postCommentToIssue(owner: string, repo: string, issueNumber: number, body: string) {
    return this.comment.postCommentToIssue(owner, repo, issueNumber, body);
  }
}
