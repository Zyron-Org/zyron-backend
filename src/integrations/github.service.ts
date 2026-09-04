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

  getRepositorySolidityContracts(repoUrl: string, branch = 'main') {
    return this.api.getRepositorySolidityContracts(repoUrl, branch);
  }

  fetchRepoTree(owner: string, repo: string, branch = 'main') {
    return this.api.fetchRepoTree(owner, repo, branch);
  }

  fetchFileContent(owner: string, repo: string, filePath: string, branch = 'main') {
    return this.api.fetchFileContent(owner, repo, filePath, branch);
  }

  postCommentToIssue(owner: string, repo: string, issueNumber: number, body: string) {
    return this.comment.postCommentToIssue(owner, repo, issueNumber, body);
  }
}
