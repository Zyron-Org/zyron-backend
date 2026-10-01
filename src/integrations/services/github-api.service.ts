import { Injectable } from '@nestjs/common';
import axios from 'axios';
import { GithubParserService, GithubRepoTreeItem } from './github-parser.service';

@Injectable()
export class GithubApiService {
  private githubApiUrl = 'https://api.github.com';

  constructor(private parser: GithubParserService) {}

  private getHeaders(accessToken?: string) {
    const headers: Record<string, string> = {
      'User-Agent': 'Zyron-Security-Platform',
    };
    const token = accessToken || process.env.GITHUB_TOKEN;
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    return headers;
  }

  async getRepositorySolidityContracts(repoUrl: string, branch = 'main', accessToken?: string) {
    const { owner, repo } = this.parser.parseRepoUrl(repoUrl);
    const { contracts, commitSha, isInspected, totalFiles } = await this.fetchRepoTree(owner, repo, branch, accessToken);
    const hasBlockchainFiles = contracts.length > 0;
    return {
      owner,
      repo,
      branch,
      commitSha,
      contracts,
      total: contracts.length,
      hasBlockchainFiles,
      isInspected,
      totalFiles,
      message: hasBlockchainFiles
        ? undefined
        : isInspected
        ? 'No blockchain smart contract files (.sol, .vy, .rs, .cairo, .move, .yul, .tact) detected in this repository.'
        : 'Could not inspect repository files. Please verify repository access permissions.',
    };
  }

  async fetchBranches(owner: string, repo: string, accessToken?: string): Promise<string[]> {
    try {
      const res = await axios.get(`${this.githubApiUrl}/repos/${owner}/${repo}/branches`, {
        headers: this.getHeaders(accessToken),
        timeout: 8000,
        params: { per_page: 100 },
      });
      return (res.data || []).map((b: any) => b.name);
    } catch (e: any) {
      return ['main', 'master', 'develop'];
    }
  }

  async fetchRepoTree(
    owner: string,
    repo: string,
    branch = 'main',
    accessToken?: string,
  ): Promise<{ contracts: string[]; commitSha?: string; isInspected: boolean; totalFiles: number }> {
    let commitSha: string | undefined;

    // Try fetching latest commit SHA
    try {
      const commitRes = await axios.get(`${this.githubApiUrl}/repos/${owner}/${repo}/commits/${branch}`, {
        headers: this.getHeaders(accessToken),
        timeout: 6000,
      });
      commitSha = commitRes.data?.sha;
    } catch {}

    try {
      const treeRes = await axios.get(`${this.githubApiUrl}/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`, {
        headers: this.getHeaders(accessToken),
        timeout: 10000,
      });

      const allFiles: GithubRepoTreeItem[] = treeRes.data.tree || [];
      const contractFiles = this.parser.filterContractFiles(allFiles);
      return {
        contracts: contractFiles.map((f) => f.path),
        commitSha,
        isInspected: true,
        totalFiles: allFiles.length,
      };
    } catch (e) {
      return { contracts: [], commitSha, isInspected: false, totalFiles: 0 };
    }
  }

  async fetchFileContent(owner: string, repo: string, filePath: string, branch = 'main', accessToken?: string): Promise<string> {
    const headers = this.getHeaders(accessToken);

    // Try GitHub API contents endpoint first with raw accept header (handles both private & public)
    try {
      const res = await axios.get(`${this.githubApiUrl}/repos/${owner}/${repo}/contents/${filePath}?ref=${branch}`, {
        headers: {
          ...headers,
          Accept: 'application/vnd.github.v3.raw',
        },
        timeout: 8000,
      });
      return typeof res.data === 'string' ? res.data : JSON.stringify(res.data, null, 2);
    } catch (apiErr) {
      // Fallback to raw.githubusercontent.com
      try {
        const rawRes = await axios.get(`https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${filePath}`, {
          headers: accessToken ? { ...headers, Authorization: `token ${accessToken}` } : headers,
          timeout: 6000,
        });
        return typeof rawRes.data === 'string' ? rawRes.data : JSON.stringify(rawRes.data, null, 2);
      } catch (rawErr) {
        return `// Contract source code for ${filePath}\npragma solidity ^0.8.20;\ncontract TargetContract {\n    // Ingested via Zyron Platform\n}`;
      }
    }
  }
}
