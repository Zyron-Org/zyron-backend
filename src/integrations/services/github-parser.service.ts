import { Injectable, BadRequestException } from '@nestjs/common';

export interface GithubRepoTreeItem {
  path: string;
  type: string;
  size?: number;
  sha?: string;
  url?: string;
}

@Injectable()
export class GithubParserService {
  private primaryContractExtensions = [
    '.sol', '.rs', '.vy', '.move', '.cairo', '.huff', '.sw', '.tact', '.func', '.circom', '.zok',
  ];

  private fallbackCodeExtensions = [
    '.ts', '.tsx', '.js', '.jsx', '.py', '.go', '.java', '.cpp', '.c', '.h', '.hpp', '.json', '.yaml', '.yml', '.toml',
  ];

  private ignoredPaths = [
    'node_modules/', '.next/', 'dist/', 'build/', '.git/', 'out/', 'coverage/', 'vendor/',
    'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock',
  ];

  parseRepoUrl(repoUrl: string): { owner: string; repo: string } {
    if (!repoUrl) {
      throw new BadRequestException('Repository URL or shorthand is required');
    }

    const urlMatch = repoUrl.match(/github\.com\/([^\/]+)\/([^\/]+)/);
    if (urlMatch) {
      return { owner: urlMatch[1], repo: urlMatch[2].replace(/\.git$/, '') };
    }

    const parts = repoUrl.split('/');
    if (parts.length === 2 && parts[0].trim() && parts[1].trim()) {
      return { owner: parts[0].trim(), repo: parts[1].trim().replace(/\.git$/, '') };
    }

    throw new BadRequestException('Invalid GitHub repository format (expected owner/repo or https://github.com/owner/repo)');
  }

  filterContractFiles(tree: GithubRepoTreeItem[]): GithubRepoTreeItem[] {
    const validBlobs = tree.filter((item) => {
      if (item.type !== 'blob' || !item.path) return false;
      const lower = item.path.toLowerCase();
      return !this.ignoredPaths.some((ignored) => lower.includes(ignored));
    });

    const primaryMatches = validBlobs.filter((item) => {
      const lower = item.path.toLowerCase();
      return this.primaryContractExtensions.some((ext) => lower.endsWith(ext));
    });

    if (primaryMatches.length > 0) {
      return primaryMatches;
    }

    return validBlobs.filter((item) => {
      const lower = item.path.toLowerCase();
      return this.fallbackCodeExtensions.some((ext) => lower.endsWith(ext));
    });
  }
}
