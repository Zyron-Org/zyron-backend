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
  private contractExtensions = ['.sol', '.rs', '.vy', '.move', '.cairo', '.huff'];

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
    return tree.filter((item) => {
      if (item.type !== 'blob' || !item.path) return false;
      const lower = item.path.toLowerCase();
      return this.contractExtensions.some((ext) => lower.endsWith(ext));
    });
  }
}
