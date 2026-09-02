import { describe, it, expect, beforeEach } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import { GithubService } from '../src/integrations/github.service';
import { BadRequestException } from '@nestjs/common';

describe('GithubService (Unit Tests)', () => {
  let githubService: GithubService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [GithubService],
    }).compile();

    githubService = module.get<GithubService>(GithubService);
  });

  describe('parseRepoUrl()', () => {
    it('should parse owner and repo name from full GitHub URL', () => {
      const parsed = githubService.parseRepoUrl('https://github.com/aura-finance/core-vaults');
      expect(parsed).toEqual({ owner: 'aura-finance', repo: 'core-vaults' });
    });

    it('should parse shorthand owner/repo string', () => {
      const parsed = githubService.parseRepoUrl('aura-finance/core-vaults');
      expect(parsed).toEqual({ owner: 'aura-finance', repo: 'core-vaults' });
    });

    it('should throw BadRequestException on malformed URL', () => {
      expect(() => githubService.parseRepoUrl('invalid-url-string')).toThrow(BadRequestException);
    });
  });

  describe('filterContractFiles()', () => {
    it('should filter tree items to return multi-chain contract files (.sol, .rs, .vy, .move, .cairo, .huff)', () => {
      const tree = [
        { path: 'contracts/VaultCore.sol', type: 'blob', size: 1200 },
        { path: 'src/lib.rs', type: 'blob', size: 2400 },
        { path: 'contracts/pool.vy', type: 'blob', size: 900 },
        { path: 'sources/coin.move', type: 'blob', size: 1500 },
        { path: 'src/verifier.cairo', type: 'blob', size: 1100 },
        { path: 'src/macro.huff', type: 'blob', size: 600 },
        { path: 'scripts/deploy.js', type: 'blob', size: 400 },
        { path: 'README.md', type: 'blob', size: 500 },
      ];

      const filtered = githubService.filterContractFiles(tree as any);
      expect(filtered).toHaveLength(6);
      expect(filtered.map((f) => f.path)).toEqual([
        'contracts/VaultCore.sol',
        'src/lib.rs',
        'contracts/pool.vy',
        'sources/coin.move',
        'src/verifier.cairo',
        'src/macro.huff',
      ]);
    });
  });
});
