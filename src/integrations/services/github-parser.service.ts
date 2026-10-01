import { Injectable, BadRequestException } from '@nestjs/common';

export interface GithubRepoTreeItem {
  path: string;
  type: string;
  size?: number;
  sha?: string;
  url?: string;
}

export const BLOCKCHAIN_CONTRACT_EXTENSIONS = [
  '.sol', // Solidity
  '.vy', // Vyper
  '.cairo', // Cairo (Starknet)
  '.move', // Move (Aptos / Sui)
  '.rs', // Rust (Solana Anchor, CosmWasm, Near, Polkadot/Substrate)
  '.yul', // Yul EVM low-level
  '.tact', // TON Tact
  '.func', // TON FunC
  '.fc', // TON FunC
  '.huff', // Huff EVM low-level
  '.sw', // Sway (Fuel VM)
  '.circom', // Circom ZK
  '.fe', // Fe language
  '.zok', // ZoKrates
];

export function isBlockchainContractFile(filenameOrPath?: string): boolean {
  if (!filenameOrPath) return false;
  const lower = filenameOrPath.toLowerCase().trim();
  return BLOCKCHAIN_CONTRACT_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

export function containsBlockchainMarkers(sourceCode?: string): boolean {
  if (!sourceCode || typeof sourceCode !== 'string') return false;
  const lower = sourceCode.toLowerCase();
  return (
    lower.includes('pragma solidity') ||
    lower.includes('pragma vyper') ||
    lower.includes('contract ') ||
    lower.includes('interface ') ||
    lower.includes('library ') ||
    lower.includes('#[program]') ||
    lower.includes('solana_program') ||
    lower.includes('anchor_lang') ||
    lower.includes('cosmwasm_std') ||
    lower.includes('#[starknet::contract]') ||
    lower.includes('module ') ||
    lower.includes('@openzeppelin') ||
    lower.includes('is initializable') ||
    lower.includes('is ownable') ||
    lower.includes('is erc20') ||
    lower.includes('is erc721')
  );
}

@Injectable()
export class GithubParserService {
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

    return validBlobs.filter((item) => isBlockchainContractFile(item.path));
  }
}

