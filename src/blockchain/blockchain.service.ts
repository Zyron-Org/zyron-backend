import { Injectable, Logger } from '@nestjs/common';
import { ethers } from 'ethers';

export interface ChainConfig {
  chainId: number;
  name: string;
  rpcUrl: string;
  explorerUrl: string;
  escrowAddress: string;
  attestationAddress: string;
  nativeUsdcAddress: string;
}

@Injectable()
export class BlockchainService {
  private readonly logger = new Logger(BlockchainService.name);
  private providers: Map<number, ethers.JsonRpcProvider> = new Map();

  // Multi-chain configuration registry
  private chains: Map<number, ChainConfig> = new Map([
    [42161, {
      chainId: 42161,
      name: 'Arbitrum One',
      rpcUrl: process.env.ARBITRUM_RPC_URL || 'https://arb1.arbitrum.io/rpc',
      explorerUrl: 'https://arbiscan.io',
      escrowAddress: process.env.ARBITRUM_ESCROW_ADDRESS || '',
      attestationAddress: process.env.ARBITRUM_ATTESTATION_ADDRESS || '',
      nativeUsdcAddress: '0xaf88d065e77c8cC2239327C5EDb3A432268e5831',
    }],
    [421614, {
      chainId: 421614,
      name: 'Arbitrum Sepolia',
      rpcUrl: process.env.ARBITRUM_SEPOLIA_RPC_URL || 'https://sepolia-rollup.arbitrum.io/rpc',
      explorerUrl: 'https://sepolia.arbiscan.io',
      escrowAddress: process.env.ARBITRUM_SEPOLIA_ESCROW_ADDRESS || '',
      attestationAddress: process.env.ARBITRUM_SEPOLIA_ATTESTATION_ADDRESS || '',
      nativeUsdcAddress: '',
    }],
    [8453, {
      chainId: 8453,
      name: 'Base',
      rpcUrl: process.env.BASE_RPC_URL || 'https://mainnet.base.org',
      explorerUrl: 'https://basescan.org',
      escrowAddress: process.env.BASE_ESCROW_ADDRESS || '',
      attestationAddress: process.env.BASE_ATTESTATION_ADDRESS || '',
      nativeUsdcAddress: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    }],
    [84532, {
      chainId: 84532,
      name: 'Base Sepolia',
      rpcUrl: process.env.BASE_SEPOLIA_RPC_URL || 'https://sepolia.base.org',
      explorerUrl: 'https://sepolia.basescan.org',
      escrowAddress: process.env.BASE_SEPOLIA_ESCROW_ADDRESS || '',
      attestationAddress: process.env.BASE_SEPOLIA_ATTESTATION_ADDRESS || '',
      nativeUsdcAddress: '',
    }],
    [1, {
      chainId: 1,
      name: 'Ethereum Mainnet',
      rpcUrl: process.env.ETHEREUM_RPC_URL || 'https://eth.llamarpc.com',
      explorerUrl: 'https://etherscan.io',
      escrowAddress: process.env.ETHEREUM_ESCROW_ADDRESS || '',
      attestationAddress: process.env.ETHEREUM_ATTESTATION_ADDRESS || '',
      nativeUsdcAddress: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
    }],
    [11155111, {
      chainId: 11155111,
      name: 'Ethereum Sepolia',
      rpcUrl: process.env.ETHEREUM_SEPOLIA_RPC_URL || 'https://rpc.sepolia.org',
      explorerUrl: 'https://sepolia.etherscan.io',
      escrowAddress: process.env.ETHEREUM_SEPOLIA_ESCROW_ADDRESS || '',
      attestationAddress: process.env.ETHEREUM_SEPOLIA_ATTESTATION_ADDRESS || '',
      nativeUsdcAddress: '',
    }],
  ]);

  getChainConfig(chainId: number): ChainConfig | undefined {
    return this.chains.get(chainId);
  }

  getSupportedChains(): ChainConfig[] {
    return Array.from(this.chains.values());
  }

  getProvider(chainId: number): ethers.JsonRpcProvider {
    if (this.providers.has(chainId)) {
      return this.providers.get(chainId)!;
    }

    const config = this.chains.get(chainId);
    if (!config) {
      throw new Error(`Chain ID ${chainId} is not supported`);
    }

    const provider = new ethers.JsonRpcProvider(config.rpcUrl);
    this.providers.set(chainId, provider);
    this.logger.log(`Connected to ${config.name} (Chain ID: ${chainId})`);
    return provider;
  }

  /**
   * Verify that a transaction hash exists on-chain and was successful
   */
  async verifyTransaction(chainId: number, txHash: string): Promise<{
    valid: boolean;
    blockNumber?: number;
    from?: string;
    to?: string;
    status?: number;
  }> {
    try {
      const provider = this.getProvider(chainId);
      const receipt = await provider.getTransactionReceipt(txHash);

      if (!receipt) {
        return { valid: false };
      }

      return {
        valid: receipt.status === 1,
        blockNumber: receipt.blockNumber,
        from: receipt.from,
        to: receipt.to || undefined,
        status: receipt.status || undefined,
      };
    } catch (e: any) {
      this.logger.warn(`Failed to verify tx ${txHash} on chain ${chainId}: ${e.message}`);
      return { valid: false };
    }
  }

  /**
   * Fetch deployed contract bytecode and compute keccak256 hash
   */
  async getContractBytecodeHash(chainId: number, contractAddress: string): Promise<string | null> {
    try {
      const provider = this.getProvider(chainId);
      const bytecode = await provider.getCode(contractAddress);

      if (!bytecode || bytecode === '0x') {
        return null;
      }

      return ethers.keccak256(bytecode);
    } catch (e: any) {
      this.logger.warn(`Failed to fetch bytecode for ${contractAddress} on chain ${chainId}: ${e.message}`);
      return null;
    }
  }

  /**
   * Get explorer URL for a transaction hash
   */
  getExplorerTxUrl(chainId: number, txHash: string): string {
    const config = this.chains.get(chainId);
    if (!config) return '';
    return `${config.explorerUrl}/tx/${txHash}`;
  }
}
