import { Injectable } from '@nestjs/common';
import {
  ChainConfigService,
  TransactionVerifierService,
  BytecodeVerifierService,
  ChainConfig,
} from './services';

@Injectable()
export class BlockchainService {
  constructor(
    private chainConfig: ChainConfigService,
    private txVerifier: TransactionVerifierService,
    private bytecodeVerifier: BytecodeVerifierService,
  ) {}

  getChainConfig(chainId: number): ChainConfig | undefined {
    return this.chainConfig.getChainConfig(chainId);
  }

  getSupportedChains(): ChainConfig[] {
    return this.chainConfig.getSupportedChains();
  }

  getProvider(chainId: number) {
    return this.chainConfig.getProvider(chainId);
  }

  verifyTransaction(chainId: number, txHash: string) {
    return this.txVerifier.verifyTransaction(chainId, txHash);
  }

  getContractBytecodeHash(chainId: number, contractAddress: string) {
    return this.bytecodeVerifier.getContractBytecodeHash(chainId, contractAddress);
  }

  getExplorerTxUrl(chainId: number, txHash: string): string {
    return this.txVerifier.getExplorerTxUrl(chainId, txHash);
  }
}
