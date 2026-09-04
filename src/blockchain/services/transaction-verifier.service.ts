import { Injectable, Logger } from '@nestjs/common';
import { ChainConfigService } from './chain-config.service';

@Injectable()
export class TransactionVerifierService {
  private readonly logger = new Logger(TransactionVerifierService.name);

  constructor(private chainConfig: ChainConfigService) {}

  async verifyTransaction(chainId: number, txHash: string): Promise<{
    valid: boolean;
    blockNumber?: number;
    from?: string;
    to?: string;
    status?: number;
  }> {
    try {
      const provider = this.chainConfig.getProvider(chainId);
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

  getExplorerTxUrl(chainId: number, txHash: string): string {
    const config = this.chainConfig.getChainConfig(chainId);
    if (!config) return '';
    return `${config.explorerUrl}/tx/${txHash}`;
  }
}
