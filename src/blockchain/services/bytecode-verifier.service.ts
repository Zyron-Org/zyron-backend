import { Injectable, Logger } from '@nestjs/common';
import { ethers } from 'ethers';
import { ChainConfigService } from './chain-config.service';

@Injectable()
export class BytecodeVerifierService {
  private readonly logger = new Logger(BytecodeVerifierService.name);

  constructor(private chainConfig: ChainConfigService) {}

  async getContractBytecodeHash(chainId: number, contractAddress: string): Promise<string | null> {
    try {
      const provider = this.chainConfig.getProvider(chainId);
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
}
