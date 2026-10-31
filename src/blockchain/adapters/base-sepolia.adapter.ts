import { Injectable } from '@nestjs/common';
import { ChainConfigService } from '../services/chain-config.service';
import { EvmChainAdapter } from './chain-adapter.interface';

export const BASE_SEPOLIA_CHAIN_ID = 84532;

@Injectable()
export class BaseSepoliaAdapter extends EvmChainAdapter {
  readonly chainId = BASE_SEPOLIA_CHAIN_ID;
  readonly name = 'Base Sepolia';
  readonly isTestnet = true;
  readonly nativeSymbol = 'ETH';

  constructor(chainConfigService: ChainConfigService) {
    super(chainConfigService);
  }
}
