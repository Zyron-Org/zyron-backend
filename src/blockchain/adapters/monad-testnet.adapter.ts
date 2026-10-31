import { Injectable } from '@nestjs/common';
import { ChainConfigService } from '../services/chain-config.service';
import { MONAD_TESTNET_CHAIN_ID } from '../constants';
import { EvmChainAdapter } from './chain-adapter.interface';

@Injectable()
export class MonadTestnetAdapter extends EvmChainAdapter {
  readonly chainId = MONAD_TESTNET_CHAIN_ID;
  readonly name = 'Monad Testnet';
  readonly isTestnet = true;
  readonly nativeSymbol = 'MON';

  constructor(chainConfigService: ChainConfigService) {
    super(chainConfigService);
  }
}
