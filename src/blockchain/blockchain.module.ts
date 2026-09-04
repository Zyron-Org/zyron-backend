import { Global, Module } from '@nestjs/common';
import { BlockchainService } from './blockchain.service';
import {
  ChainConfigService,
  TransactionVerifierService,
  BytecodeVerifierService,
} from './services';

@Global()
@Module({
  providers: [
    BlockchainService,
    ChainConfigService,
    TransactionVerifierService,
    BytecodeVerifierService,
  ],
  exports: [
    BlockchainService,
    ChainConfigService,
    TransactionVerifierService,
    BytecodeVerifierService,
  ],
})
export class BlockchainModule {}
