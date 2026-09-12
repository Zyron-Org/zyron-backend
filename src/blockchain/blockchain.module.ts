import { Global, Module } from '@nestjs/common';
import { BlockchainService } from './blockchain.service';
import {
  ChainConfigService,
  TransactionVerifierService,
  BytecodeVerifierService,
  AttestationService,
  AttestationConfirmerService,
  AttestationSubmitterService,
} from './services';

@Global()
@Module({
  providers: [
    BlockchainService,
    ChainConfigService,
    TransactionVerifierService,
    BytecodeVerifierService,
    AttestationService,
    AttestationConfirmerService,
    AttestationSubmitterService,
  ],
  exports: [
    BlockchainService,
    ChainConfigService,
    TransactionVerifierService,
    BytecodeVerifierService,
    AttestationService,
    AttestationConfirmerService,
    AttestationSubmitterService,
  ],
})
export class BlockchainModule {}
