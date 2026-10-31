import { Global, Module } from '@nestjs/common';
import { BlockchainService } from './blockchain.service';
import { BlockchainController } from './blockchain.controller';
import {
  ChainConfigService,
  TransactionVerifierService,
  BytecodeVerifierService,
  AttestationService,
  AttestationConfirmerService,
  AttestationSubmitterService,
  EvidenceHasherService,
} from './services';
import {
  MonadTestnetAdapter,
  BaseSepoliaAdapter,
  ChainAdapterRegistry,
} from './adapters';

@Global()
@Module({
  controllers: [BlockchainController],
  providers: [
    BlockchainService,
    ChainConfigService,
    TransactionVerifierService,
    BytecodeVerifierService,
    AttestationService,
    AttestationConfirmerService,
    AttestationSubmitterService,
    EvidenceHasherService,
    MonadTestnetAdapter,
    BaseSepoliaAdapter,
    ChainAdapterRegistry,
  ],
  exports: [
    BlockchainService,
    ChainConfigService,
    TransactionVerifierService,
    BytecodeVerifierService,
    AttestationService,
    AttestationConfirmerService,
    AttestationSubmitterService,
    EvidenceHasherService,
    MonadTestnetAdapter,
    BaseSepoliaAdapter,
    ChainAdapterRegistry,
  ],
})
export class BlockchainModule {}
