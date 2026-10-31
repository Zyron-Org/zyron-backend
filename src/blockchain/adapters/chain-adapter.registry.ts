import { Injectable, BadRequestException, Optional } from '@nestjs/common';
import { ChainConfigService } from '../services/chain-config.service';
import { ChainAdapter } from './chain-adapter.interface';
import { MonadTestnetAdapter } from './monad-testnet.adapter';
import { BaseSepoliaAdapter } from './base-sepolia.adapter';

export interface ChainMatrixEntry {
  chainId: number;
  name: string;
  isTestnet: boolean;
  nativeSymbol: string;
  rpcUrl: string;
  explorerUrl: string;
  attestationAddress: string;
  isConfigured: boolean;
  missingConfigReason: string | null;
}

@Injectable()
export class ChainAdapterRegistry {
  private readonly adapters = new Map<number, ChainAdapter>();

  constructor(
    private readonly chainConfigService: ChainConfigService,
    @Optional() monadAdapter?: MonadTestnetAdapter,
    @Optional() baseSepoliaAdapter?: BaseSepoliaAdapter,
  ) {
    const monad = monadAdapter || new MonadTestnetAdapter(this.chainConfigService);
    const baseSepolia = baseSepoliaAdapter || new BaseSepoliaAdapter(this.chainConfigService);
    this.register(monad);
    this.register(baseSepolia);
  }

  register(adapter: ChainAdapter): void {
    this.adapters.set(adapter.chainId, adapter);
  }

  getAdapter(chainId: number): ChainAdapter {
    const adapter = this.adapters.get(Number(chainId));
    if (!adapter) {
      throw new BadRequestException(
        `Unsupported attestation chainId ${chainId}. Supported chains: ${Array.from(this.adapters.keys()).join(', ')}.`,
      );
    }
    return adapter;
  }

  hasAdapter(chainId: number): boolean {
    return this.adapters.has(Number(chainId));
  }

  listAdapters(): ChainAdapter[] {
    return Array.from(this.adapters.values());
  }

  getSupportedChainMatrix(): ChainMatrixEntry[] {
    return this.listAdapters().map((adapter) => {
      const cfg = adapter.getChainConfig();
      return {
        chainId: adapter.chainId,
        name: adapter.name,
        isTestnet: adapter.isTestnet,
        nativeSymbol: adapter.nativeSymbol,
        rpcUrl: cfg.rpcUrl,
        explorerUrl: cfg.explorerUrl,
        attestationAddress: cfg.attestationAddress || '',
        isConfigured: adapter.isConfigured(),
        missingConfigReason: adapter.getMissingConfigReason(),
      };
    });
  }
}
