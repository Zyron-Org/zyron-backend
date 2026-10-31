import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ChainConfigService } from '../src/blockchain/services/chain-config.service';

const DEPLOYED_MONAD_ATTESTATION = '0xBd24D2BFFbc69a17aCe69aaF930fC4e0d979c4D3';

describe('ChainConfigService – Monad Testnet', () => {
  const saved = { ...process.env };
  let service: ChainConfigService;

  beforeEach(() => {
    delete process.env.MONAD_TESTNET_RPC_URL;
    delete process.env.MONAD_TESTNET_ATTESTATION_ADDRESS;
    delete process.env.ATTESTATION_CONTRACT_ADDRESS;
    service = new ChainConfigService();
  });

  afterEach(() => {
    process.env = { ...saved };
  });

  it('registers Monad Testnet (10143) with the correct network details', () => {
    const cfg = service.getChainConfig(10143);
    expect(cfg).toBeDefined();
    expect(cfg!.chainId).toBe(10143);
    expect(cfg!.name).toBe('Monad Testnet');
    expect(cfg!.rpcUrl).toBe('https://testnet-rpc.monad.xyz');
    expect(cfg!.explorerUrl).toBe('https://testnet.monadvision.com');
    expect(cfg!.nativeCurrencySymbol).toBe('MON');
  });

  it('points at the deployed Monad ZyronAttestation contract by default', () => {
    expect(service.getChainConfig(10143)!.attestationAddress).toBe(DEPLOYED_MONAD_ATTESTATION);
  });

  it('allows RPC and attestation address overrides via env', () => {
    process.env.MONAD_TESTNET_RPC_URL = 'https://custom-rpc.example';
    process.env.MONAD_TESTNET_ATTESTATION_ADDRESS = '0x0000000000000000000000000000000000000001';
    const cfg = new ChainConfigService().getChainConfig(10143)!;
    expect(cfg.rpcUrl).toBe('https://custom-rpc.example');
    expect(cfg.attestationAddress).toBe('0x0000000000000000000000000000000000000001');
  });

  it('no longer supports Arbitrum Sepolia (421614)', () => {
    expect(service.getChainConfig(421614)).toBeUndefined();
    expect(service.getSupportedChains().map((c) => c.chainId)).not.toContain(421614);
    expect(() => service.getProvider(421614)).toThrow(/not supported/);
  });

  it('includes Monad Testnet in the supported chains list', () => {
    expect(service.getSupportedChains().map((c) => c.chainId)).toContain(10143);
  });

  it('creates a JSON-RPC provider for Monad Testnet and caches it', () => {
    const p1 = service.getProvider(10143);
    const p2 = service.getProvider(10143);
    expect(p1).toBe(p2);
  });
});
