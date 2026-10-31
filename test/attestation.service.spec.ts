import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { TypedDataEncoder, Wallet, id, keccak256, toUtf8Bytes } from 'ethers';
import { AttestationService } from '../src/blockchain/services/attestation.service';
import { ChainConfigService } from '../src/blockchain/services/chain-config.service';
import { DEFAULT_ATTESTATION_CHAIN_ID, getDefaultAttestationChainId } from '../src/blockchain/constants';

const DEPLOYED = '0xBd24D2BFFbc69a17aCe69aaF930fC4e0d979c4D3';
const hex32 = (c: string) => '0x' + c.repeat(64);
const LEAD = '0x0000000000000000000000000000000000000444';

// Must equal ZyronAttestation.ATTESTATION_TYPEHASH preimage (field order matters).
const CONTRACT_TYPE_STRING =
  'AttestationPayload(bytes32 auditId,bytes32 merkleRoot,bytes32 repoTreeHash,bytes32 bytecodeHash,address leadAuditor,uint256 sloc,uint8 status,uint256 timestamp)';

const audit = {
  id: 'ZYR-9481',
  protocolName: 'Zyron Test Protocol',
  contractFileName: 'VaultCore.sol',
  gitCommit: 'f402090c',
  sloc: 2410,
  sourceHash: hex32('a'),
  bytecodeHash: hex32('b'),
  attestationStatus: 'AUTOMATED_ONLY',
  onChainChainId: null as number | null,
  findings: [{ displayId: 'ZYR-9481-001', severity: 'HIGH', falsePositive: false }],
  leadAuditor: { walletAddress: LEAD },
};

describe('Default attestation chain', () => {
  const saved = { ...process.env };
  afterEach(() => {
    process.env = { ...saved };
  });

  it('is Monad Testnet (10143)', () => {
    expect(DEFAULT_ATTESTATION_CHAIN_ID).toBe(10143);
    delete process.env.DEFAULT_ATTESTATION_CHAIN_ID;
    expect(getDefaultAttestationChainId()).toBe(10143);
  });

  it('can be overridden through DEFAULT_ATTESTATION_CHAIN_ID', () => {
    process.env.DEFAULT_ATTESTATION_CHAIN_ID = '8453';
    expect(getDefaultAttestationChainId()).toBe(8453);
  });
});

describe('AttestationService.buildAttestationPayload – Monad Testnet', () => {
  const saved = { ...process.env };
  let prisma: any;
  let service: AttestationService;

  beforeEach(() => {
    delete process.env.DEFAULT_ATTESTATION_CHAIN_ID;
    delete process.env.MONAD_TESTNET_ATTESTATION_ADDRESS;
    delete process.env.ATTESTATION_CONTRACT_ADDRESS;
    prisma = { auditRequest: { findUnique: vi.fn().mockResolvedValue({ ...audit }) } };
    service = new AttestationService(prisma, new ChainConfigService());
  });

  afterEach(() => {
    process.env = { ...saved };
  });

  it('builds an EIP-712 domain for Monad Testnet and the deployed contract', async () => {
    const { payload, targetChainId, verifyingContract } = await service.buildAttestationPayload('ZYR-9481');
    expect(targetChainId).toBe(10143);
    expect(verifyingContract).toBe(DEPLOYED);
    expect(payload.domain).toEqual({
      name: 'ZyronAttestation',
      version: '3.0.0',
      chainId: 10143,
      verifyingContract: DEPLOYED,
    });
  });

  it('never falls back to the old Arbitrum Sepolia contract address', async () => {
    prisma.auditRequest.findUnique.mockResolvedValue({ ...audit, onChainChainId: 99999 }); // unknown chain
    const { verifyingContract } = await service.buildAttestationPayload('ZYR-9481');
    expect(verifyingContract).toBe(DEPLOYED);
    expect(verifyingContract).not.toBe('0x3331185fAEB2AD65ccDEB7C15025393Ca8F6834D');
  });

  it("uses the contract's AttestationPayload type layout (repoTreeHash, same field order)", async () => {
    const { payload } = await service.buildAttestationPayload('ZYR-9481');
    const encoder = TypedDataEncoder.from({ AttestationPayload: payload.types.AttestationPayload });
    expect(encoder.encodeType('AttestationPayload')).toBe(CONTRACT_TYPE_STRING);
    expect(id(CONTRACT_TYPE_STRING)).toBe(id(encoder.encodeType('AttestationPayload')));
  });

  it('maps the audit source hash to repoTreeHash and hashes the audit id', async () => {
    const { payload } = await service.buildAttestationPayload('ZYR-9481');
    expect(payload.message.repoTreeHash).toBe(hex32('a'));
    expect(payload.message.auditId).toBe(keccak256(toUtf8Bytes('ZYR-9481')));
    expect(payload.message.leadAuditor).toBe(LEAD);
    expect(payload.message.status).toBe(2);
    expect((payload.message as any).sourceHash).toBeUndefined();
  });

  it('produces a payload that an auditor wallet can sign and that recovers to the signer', async () => {
    const wallet = Wallet.createRandom();
    const { payload } = await service.buildAttestationPayload('ZYR-9481', wallet.address);
    const sig = await wallet.signTypedData(
      payload.domain,
      { AttestationPayload: payload.types.AttestationPayload },
      payload.message,
    );
    const recovered = TypedDataEncoder.hash(
      payload.domain,
      { AttestationPayload: payload.types.AttestationPayload },
      payload.message,
    );
    expect(sig).toMatch(/^0x[0-9a-f]{130}$/);
    expect(recovered).toMatch(/^0x[0-9a-f]{64}$/);
  });
});
