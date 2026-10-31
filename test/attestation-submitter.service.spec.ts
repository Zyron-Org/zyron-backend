import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { Interface, id, keccak256, toUtf8Bytes, ZeroAddress } from 'ethers';

// Shared state for the mocked ethers.Contract (vi.mock is hoisted above imports).
const state = vi.hoisted(() => ({
  created: [] as any[],
  verifyRecord: undefined as any,
  verifyError: undefined as Error | undefined,
}));

vi.mock('ethers', async (importOriginal) => {
  const actual: any = await importOriginal();
  class FakeContract {
    publishAttestation = vi.fn().mockResolvedValue({ wait: async () => ({ hash: '0xpublished' }) });
    publishAttestationWithSignature = vi
      .fn()
      .mockResolvedValue({ wait: async () => ({ hash: '0xrelayed' }) });
    verifyAttestation = vi.fn(async () => {
      if (state.verifyError) throw state.verifyError;
      return state.verifyRecord;
    });
    constructor(public address: string, public abi: any, public runner: any) {
      state.created.push(this);
    }
  }
  return { ...actual, ethers: { ...actual.ethers, Contract: FakeContract }, Contract: FakeContract };
});

import { AttestationSubmitterService } from '../src/blockchain/services/attestation-submitter.service';
import { ChainConfigService } from '../src/blockchain/services/chain-config.service';

const OPERATOR_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const INPUT_TUPLE =
  '(bytes32,string,string,string,bytes32,bytes32,bytes32,string,string,address,address,address,uint256)';
const DEPLOYED = '0xBd24D2BFFbc69a17aCe69aaF930fC4e0d979c4D3';
const hex32 = (c: string) => '0x' + c.repeat(64);
const LEAD = '0x0000000000000000000000000000000000000444';

const audit = {
  id: 'ZYR-9481',
  protocolName: 'Zyron Test Protocol',
  contractFileName: 'VaultCore.sol',
  gitCommit: 'f402090ca289912040bb4129e34012948bbca102',
  sloc: 2410,
  sourceHash: hex32('a'),
  bytecodeHash: hex32('b'),
  merkleRoot: hex32('c'),
  ipfsCid: 'bafkreigjz7t5txj5xdmwgaxjt3yzc7gkzuecygcnq3gar24rhjatiujse4',
  ipfsMetadataCid: 'bafkreifhdyyqyfgymh25n4qnjgsqpg3dzzumj4nvkimn4bf46vq36cciu4',
  onChainChainId: null as number | null,
  leadAuditor: { walletAddress: LEAD },
  peerAuditor: null,
};

describe('AttestationSubmitterService – Monad Testnet', () => {
  const saved = { ...process.env };
  let prisma: any;
  let service: AttestationSubmitterService;

  beforeEach(() => {
    state.created.length = 0;
    state.verifyRecord = undefined;
    state.verifyError = undefined;
    delete process.env.DEFAULT_ATTESTATION_CHAIN_ID;
    delete process.env.MONAD_TESTNET_ATTESTATION_ADDRESS;
    delete process.env.ATTESTATION_CONTRACT_ADDRESS;
    process.env.OPERATOR_PRIVATE_KEY = OPERATOR_KEY;
    prisma = {
      auditRequest: {
        findUnique: vi.fn().mockResolvedValue({ ...audit }),
        update: vi.fn().mockResolvedValue({}),
      },
    };
    const chains = new ChainConfigService();
    vi.spyOn(chains, 'getProvider').mockReturnValue(null as any);
    service = new AttestationSubmitterService(prisma, chains);
  });

  afterEach(() => {
    process.env = { ...saved };
  });

  it('defaults to Monad Testnet (10143) and targets the deployed contract', async () => {
    const res = await service.submitAutomatedAttestation('ZYR-9481');
    expect(res).toEqual({ txHash: '0xpublished', chainId: 10143 });
    expect(state.created[0].address).toBe(DEPLOYED);
    expect(prisma.auditRequest.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ onChainChainId: 10143 }) }),
    );
  });

  it('uses an ABI whose publishAttestation selector matches the deployed ZyronAttestation contract', async () => {
    await service.submitAutomatedAttestation('ZYR-9481');
    const iface = new Interface(state.created[0].abi);
    const expected = id(`publishAttestation(${INPUT_TUPLE})`).slice(0, 10);
    expect(iface.getFunction('publishAttestation')!.selector).toBe(expected);
  });

  it('publishes a single AttestationInput struct built from the audit', async () => {
    await service.submitAutomatedAttestation('ZYR-9481');
    const call = state.created[0].publishAttestation.mock.calls[0];
    expect(call).toHaveLength(1);
    expect(call[0]).toMatchObject({
      auditId: keccak256(toUtf8Bytes('ZYR-9481')),
      protocolName: 'Zyron Test Protocol',
      targetContract: 'VaultCore.sol',
      gitCommit: audit.gitCommit,
      repoTreeHash: audit.sourceHash,
      bytecodeHash: audit.bytecodeHash,
      merkleRoot: audit.merkleRoot,
      ipfsReportCid: audit.ipfsCid,
      ipfsMetadataCid: audit.ipfsMetadataCid,
      leadAuditor: LEAD,
      peerAuditor: ZeroAddress,
      sloc: 2410,
    });
    // The struct must be ABI-encodable by the real contract interface.
    const iface = new Interface(state.created[0].abi);
    expect(() => iface.encodeFunctionData('publishAttestation', [call[0]])).not.toThrow();
  });

  it('falls back to the operator wallet as lead auditor and zero-pads missing hashes', async () => {
    prisma.auditRequest.findUnique.mockResolvedValue({
      ...audit,
      leadAuditor: null,
      sourceHash: null,
      bytecodeHash: null,
      merkleRoot: null,
    });
    await service.submitAutomatedAttestation('ZYR-9481');
    const [input] = state.created[0].publishAttestation.mock.calls[0];
    expect(input.leadAuditor).not.toBe(ZeroAddress);
    expect(input.repoTreeHash).toBe(hex32('0'));
    expect(input.bytecodeHash).toBe(hex32('0'));
    expect(input.merkleRoot).toBe(hex32('0'));
  });

  it('relays EIP-712 signed attestations with the contract signature layout', async () => {
    const msg = { merkleRoot: hex32('c'), bytecodeHash: hex32('b'), sloc: 2410, status: 2, timestamp: 1700000000 };
    const res = await service.submitSignedAttestation('ZYR-9481', '0xdeadbeef', LEAD, msg);
    expect(res).toEqual({ txHash: '0xrelayed', chainId: 10143, isRelayed: true });

    const iface = new Interface(state.created[0].abi);
    const expected = id(`publishAttestationWithSignature(${INPUT_TUPLE},uint8,uint256,bytes)`).slice(0, 10);
    expect(iface.getFunction('publishAttestationWithSignature')!.selector).toBe(expected);

    const [input, status, timestamp, signature] = state.created[0].publishAttestationWithSignature.mock.calls[0];
    expect(input.leadAuditor).toBe(LEAD);
    expect(input.sloc).toBe(2410);
    expect(status).toBe(2);
    expect(timestamp).toBe(1700000000);
    expect(signature).toBe('0xdeadbeef');
  });

  it('decodes verifyOnChain records and links to the MonadVision explorer', async () => {
    state.verifyRecord = {
      isVerified: true,
      merkleRoot: hex32('c'),
      bytecodeHash: hex32('b'),
      repoTreeHash: hex32('a'),
      ipfsReportCid: audit.ipfsCid,
      ipfsMetadataCid: audit.ipfsMetadataCid,
      protocolName: 'Zyron Test Protocol',
      targetContract: 'VaultCore.sol',
      gitCommit: audit.gitCommit,
      recipient: ZeroAddress,
      leadAuditor: LEAD,
      peerAuditor: ZeroAddress,
      sloc: 2410n,
      timestamp: 1700000000n,
      tokenId: 1n,
      status: 2n,
    };
    const res = await service.verifyOnChain('ZYR-9481');
    expect(res.isVerified).toBe(true);
    expect(res.chainId).toBe(10143);
    expect(res.sloc).toBe(2410);
    expect(res.tokenId).toBe(1);
    expect(res.repoTreeHash).toBe(hex32('a'));
    expect(res.explorerUrl).toBe(`https://testnet.monadvision.com/address/${DEPLOYED}`);
  });

  it('reports not-verified when the contract has no attestation for the audit', async () => {
    state.verifyError = new Error('ZyronAttestation: No verified attestation found for this audit ID');
    const res = await service.verifyOnChain('ZYR-0000');
    expect(res).toEqual({ isVerified: false, reason: 'No verified attestation found on-chain' });
  });
});
