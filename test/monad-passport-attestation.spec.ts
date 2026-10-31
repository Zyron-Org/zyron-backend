import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import { AttestationSubmitterService } from '../src/blockchain/services/attestation-submitter.service';
import { ChainConfigService } from '../src/blockchain/services/chain-config.service';
import { PrismaService } from '../src/database/database.module';
import { BadRequestException } from '@nestjs/common';
import { MONAD_TESTNET_CHAIN_ID, MONAD_TESTNET_ATTESTATION_ADDRESS } from '../src/blockchain/constants';

describe('Monad Transaction Flow & Error Handling (TDD Section 18)', () => {
  let submitter: AttestationSubmitterService;
  let mockPrisma: any;
  let mockChainConfig: any;
  let mockContract: any;
  let mockProvider: any;

  const mockAudit = {
    id: 'ZYR-9481',
    protocolName: 'Monad Yield Vault',
    contractFileName: 'Vault.sol',
    gitCommit: '3f281e0',
    sourceHash: '0x1111',
    bytecodeHash: '0x2222',
    merkleRoot: '0x3333',
    sloc: 300,
    ipfsCid: 'bafybeig...pdf',
    ipfsMetadataCid: 'bafybeig...meta',
    onChainChainId: MONAD_TESTNET_CHAIN_ID,
    attestationStatus: 'PENDING_REVIEW',
    leadAuditor: { walletAddress: '0x48b106E3C8681D08c513268854Aef257883298d3' },
    peerAuditor: null,
  };

  beforeEach(async () => {
    process.env.OPERATOR_PRIVATE_KEY = '0x8981b1442e80c6f6fb7c8ce1187cc72236720d6c159802ce687bf85ba8889a7c';

    mockPrisma = {
      auditRequest: {
        findUnique: vi.fn().mockResolvedValue(mockAudit),
        update: vi.fn().mockImplementation(({ data }) => Promise.resolve({ ...mockAudit, ...data })),
      },
    };

    mockContract = {
      publishAttestation: vi.fn(),
      publishAttestationWithSignature: vi.fn(),
      verifyAttestation: vi.fn(),
    };

    mockProvider = {
      getTransactionReceipt: vi.fn(),
      getBlockNumber: vi.fn().mockResolvedValue(68403980),
    };

    mockChainConfig = {
      getChainConfig: vi.fn().mockReturnValue({
        chainId: MONAD_TESTNET_CHAIN_ID,
        name: 'Monad Testnet',
        rpcUrl: 'https://testnet-rpc.monad.xyz',
        explorerUrl: 'https://testnet.monadvision.com',
        attestationAddress: MONAD_TESTNET_ATTESTATION_ADDRESS,
      }),
      getProvider: vi.fn().mockReturnValue(mockProvider),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AttestationSubmitterService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: ChainConfigService, useValue: mockChainConfig },
      ],
    }).compile();

    submitter = module.get<AttestationSubmitterService>(AttestationSubmitterService);
  });

  it('rejects duplicate submission if audit is already attested and confirmed on-chain', async () => {
    mockPrisma.auditRequest.findUnique.mockResolvedValueOnce({
      ...mockAudit,
      attestationStatus: 'CONFIRMED',
      onChainTxHash: '0xalready_confirmed_tx',
    });

    await expect(
      submitter.submitAutomatedAttestation('ZYR-9481'),
    ).rejects.toThrow(BadRequestException);
  });

  it('handles transaction revert from smart contract gracefully', async () => {
    // Contract throws execution revert
    const revertErr = new Error('execution reverted: ZyronAttestation: Caller is not authorized operator');
    mockContract.publishAttestation.mockRejectedValueOnce(revertErr);

    // Mock ethers Contract to use our mockContract
    vi.spyOn(submitter as any, 'getContractInstance').mockReturnValue(mockContract);

    await expect(
      submitter.submitAutomatedAttestation('ZYR-9481'),
    ).rejects.toThrow(/execution reverted/);
  });

  it('handles RPC timeout or network failure with retryable error', async () => {
    const timeoutErr = new Error('timeout of 15000ms exceeded');
    mockContract.publishAttestation.mockRejectedValueOnce(timeoutErr);

    vi.spyOn(submitter as any, 'getContractInstance').mockReturnValue(mockContract);

    await expect(
      submitter.submitAutomatedAttestation('ZYR-9481'),
    ).rejects.toThrow(/timeout/);
  });

  it('persists transaction hash and updates attestation status to AUTOMATED_ONLY on successful confirmation', async () => {
    const mockTx = {
      hash: '0xmonad_success_tx_hash',
      wait: vi.fn().mockResolvedValue({
        hash: '0xmonad_success_tx_hash',
        blockNumber: 68403980,
        status: 1,
      }),
    };
    mockContract.publishAttestation.mockResolvedValueOnce(mockTx);
    vi.spyOn(submitter as any, 'getContractInstance').mockReturnValue(mockContract);

    const result = await submitter.submitAutomatedAttestation('ZYR-9481');

    expect(result.txHash).toBe('0xmonad_success_tx_hash');
    expect(result.chainId).toBe(MONAD_TESTNET_CHAIN_ID);
    expect(mockPrisma.auditRequest.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: 'ZYR-9481' },
        data: expect.objectContaining({
          onChainTxHash: '0xmonad_success_tx_hash',
          onChainChainId: MONAD_TESTNET_CHAIN_ID,
          attestationStatus: 'AUTOMATED_ONLY',
        }),
      }),
    );
  });
});
