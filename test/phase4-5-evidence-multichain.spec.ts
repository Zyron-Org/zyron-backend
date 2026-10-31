import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { Wallet, keccak256, toUtf8Bytes } from 'ethers';
import * as crypto from 'crypto';
import { BadRequestException, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { EvidenceHasherService, EVIDENCE_SCHEMA_V1 } from '../src/blockchain/services/evidence-hasher.service';
import { ChainConfigService } from '../src/blockchain/services/chain-config.service';
import { AttestationService } from '../src/blockchain/services/attestation.service';
import { AttestationSubmitterService } from '../src/blockchain/services/attestation-submitter.service';
import {
  ChainAdapterRegistry,
  MonadTestnetAdapter,
  BaseSepoliaAdapter,
  formatChainScopedIdentity,
} from '../src/blockchain/adapters';
import { AgentProverClientService } from '../src/scanner/services/agent-prover-client.service';

describe('Phase 4 & 5: Canonical Evidence (zyron.evidence/v1) & Multichain Attestation Adapters', () => {
  const savedEnv = { ...process.env };
  let hasher: EvidenceHasherService;
  let chainConfig: ChainConfigService;
  let registry: ChainAdapterRegistry;

  beforeEach(() => {
    process.env = { ...savedEnv };
    hasher = new EvidenceHasherService();
    chainConfig = new ChainConfigService();
    registry = new ChainAdapterRegistry(chainConfig);
  });

  afterEach(() => {
    process.env = { ...savedEnv };
  });

  describe('EvidenceHasherService (zyron.evidence/v1)', () => {
    it('builds a reproducible zyron.evidence/v1 digest and detects tampering', () => {
      const recordA = hasher.buildFindingEvidenceV1({
        auditId: 'ZYR-9481',
        findingId: 'F-001',
        displayId: 'ZYR-9481-001',
        repository: 'https://github.com/Vasakee/Zyron',
        gitCommit: 'feed07e',
        sourceHashes: { 'src/VaultCore.sol': '0x' + 'a'.repeat(64) },
        targetContractFile: 'VaultCore.sol',
        targetContractAddress: '0x1111111111111111111111111111111111111111',
        chainId: 10143,
        bytecodeHash: '0x' + 'b'.repeat(64),
        ruleId: 'ZYRON-08-001',
        severity: 'CRITICAL',
        taxonomy: 'SWC-107',
        testFile: 'test/zyron/F_001.t.sol',
        testFunction: 'testExploit_F_001',
        testArtifactHash: '0x' + 'c'.repeat(64),
        claimedVerdict: 'PROVEN_EXPLOIT',
        finalStatus: 'PROVEN_EXPLOIT',
        runs: [
          { exitCode: 0, passed: true, stdoutHash: '0x' + 'd'.repeat(64), gasUsed: 124500 },
          { exitCode: 0, passed: true, stdoutHash: '0x' + 'd'.repeat(64), gasUsed: 124500 },
        ],
        verifierVersion: 'zyron-verifier/2.0.0',
        provider: 'meta',
        model: 'muse-spark-1.3',
      });

      expect(recordA.schemaVersion).toBe(EVIDENCE_SCHEMA_V1);
      expect(recordA.evidenceHash).toMatch(/^0x[0-9a-f]{64}$/);
      expect(hasher.verifyEvidenceDigest(recordA.canonicalJson, recordA.evidenceHash)).toBe(true);

      // Tampering with finalStatus or sourceHashes invalidates the digest
      const tampered = JSON.parse(recordA.canonicalJson);
      tampered.prover.finalStatus = 'PROVEN_FALSE_POSITIVE';
      expect(hasher.verifyEvidenceDigest(tampered, recordA.evidenceHash)).toBe(false);
    });

    it('computes order-independent Merkle root over finding evidence digests', () => {
      const h1 = '0x' + '1'.repeat(64);
      const h2 = '0x' + '2'.repeat(64);
      const h3 = '0x' + '3'.repeat(64);

      const rootA = hasher.computeEvidenceMerkleRoot([h3, h1, h2]);
      const rootB = hasher.computeEvidenceMerkleRoot([h1, h2, h3]);
      expect(rootA).toBe(rootB);
      expect(rootA).toMatch(/^0x[0-9a-f]{64}$/);
    });
  });

  describe('AgentProverClientService HMAC & Evidence Persistence', () => {
    it('rejects callback with missing or invalid HMAC when CALLBACK_SHARED_SECRET is configured, and persists ProverEvidence when valid', async () => {
      process.env.CALLBACK_SHARED_SECRET = 'test_hmac_secret_2026';

      const upsertedEvidences: any[] = [];
      const mockPrisma: any = {
        auditRequest: {
          findUnique: vi.fn().mockResolvedValue({
            id: 'ZYR-9481',
            contractFileName: 'VaultCore.sol',
            contractAddress: '0x1111111111111111111111111111111111111111',
            sourceHash: '0x' + 'a'.repeat(64),
            bytecodeHash: '0x' + 'b'.repeat(64),
            stage: 'SCANNING',
          }),
          update: vi.fn().mockResolvedValue({}),
        },
        finding: {
          findFirst: vi.fn().mockResolvedValue({
            id: 'find_1',
            displayId: 'ZYR-9481-001',
            ruleId: 'ZYRON-08-001',
            severity: 'CRITICAL',
            taxonomy: 'SWC-107',
            falsePositive: false,
            confidence: 'HIGH_CONFIDENCE',
          }),
          update: vi.fn().mockResolvedValue({}),
        },
        proverEvidence: {
          upsert: vi.fn().mockImplementation(async (args) => {
            upsertedEvidences.push(args.create);
            return args.create;
          }),
        },
      };

      const mockGateway: any = {
        emitProverComplete: vi.fn(),
        emitScanProgress: vi.fn(),
      };

      const client = new AgentProverClientService(mockPrisma, mockGateway, hasher);

      const payload = {
        jobId: 'job-1',
        auditId: 'ZYR-9481',
        status: 'COMPLETED' as const,
        durationMs: 2400,
        results: [
          {
            findingId: 'find_1',
            verdict: 'CANNOT_REPRODUCE', // legacy status should normalize to INCONCLUSIVE
            verification: {
              verifierVersion: 'zyron-verifier/2.0.0',
              claimedVerdict: 'PROVEN_EXPLOIT',
              finalStatus: 'INCONCLUSIVE' as const,
              reasonCodes: ['FORGE_TEST_FAILED_RUN_1'],
              sourceHashes: { 'src/VaultCore.sol': '0x' + 'a'.repeat(64) },
              testFile: 'test/zyron/F_001.t.sol',
              testFunction: 'testExploit_F_001',
              testArtifactSha256: '0x' + 'c'.repeat(64),
              runs: [{ exitCode: 1, passed: false, outputSha256: '0x' + 'e'.repeat(64) }],
            },
            model: { provider: 'meta', model: 'muse-spark-1.3', turns: 3 },
          },
        ],
      };
      const rawBody = JSON.stringify(payload);

      // Missing signature -> UnauthorizedException
      await expect(client.handleProverCallback(undefined, rawBody, payload)).rejects.toThrow(
        UnauthorizedException,
      );

      // Tampered signature -> UnauthorizedException
      await expect(
        client.handleProverCallback('sha256=' + '0'.repeat(64), rawBody, payload),
      ).rejects.toThrow(UnauthorizedException);

      // Valid HMAC signature -> succeeds, normalizes to INCONCLUSIVE, persists ProverEvidence
      const validSig =
        'sha256=' + crypto.createHmac('sha256', 'test_hmac_secret_2026').update(rawBody).digest('hex');
      const res = await client.handleProverCallback(validSig, rawBody, payload);

      expect(res.success).toBe(true);
      expect(res.evidenceMerkleRoot).toMatch(/^0x[0-9a-f]{64}$/);
      expect(upsertedEvidences).toHaveLength(1);
      expect(upsertedEvidences[0].finalStatus).toBe('INCONCLUSIVE');
      expect(upsertedEvidences[0].provider).toBe('meta');
      expect(upsertedEvidences[0].model).toBe('muse-spark-1.3');
    });
  });

  describe('Multichain Adapter Isolation & EIP-712 Authorization Rules', () => {
    it('scopes identical contract addresses to their respective chainId (Monad Testnet 10143 vs Base Sepolia 84532)', () => {
      const sameAddress = '0xAbCdEf0000000000000000000000000000001234';
      const monad = registry.getAdapter(10143);
      const baseSepolia = registry.getAdapter(84532);

      const idMonad = monad.formatContractIdentity(sameAddress);
      const idBase = baseSepolia.formatContractIdentity(sameAddress);

      expect(idMonad).toBe(`10143:${sameAddress.toLowerCase()}`);
      expect(idBase).toBe(`84532:${sameAddress.toLowerCase()}`);
      expect(idMonad).not.toBe(idBase);
      expect(formatChainScopedIdentity(10143, sameAddress)).toBe(idMonad);
    });

    it('enforces reviewer authorization, rejects cross-chain signature replay, and rejects stale source revisions', async () => {
      const auditorWallet = Wallet.createRandom();
      const wrongWallet = Wallet.createRandom();

      const storedAttestations = new Map<string, any>();
      let currentSourceHash = '0x' + 'a'.repeat(64);

      const mockPrisma: any = {
        auditRequest: {
          findUnique: vi.fn().mockImplementation(async () => ({
            id: 'ZYR-9481',
            protocolName: 'Zyron Vault',
            contractFileName: 'VaultCore.sol',
            contractAddress: '0x1111111111111111111111111111111111111111',
            gitCommit: 'feed07e',
            sourceHash: currentSourceHash,
            bytecodeHash: '0x' + 'b'.repeat(64),
            sloc: 420,
            attestationStatus: 'PENDING_REVIEW',
            findings: [{ displayId: 'ZYR-9481-001', severity: 'CRITICAL', falsePositive: false }],
            leadAuditor: { walletAddress: auditorWallet.address },
            peerAuditor: null,
          })),
        },
        proverEvidence: {
          findMany: vi.fn().mockResolvedValue([
            { findingId: 'f1', evidenceHash: '0x' + '9'.repeat(64) },
          ]),
        },
        chainAttestation: {
          upsert: vi.fn().mockImplementation(async ({ where, create, update }) => {
            const key = `${where.auditId_chainId.auditId}:${where.auditId_chainId.chainId}`;
            const rec = { id: 'ca_1', ...(storedAttestations.get(key) || create), ...update };
            storedAttestations.set(key, rec);
            return rec;
          }),
          findUnique: vi.fn().mockImplementation(async ({ where }) => {
            const key = `${where.auditId_chainId.auditId}:${where.auditId_chainId.chainId}`;
            return storedAttestations.get(key) || null;
          }),
          update: vi.fn().mockImplementation(async ({ data }) => {
            const rec = storedAttestations.get('ZYR-9481:10143');
            const updated = { ...rec, ...data };
            storedAttestations.set('ZYR-9481:10143', updated);
            return updated;
          }),
        },
        user: {
          findFirst: vi.fn().mockImplementation(async ({ where }) => {
            const addrs: string[] = where?.walletAddress?.in || [];
            if (addrs.includes(wrongWallet.address)) {
              return { id: 'u_client', role: 'CLIENT', walletAddress: wrongWallet.address };
            }
            return { id: 'u_auditor', role: 'AUDITOR', walletAddress: auditorWallet.address };
          }),
        },
      };

      const attestationService = new AttestationService(mockPrisma, chainConfig, hasher, registry);

      // 1. Prepare on Monad Testnet (10143)
      const preparedMonad = await attestationService.prepareChainAttestation(
        'ZYR-9481',
        10143,
        auditorWallet.address,
      );
      expect(preparedMonad.chainId).toBe(10143);
      expect(preparedMonad.typedData.domain.chainId).toBe(10143);

      // 2. Reject signature signed for Base Sepolia (84532) when replayed against Monad Testnet (10143)
      const forgedBaseDomain = { ...preparedMonad.typedData.domain, chainId: 84532 };
      const crossChainSig = await auditorWallet.signTypedData(
        forgedBaseDomain,
        { AttestationPayload: preparedMonad.typedData.types.AttestationPayload },
        preparedMonad.typedData.message,
      );
      await expect(
        attestationService.approveChainAttestation({
          auditId: 'ZYR-9481',
          chainId: 10143,
          signature: crossChainSig,
          signerAddress: auditorWallet.address,
        }),
      ).rejects.toThrow(BadRequestException);

      // 3. Reject CLIENT user attempting to authorize
      await expect(
        attestationService.approveChainAttestation({
          auditId: 'ZYR-9481',
          chainId: 10143,
          signature: crossChainSig,
          signerAddress: wrongWallet.address,
        }),
      ).rejects.toThrow(ForbiddenException);

      // 4. Valid Monad Testnet EIP-712 signature from authorized AUDITOR succeeds
      const validMonadSig = await auditorWallet.signTypedData(
        preparedMonad.typedData.domain,
        { AttestationPayload: preparedMonad.typedData.types.AttestationPayload },
        preparedMonad.typedData.message,
      );
      const approved = await attestationService.approveChainAttestation({
        auditId: 'ZYR-9481',
        chainId: 10143,
        signature: validMonadSig,
        signerAddress: auditorWallet.address,
      });
      expect(approved.approved).toBe(true);
      expect(approved.status).toBe('APPROVED');

      // 5. Stale source revision: if audit sourceHash changes after preparation, approval is rejected
      currentSourceHash = '0x' + 'f'.repeat(64);
      await expect(
        attestationService.approveChainAttestation({
          auditId: 'ZYR-9481',
          chainId: 10143,
          signature: validMonadSig,
          signerAddress: auditorWallet.address,
        }),
      ).rejects.toThrow(/Stale source revision/);
    });

    it('fails closed when Base Sepolia registry address is not configured or OPERATOR_PRIVATE_KEY is missing', async () => {
      process.env.BASE_SEPOLIA_ATTESTATION_ADDRESS = '';
      delete process.env.OPERATOR_PRIVATE_KEY;

      const freshConfig = new ChainConfigService();
      const freshRegistry = new ChainAdapterRegistry(freshConfig);
      const baseAdapter = freshRegistry.getAdapter(84532);

      expect(baseAdapter.isConfigured()).toBe(false);
      expect(baseAdapter.getMissingConfigReason()).toContain('84532');

      const mockPrisma: any = {
        auditRequest: {
          findUnique: vi.fn().mockResolvedValue({
            id: 'ZYR-9481',
            protocolName: 'Vault',
            contractFileName: 'Vault.sol',
            onChainChainId: 10143,
            attestationStatus: 'PENDING_REVIEW',
          }),
        },
      };
      const submitter = new AttestationSubmitterService(mockPrisma, freshConfig, freshRegistry);

      // Refuses to fabricate a mock tx hash when OPERATOR_PRIVATE_KEY is unset
      await expect(submitter.submitAutomatedAttestation('ZYR-9481', 10143)).rejects.toThrow(
        /refusing to fabricate a transaction hash/,
      );
    });
  });
});
