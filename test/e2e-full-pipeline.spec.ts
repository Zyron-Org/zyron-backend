import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { Wallet, Interface, keccak256, toUtf8Bytes } from 'ethers';
import { BadRequestException, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { ASTParserService } from '../src/scanner/engine/ast-parser.service';
import { CFGBuilderService } from '../src/scanner/engine/cfg-builder.service';
import { InheritanceResolverService } from '../src/scanner/engine/inheritance-resolver.service';
import { PragmaAnalyzerService } from '../src/scanner/engine/pragma-analyzer.service';
import { PassRegistryService } from '../src/scanner/passes/pass-registry';
import { MetaProviderService } from '../src/scanner/ai-providers/meta-provider.service';
import { AgentProverClientService } from '../src/scanner/services/agent-prover-client.service';
import { EvidenceHasherService, EVIDENCE_SCHEMA_V1 } from '../src/blockchain/services/evidence-hasher.service';
import { ChainConfigService } from '../src/blockchain/services/chain-config.service';
import { ChainAdapterRegistry, ZYRON_ATTESTATION_REGISTRY_ABI } from '../src/blockchain/adapters';
import { AttestationService } from '../src/blockchain/services/attestation.service';
import { AttestationSubmitterService } from '../src/blockchain/services/attestation-submitter.service';

describe('End-to-End Zyron Security Pipeline (AST Scan -> Meta AI Prover -> Verifier v2 -> zyron.evidence/v1 -> Multichain Attestation)', () => {
  const savedEnv = { ...process.env };
  const vaultCorePath = path.resolve(__dirname, '../../zyron-test-protocol/contracts/VaultCore.sol');
  const vaultCoreSource = fs.existsSync(vaultCorePath)
    ? fs.readFileSync(vaultCorePath, 'utf8')
    : `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract VaultCore {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] -= amount;
    }
}`;
  const vaultCoreSha256 = '0x' + crypto.createHash('sha256').update(vaultCoreSource).digest('hex');
  const runtimeBytecodeHash = '0x' + crypto.createHash('sha256').update('VaultCore-runtime-bytecode').digest('hex');

  let hasher: EvidenceHasherService;
  let chainConfig: ChainConfigService;
  let adapterRegistry: ChainAdapterRegistry;
  let attestationService: AttestationService;
  let submitterService: AttestationSubmitterService;
  let proverClient: AgentProverClientService;

  // In-memory state backing Prisma mocks for full lifecycle verification
  let auditStore: any;
  let findingsStore: Map<string, any>;
  let proverEvidenceStore: Map<string, any>;
  let chainAttestationStore: Map<string, any>;
  let auditorWallet: Wallet;
  let clientWallet: Wallet;

  beforeEach(() => {
    process.env = {
      ...savedEnv,
      AI_PROVIDER: 'meta',
      MODEL_API_KEY: 'meta_test_key_standard_mode',
      META_MODEL: 'muse-spark-1.3',
      CALLBACK_SHARED_SECRET: 'zyron_e2e_hmac_secret_2026',
      MONAD_TESTNET_ATTESTATION_ADDRESS: '0xBd24D2BFFbc69a17aCe69aaF930fC4e0d979c4D3',
      BASE_SEPOLIA_ATTESTATION_ADDRESS: '0xc242125A0b342E045Cf0E1c2e02C95D1EAEEC5c4',
      OPERATOR_PRIVATE_KEY: Wallet.createRandom().privateKey,
    };

    auditorWallet = Wallet.createRandom();
    clientWallet = Wallet.createRandom();

    findingsStore = new Map([
      [
        'find_reentrancy',
        {
          id: 'find_reentrancy',
          displayId: 'ZYR-E2E-001',
          ruleId: 'ZYRON-08-001',
          title: 'Classic Reentrancy in withdraw()',
          severity: 'CRITICAL',
          taxonomy: 'SWC-107',
          status: 'OPEN',
          falsePositive: false,
          confidence: 'HIGH_CONFIDENCE',
        },
      ],
      [
        'find_safe_withdraw',
        {
          id: 'find_safe_withdraw',
          displayId: 'ZYR-E2E-002',
          ruleId: 'ZYRON-08-002',
          title: 'Potential Reentrancy in safeEmergencyWithdraw()',
          severity: 'HIGH',
          taxonomy: 'SWC-107',
          status: 'OPEN',
          falsePositive: false,
          confidence: 'NEEDS_REVIEW',
        },
      ],
      [
        'find_inconclusive',
        {
          id: 'find_inconclusive',
          displayId: 'ZYR-E2E-003',
          ruleId: 'ZYRON-04-001',
          title: 'Unverified Timestamp Dependency',
          severity: 'MEDIUM',
          taxonomy: 'SWC-116',
          status: 'OPEN',
          falsePositive: false,
          confidence: 'SPECULATIVE',
        },
      ],
    ]);

    proverEvidenceStore = new Map();
    chainAttestationStore = new Map();

    auditStore = {
      id: 'ZYR-E2E-1',
      protocolName: 'Zyron Test Protocol',
      contractFileName: 'VaultCore.sol',
      contractAddress: '0x1111111111111111111111111111111111111111',
      gitCommit: 'e366c89',
      sourceHash: vaultCoreSha256,
      bytecodeHash: runtimeBytecodeHash,
      merkleRoot: null,
      ipfsCid: 'bafkreigjz7t5txj5xdmwgaxjt3yzc7gkzuecygcnq3gar24rhjatiujse4',
      ipfsMetadataCid: 'bafkreifhdyyqyfgymh25n4qnjgsqpg3dzzumj4nvkimn4bf46vq36cciu4',
      sloc: 145,
      stage: 'SCANNING',
      attestationStatus: 'PENDING_REVIEW',
      onChainTxHash: null,
      onChainChainId: null,
      leadAuditor: { walletAddress: auditorWallet.address },
      peerAuditor: null,
    };

    const mockPrisma: any = {
      auditRequest: {
        findUnique: vi.fn().mockImplementation(async () => ({
          ...auditStore,
          findings: Array.from(findingsStore.values()),
        })),
        update: vi.fn().mockImplementation(async ({ data }) => {
          auditStore = { ...auditStore, ...data };
          return auditStore;
        }),
      },
      finding: {
        findFirst: vi.fn().mockImplementation(async ({ where }) => {
          for (const f of findingsStore.values()) {
            if (f.id === where?.OR?.[0]?.id || f.displayId === where?.OR?.[1]?.displayId) {
              return f;
            }
          }
          return null;
        }),
        update: vi.fn().mockImplementation(async ({ where, data }) => {
          const existing = findingsStore.get(where.id);
          const updated = { ...existing, ...data };
          findingsStore.set(where.id, updated);
          return updated;
        }),
      },
      proverEvidence: {
        upsert: vi.fn().mockImplementation(async ({ where, create, update }) => {
          const findingId = where.auditId_findingId?.findingId || where.findingId;
          const rec = {
            id: `pe_${findingId}`,
            ...(proverEvidenceStore.get(findingId) || create),
            ...update,
            createdAt: new Date(),
          };
          proverEvidenceStore.set(findingId, rec);
          return rec;
        }),
        findMany: vi.fn().mockImplementation(async () => Array.from(proverEvidenceStore.values())),
      },
      chainAttestation: {
        upsert: vi.fn().mockImplementation(async ({ where, create, update }) => {
          const key = `${where.auditId_chainId.auditId}:${where.auditId_chainId.chainId}`;
          const rec = {
            id: `ca_${key}`,
            ...(chainAttestationStore.get(key) || create),
            ...update,
            updatedAt: new Date(),
          };
          chainAttestationStore.set(key, rec);
          return rec;
        }),
        findUnique: vi.fn().mockImplementation(async ({ where }) => {
          const key = `${where.auditId_chainId.auditId}:${where.auditId_chainId.chainId}`;
          return chainAttestationStore.get(key) || null;
        }),
        update: vi.fn().mockImplementation(async ({ where, data }) => {
          for (const [k, v] of chainAttestationStore.entries()) {
            if (v.id === where.id) {
              const updated = { ...v, ...data, updatedAt: new Date() };
              chainAttestationStore.set(k, updated);
              return updated;
            }
          }
          return null;
        }),
        findMany: vi.fn().mockImplementation(async () => Array.from(chainAttestationStore.values())),
      },
      user: {
        findFirst: vi.fn().mockImplementation(async ({ where }) => {
          const addrs: string[] = where?.walletAddress?.in || [];
          if (addrs.includes(clientWallet.address) || addrs.includes(clientWallet.address.toLowerCase())) {
            return { id: 'u_client', role: 'CLIENT', walletAddress: clientWallet.address };
          }
          return { id: 'u_auditor', role: 'AUDITOR', walletAddress: auditorWallet.address };
        }),
      },
    };

    const mockGateway: any = {
      emitProverComplete: vi.fn(),
      emitScanProgress: vi.fn(),
    };

    hasher = new EvidenceHasherService();
    chainConfig = new ChainConfigService();
    adapterRegistry = new ChainAdapterRegistry(chainConfig);
    proverClient = new AgentProverClientService(mockPrisma, mockGateway, hasher);
    attestationService = new AttestationService(mockPrisma, chainConfig, hasher, adapterRegistry);
    submitterService = new AttestationSubmitterService(mockPrisma, chainConfig, adapterRegistry);
  });

  afterEach(() => {
    process.env = { ...savedEnv };
  });

  it('executes the complete 5-stage Zyron workflow end-to-end across AST scanner, Meta AI prover, zyron.evidence/v1, and Monad Testnet (10143) + Base Sepolia (84532)', async () => {
    // =========================================================================
    // STAGE 1: AST Static Vulnerability Scanner on VaultCore.sol
    // =========================================================================
    const astParser = new ASTParserService();
    const cfgBuilder = new CFGBuilderService();
    const inheritanceResolver = new InheritanceResolverService();
    const pragmaAnalyzer = new PragmaAnalyzerService();
    const passRegistry = new PassRegistryService();

    const filesMap = new Map([
      [
        'src/VaultCore.sol',
        {
          filePath: 'src/VaultCore.sol',
          content: vaultCoreSource,
          sloc: vaultCoreSource.split('\n').length,
          imports: [],
        },
      ],
    ]);
    const parsedProject = astParser.parseProject(filesMap as any);
    expect(parsedProject.contracts.size).toBeGreaterThan(0);

    inheritanceResolver.resolve(parsedProject);
    cfgBuilder.buildCFGs(parsedProject);
    const pragmaAnalysis = pragmaAnalyzer.analyzeProject(filesMap as any);
    expect(pragmaAnalysis.effectiveVersion).toBeTruthy();

    const passRun = await passRegistry.runAllPasses(parsedProject);
    const allStaticFindings = passRun.findings;
    expect(allStaticFindings.length).toBeGreaterThan(0);
    expect(allStaticFindings.some((f) => f.title.toLowerCase().includes('reentran'))).toBe(true);

    // =========================================================================
    // STAGE 2: Prover Callback with HMAC Verification & Deterministic Verdicts
    // =========================================================================
    const callbackPayload = {
      jobId: 'job-e2e-001',
      auditId: 'ZYR-E2E-1',
      status: 'COMPLETED' as const,
      durationMs: 3120,
      results: [
        {
          findingId: 'find_reentrancy',
          verdict: 'PROVEN_EXPLOIT' as const,
          exploitTestCode: 'contract ExploitTest { function testExploit_ZYR_E2E_001() public {} }',
          verification: {
            verifierVersion: 'zyron-verifier/2.0.0',
            claimedVerdict: 'PROVEN_EXPLOIT',
            finalStatus: 'PROVEN_EXPLOIT' as const,
            reasonCodes: ['REPRODUCIBLE_EXPLOIT_VERIFIED_2_OF_2'],
            sourceHashes: { 'src/VaultCore.sol': vaultCoreSha256 },
            testFile: 'test/zyron/ZYR_E2E_001.t.sol',
            testFunction: 'testExploit_ZYR_E2E_001',
            testArtifactSha256: '0x' + '1'.repeat(64),
            runs: [
              { exitCode: 0, passed: true, outputSha256: '0x' + '2'.repeat(64), gasUsed: 118420 },
              { exitCode: 0, passed: true, outputSha256: '0x' + '2'.repeat(64), gasUsed: 118420 },
            ],
          },
          investigation: [
            { turn: 1, tool: 'read_file', args: { path: 'src/VaultCore.sol' }, ok: true, durationMs: 8, outputHash: '0x' + 'a'.repeat(64), summary: 'Read VaultCore.sol' },
            { turn: 2, tool: 'write_file', args: { path: 'test/zyron/ZYR_E2E_001.t.sol' }, ok: true, durationMs: 12, outputHash: '0x' + 'b'.repeat(64), summary: 'Wrote reentrancy exploit PoC' },
            { turn: 3, tool: 'run_forge_test', args: { matchContract: 'ExploitTest' }, ok: true, durationMs: 840, outputHash: '0x' + 'c'.repeat(64), summary: 'Exploit drained 10 ETH' },
          ],
          model: { provider: 'meta', model: 'muse-spark-1.3', turns: 4 },
        },
        {
          findingId: 'find_safe_withdraw',
          verdict: 'PROVEN_FALSE_POSITIVE' as const,
          verification: {
            verifierVersion: 'zyron-verifier/2.0.0',
            claimedVerdict: 'PROVEN_FALSE_POSITIVE',
            finalStatus: 'PROVEN_FALSE_POSITIVE' as const,
            reasonCodes: ['GUARD_AND_COUNTER_TEST_VERIFIED_2_OF_2'],
            sourceHashes: { 'src/VaultCore.sol': vaultCoreSha256 },
            testFile: 'test/zyron/ZYR_E2E_002.t.sol',
            testFunction: 'testCounter_ZYR_E2E_002',
            testArtifactSha256: '0x' + '3'.repeat(64),
            runs: [
              { exitCode: 0, passed: true, outputSha256: '0x' + '4'.repeat(64), gasUsed: 44100 },
              { exitCode: 0, passed: true, outputSha256: '0x' + '4'.repeat(64), gasUsed: 44100 },
            ],
          },
          model: { provider: 'meta', model: 'muse-spark-1.3', turns: 3 },
        },
        {
          findingId: 'find_inconclusive',
          verdict: 'INCONCLUSIVE' as const,
          verification: {
            verifierVersion: 'zyron-verifier/2.0.0',
            claimedVerdict: 'PROVEN_EXPLOIT',
            finalStatus: 'INCONCLUSIVE' as const,
            reasonCodes: ['MISSING_EXPLOIT_TEST_ARTIFACT'],
            sourceHashes: { 'src/VaultCore.sol': vaultCoreSha256 },
            runs: [],
          },
          model: { provider: 'meta', model: 'muse-spark-1.3', turns: 2 },
        },
      ],
    };

    const rawBody = JSON.stringify(callbackPayload);
    const validHmac =
      'sha256=' +
      crypto.createHmac('sha256', process.env.CALLBACK_SHARED_SECRET!).update(rawBody).digest('hex');

    // Tampered HMAC must fail closed
    await expect(
      proverClient.handleProverCallback('sha256=' + 'f'.repeat(64), rawBody, callbackPayload),
    ).rejects.toThrow(UnauthorizedException);

    // Authentic HMAC succeeds and persists canonical zyron.evidence/v1 records
    const callbackResult = await proverClient.handleProverCallback(validHmac, rawBody, callbackPayload);
    expect(callbackResult.success).toBe(true);
    expect(callbackResult.evidenceMerkleRoot).toMatch(/^0x[0-9a-f]{64}$/);

    // Verify finding statuses were updated according to deterministic verifier rules
    expect(findingsStore.get('find_reentrancy').fuzzTestStatus).toBe('PROVEN_EXPLOIT');
    expect(findingsStore.get('find_reentrancy').falsePositive).toBe(false);
    expect(findingsStore.get('find_safe_withdraw').fuzzTestStatus).toBe('PROVEN_FALSE_POSITIVE');
    expect(findingsStore.get('find_safe_withdraw').falsePositive).toBe(true);
    expect(findingsStore.get('find_inconclusive').fuzzTestStatus).toBe('INCONCLUSIVE');
    expect(findingsStore.get('find_inconclusive').falsePositive).toBe(false);

    // =========================================================================
    // STAGE 3: Canonical Evidence Bundle (zyron.evidence/v1) Verification
    // =========================================================================
    const bundle = await attestationService.getAuditEvidenceBundle('ZYR-E2E-1');
    expect(bundle.proverEvidences).toHaveLength(3);
    expect(bundle.evidenceRoot).toBe(callbackResult.evidenceMerkleRoot);

    for (const ev of bundle.proverEvidences) {
      expect(ev.schemaVersion).toBe(EVIDENCE_SCHEMA_V1);
      expect(ev.verifierVersion).toBe('zyron-verifier/2.0.0');
      expect(ev.provider).toBe('meta');
      expect(ev.model).toBe('muse-spark-1.3');
      expect(hasher.verifyEvidenceDigest(ev.canonicalJson, ev.evidenceHash)).toBe(true);
    }

    // =========================================================================
    // STAGE 4: Multichain Attestation (Monad Testnet 10143 + Base Sepolia 84532)
    // =========================================================================
    const preparedMonad = await attestationService.prepareChainAttestation(
      'ZYR-E2E-1',
      10143,
      auditorWallet.address,
    );
    const preparedBase = await attestationService.prepareChainAttestation(
      'ZYR-E2E-1',
      84532,
      auditorWallet.address,
    );

    expect(preparedMonad.contractIdentity).toBe('10143:0x1111111111111111111111111111111111111111');
    expect(preparedBase.contractIdentity).toBe('84532:0x1111111111111111111111111111111111111111');
    expect(preparedMonad.registryAddress).toBe('0xBd24D2BFFbc69a17aCe69aaF930fC4e0d979c4D3');
    expect(preparedBase.registryAddress).toBe('0xc242125A0b342E045Cf0E1c2e02C95D1EAEEC5c4');
    expect(preparedMonad.evidenceRoot).toBe(bundle.evidenceRoot);
    expect(preparedBase.evidenceRoot).toBe(bundle.evidenceRoot);

    const monadSignature = await auditorWallet.signTypedData(
      preparedMonad.typedData.domain,
      { AttestationPayload: preparedMonad.typedData.types.AttestationPayload },
      preparedMonad.typedData.message,
    );
    const baseSignature = await auditorWallet.signTypedData(
      preparedBase.typedData.domain,
      { AttestationPayload: preparedBase.typedData.types.AttestationPayload },
      preparedBase.typedData.message,
    );

    // Cross-chain replay check: Base Sepolia signature MUST fail on Monad Testnet (10143)
    await expect(
      attestationService.approveChainAttestation({
        auditId: 'ZYR-E2E-1',
        chainId: 10143,
        signature: baseSignature,
        signerAddress: auditorWallet.address,
      }),
    ).rejects.toThrow(BadRequestException);

    // Unauthorized role check: CLIENT user wallet MUST fail with ForbiddenException
    await expect(
      attestationService.approveChainAttestation({
        auditId: 'ZYR-E2E-1',
        chainId: 10143,
        signature: monadSignature,
        signerAddress: clientWallet.address,
      }),
    ).rejects.toThrow(ForbiddenException);

    // Valid human AUDITOR signatures approve both chains independently
    const approvedMonad = await attestationService.approveChainAttestation({
      auditId: 'ZYR-E2E-1',
      chainId: 10143,
      signature: monadSignature,
      signerAddress: auditorWallet.address,
    });
    const approvedBase = await attestationService.approveChainAttestation({
      auditId: 'ZYR-E2E-1',
      chainId: 84532,
      signature: baseSignature,
      signerAddress: auditorWallet.address,
    });
    expect(approvedMonad.status).toBe('APPROVED');
    expect(approvedBase.status).toBe('APPROVED');

    // Mock adapter on-chain broadcast to verify ABI encoding and submission lifecycle on both chains
    const registryInterface = new Interface(ZYRON_ATTESTATION_REGISTRY_ABI);
    for (const chainId of [10143, 84532]) {
      const adapter = adapterRegistry.getAdapter(chainId);
      vi.spyOn(adapter, 'submitSignedAttestation').mockImplementation(async (params) => {
        // Verify that the calldata encodes cleanly against ZyronAttestation.sol's ABI
        const encoded = registryInterface.encodeFunctionData('publishAttestationWithSignature', [
          {
            auditId: keccak256(toUtf8Bytes(params.prepared.auditId)),
            protocolName: params.protocolName,
            targetContract: params.targetContractFile,
            gitCommit: params.gitCommit || '',
            repoTreeHash: params.prepared.repoTreeHash,
            bytecodeHash: params.prepared.bytecodeHash,
            merkleRoot: params.prepared.merkleRoot,
            ipfsReportCid: params.ipfsCid || '',
            ipfsMetadataCid: params.ipfsMetadataCid || '',
            recipient: '0x0000000000000000000000000000000000000000',
            leadAuditor: params.prepared.typedData.message.leadAuditor,
            peerAuditor: '0x0000000000000000000000000000000000000000',
            sloc: params.prepared.typedData.message.sloc,
          },
          params.prepared.typedData.message.status,
          params.prepared.typedData.message.timestamp,
          params.signature,
        ]);
        expect(encoded).toMatch(/^0x72318d78/); // publishAttestationWithSignature selector

        const txHash = '0x' + crypto.createHash('sha256').update(`${chainId}:${params.signature}`).digest('hex');
        return {
          txHash,
          blockNumber: chainId === 10143 ? 68405001 : 51552990,
          chainId,
          chainName: adapter.name,
          registryAddress: adapter.getChainConfig().attestationAddress,
          status: 'CONFIRMED',
          explorerUrl: `${adapter.getChainConfig().explorerUrl}/tx/${txHash}`,
        };
      });
    }

    const submittedMonad = await submitterService.submitApprovedChainAttestation('ZYR-E2E-1', 10143);
    const submittedBase = await submitterService.submitApprovedChainAttestation('ZYR-E2E-1', 84532);

    expect(submittedMonad.status).toBe('CONFIRMED');
    expect(submittedMonad.chainId).toBe(10143);
    expect(submittedBase.status).toBe('CONFIRMED');
    expect(submittedBase.chainId).toBe(84532);
    expect(submittedMonad.txHash).not.toBe(submittedBase.txHash);

    // Duplicate submission on an already-confirmed chain must be rejected
    await expect(submitterService.submitApprovedChainAttestation('ZYR-E2E-1', 10143)).rejects.toThrow(
      /Duplicate submission rejected/,
    );

    // =========================================================================
    // STAGE 5: Public Verification Bundle Inspection
    // =========================================================================
    const finalBundle = await attestationService.getAuditEvidenceBundle('ZYR-E2E-1');
    expect(finalBundle.chainAttestations).toHaveLength(2);
    const monadRecord = finalBundle.chainAttestations.find((c: any) => c.chainId === 10143);
    const baseRecord = finalBundle.chainAttestations.find((c: any) => c.chainId === 84532);

    expect(monadRecord?.status).toBe('CONFIRMED');
    expect(monadRecord?.txHash).toBe(submittedMonad.txHash);
    expect(monadRecord?.evidenceRoot).toBe(bundle.evidenceRoot);

    expect(baseRecord?.status).toBe('CONFIRMED');
    expect(baseRecord?.txHash).toBe(submittedBase.txHash);
    expect(baseRecord?.evidenceRoot).toBe(bundle.evidenceRoot);
  });
});
