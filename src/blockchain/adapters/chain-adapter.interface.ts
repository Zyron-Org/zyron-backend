import { createHash } from 'crypto';
import { ethers, keccak256, toUtf8Bytes, verifyTypedData } from 'ethers';
import { ChainConfig, ChainConfigService } from '../services/chain-config.service';
import { normalizeBytes32 } from '../utils';

export const ATTESTATION_SIGNATURE_TTL_SECONDS = 24 * 60 * 60; // 24 hours

const ATTESTATION_INPUT_TUPLE =
  'tuple(bytes32 auditId, string protocolName, string targetContract, string gitCommit, bytes32 repoTreeHash, bytes32 bytecodeHash, bytes32 merkleRoot, string ipfsReportCid, string ipfsMetadataCid, address recipient, address leadAuditor, address peerAuditor, uint256 sloc)';

const ATTESTATION_RECORD_TUPLE =
  'tuple(bytes32 auditId, string protocolName, string targetContract, string gitCommit, bytes32 repoTreeHash, bytes32 bytecodeHash, bytes32 merkleRoot, string ipfsReportCid, string ipfsMetadataCid, address recipient, address leadAuditor, address peerAuditor, uint256 sloc, uint256 timestamp, uint256 tokenId, uint8 status, bool isVerified)';

export const ZYRON_ATTESTATION_REGISTRY_ABI = [
  `function publishAttestation(${ATTESTATION_INPUT_TUPLE} input) external returns (uint256)`,
  `function publishAttestationWithSignature(${ATTESTATION_INPUT_TUPLE} input, uint8 status, uint256 timestamp, bytes signature) external returns (uint256)`,
  `function verifyAttestation(bytes32 auditId) external view returns (${ATTESTATION_RECORD_TUPLE})`,
];

export const EIP712_ATTESTATION_TYPES = {
  EIP712Domain: [
    { name: 'name', type: 'string' },
    { name: 'version', type: 'string' },
    { name: 'chainId', type: 'uint256' },
    { name: 'verifyingContract', type: 'address' },
  ],
  AttestationPayload: [
    { name: 'auditId', type: 'bytes32' },
    { name: 'merkleRoot', type: 'bytes32' },
    { name: 'repoTreeHash', type: 'bytes32' },
    { name: 'bytecodeHash', type: 'bytes32' },
    { name: 'leadAuditor', type: 'address' },
    { name: 'sloc', type: 'uint256' },
    { name: 'status', type: 'uint8' },
    { name: 'timestamp', type: 'uint256' },
  ],
};

export function formatChainScopedIdentity(chainId: number, address?: string | null): string {
  const trimmed = (address || '').trim();
  const normalizedAddr = /^0x[0-9a-fA-F]{40}$/.test(trimmed) ? trimmed.toLowerCase() : ethers.ZeroAddress;
  return `${chainId}:${normalizedAddr}`;
}

export interface PrepareAttestationParams {
  auditId: string;
  protocolName: string;
  targetContractFile: string;
  targetContractAddress?: string | null;
  gitCommit?: string | null;
  repoTreeHash?: string | null;
  bytecodeHash?: string | null;
  evidenceRoot: string;
  sloc: number;
  leadAuditor: string;
  peerAuditor?: string | null;
  ipfsCid?: string | null;
  ipfsMetadataCid?: string | null;
  timestamp?: number;
}

export interface PreparedChainAttestation {
  auditId: string;
  chainId: number;
  chainName: string;
  contractIdentity: string;
  targetContractAddress: string;
  registryAddress: string;
  evidenceRoot: string;
  merkleRoot: string;
  repoTreeHash: string;
  bytecodeHash: string;
  typedData: {
    types: typeof EIP712_ATTESTATION_TYPES;
    primaryType: 'AttestationPayload';
    domain: {
      name: string;
      version: string;
      chainId: number;
      verifyingContract: string;
    };
    message: {
      auditId: string;
      merkleRoot: string;
      repoTreeHash: string;
      bytecodeHash: string;
      leadAuditor: string;
      sloc: number;
      status: number;
      timestamp: number;
    };
  };
}

export interface SubmittedChainAttestation {
  txHash: string;
  blockNumber: number | null;
  chainId: number;
  chainName: string;
  registryAddress: string;
  status: 'SUBMITTED' | 'CONFIRMED';
  explorerUrl: string;
}

export interface OnChainVerificationRecord {
  isVerified: boolean;
  auditId: string;
  chainId: number;
  chainName: string;
  contractAddress: string;
  merkleRoot?: string;
  bytecodeHash?: string;
  repoTreeHash?: string;
  ipfsReportCid?: string;
  ipfsMetadataCid?: string;
  protocolName?: string;
  targetContract?: string;
  gitCommit?: string;
  recipient?: string;
  leadAuditor?: string;
  peerAuditor?: string;
  sloc?: number;
  timestamp?: number;
  tokenId?: number;
  status?: number;
  explorerUrl?: string;
  reason?: string;
}

export interface ChainAdapter {
  readonly chainId: number;
  readonly name: string;
  readonly isTestnet: boolean;
  readonly nativeSymbol: string;

  getChainConfig(): ChainConfig;
  isConfigured(): boolean;
  getMissingConfigReason(): string | null;
  formatContractIdentity(address?: string | null): string;
  verifyChainIdentity(): Promise<{ ok: boolean; reportedChainId: number }>;
  getRuntimeBytecode(address: string): Promise<string>;
  verifyBytecodeHash(address: string, expectedHash: string): Promise<{ matches: boolean; actualKeccak256: string; actualSha256: string }>;
  prepareAttestation(params: PrepareAttestationParams): PreparedChainAttestation;
  verifyAttestationSignature(
    prepared: PreparedChainAttestation,
    signature: string,
    expectedSigner?: string,
    nowSeconds?: number,
  ): { valid: boolean; recoveredSigner: string; reason?: string };
  submitSignedAttestation(params: {
    prepared: PreparedChainAttestation;
    signature: string;
    protocolName: string;
    targetContractFile: string;
    gitCommit?: string | null;
    ipfsCid?: string | null;
    ipfsMetadataCid?: string | null;
    peerAuditor?: string | null;
  }): Promise<SubmittedChainAttestation>;
  readAttestation(auditId: string): Promise<OnChainVerificationRecord>;
  getExplorerTxUrl(txHash: string): string;
  getExplorerAddressUrl(address: string): string;
}

export abstract class EvmChainAdapter implements ChainAdapter {
  abstract readonly chainId: number;
  abstract readonly name: string;
  abstract readonly isTestnet: boolean;
  abstract readonly nativeSymbol: string;

  constructor(protected readonly chainConfigService: ChainConfigService) {}

  getChainConfig(): ChainConfig {
    const cfg = this.chainConfigService.getChainConfig(this.chainId);
    if (!cfg) {
      throw new Error(`Chain config missing for chainId ${this.chainId} (${this.name})`);
    }
    return cfg;
  }

  isConfigured(): boolean {
    const cfg = this.chainConfigService.getChainConfig(this.chainId);
    return Boolean(cfg && cfg.rpcUrl && cfg.attestationAddress && ethers.isAddress(cfg.attestationAddress));
  }

  getMissingConfigReason(): string | null {
    const cfg = this.chainConfigService.getChainConfig(this.chainId);
    if (!cfg) return `Chain ${this.chainId} is not registered in ChainConfigService.`;
    if (!cfg.rpcUrl) return `Missing RPC URL for ${this.name} (${this.chainId}).`;
    if (!cfg.attestationAddress || !ethers.isAddress(cfg.attestationAddress)) {
      return `Missing deployed ZyronAttestation registry address for ${this.name} (chainId ${this.chainId}).`;
    }
    return null;
  }

  formatContractIdentity(address?: string | null): string {
    return formatChainScopedIdentity(this.chainId, address);
  }

  async verifyChainIdentity(): Promise<{ ok: boolean; reportedChainId: number }> {
    const provider = this.chainConfigService.getProvider(this.chainId);
    const network = await provider.getNetwork();
    const reportedChainId = Number(network.chainId);
    return {
      ok: reportedChainId === this.chainId,
      reportedChainId,
    };
  }

  async getRuntimeBytecode(address: string): Promise<string> {
    if (!ethers.isAddress(address)) {
      throw new Error(`Invalid contract address "${address}" on chain ${this.chainId}`);
    }
    const provider = this.chainConfigService.getProvider(this.chainId);
    return provider.getCode(address);
  }

  async verifyBytecodeHash(
    address: string,
    expectedHash: string,
  ): Promise<{ matches: boolean; actualKeccak256: string; actualSha256: string }> {
    const code = await this.getRuntimeBytecode(address);
    if (!code || code === '0x') {
      return { matches: false, actualKeccak256: '0x' + '0'.repeat(64), actualSha256: '0x' + '0'.repeat(64) };
    }
    const actualKeccak256 = keccak256(code).toLowerCase();
    const rawBytes = Buffer.from(code.replace(/^0x/, ''), 'hex');
    const actualSha256 = '0x' + createHash('sha256').update(rawBytes).digest('hex').toLowerCase();
    const normExpected = (expectedHash.startsWith('0x') ? expectedHash : `0x${expectedHash}`).toLowerCase();
    return {
      matches: normExpected === actualKeccak256 || normExpected === actualSha256,
      actualKeccak256,
      actualSha256,
    };
  }

  prepareAttestation(params: PrepareAttestationParams): PreparedChainAttestation {
    if (!this.isTestnet) {
      throw new Error(`Safety refusal: chain ${this.chainId} (${this.name}) is not a testnet.`);
    }
    const cfg = this.getChainConfig();
    if (!cfg.attestationAddress || !ethers.isAddress(cfg.attestationAddress)) {
      throw new Error(
        this.getMissingConfigReason() ||
          `Attestation registry not configured for ${this.name} (${this.chainId}).`,
      );
    }

    if (!params.leadAuditor || !ethers.isAddress(params.leadAuditor) || params.leadAuditor === ethers.ZeroAddress) {
      throw new Error('A valid non-zero leadAuditor wallet address is required to prepare an attestation.');
    }

    const evidenceRoot = normalizeBytes32(params.evidenceRoot);
    const repoTreeHash = normalizeBytes32(params.repoTreeHash);
    const bytecodeHash = normalizeBytes32(
      params.bytecodeHash ||
        '0x' +
          createHash('sha256')
            .update(`${this.chainId}:${params.protocolName}:${params.targetContractFile}:${params.gitCommit || ''}:${params.auditId}`)
            .digest('hex'),
    );
    const timestamp = params.timestamp ?? Math.floor(Date.now() / 1000);
    const targetAddr =
      params.targetContractAddress && ethers.isAddress(params.targetContractAddress)
        ? params.targetContractAddress
        : ethers.ZeroAddress;

    return {
      auditId: params.auditId,
      chainId: this.chainId,
      chainName: this.name,
      contractIdentity: this.formatContractIdentity(targetAddr),
      targetContractAddress: targetAddr,
      registryAddress: cfg.attestationAddress,
      evidenceRoot,
      merkleRoot: evidenceRoot,
      repoTreeHash,
      bytecodeHash,
      typedData: {
        types: EIP712_ATTESTATION_TYPES,
        primaryType: 'AttestationPayload',
        domain: {
          name: 'ZyronAttestation',
          version: '3.0.0',
          chainId: this.chainId,
          verifyingContract: cfg.attestationAddress,
        },
        message: {
          auditId: keccak256(toUtf8Bytes(params.auditId)),
          merkleRoot: evidenceRoot,
          repoTreeHash,
          bytecodeHash,
          leadAuditor: params.leadAuditor,
          sloc: params.sloc || 100,
          status: 2, // MANUALLY_ATTESTED
          timestamp,
        },
      },
    };
  }

  verifyAttestationSignature(
    prepared: PreparedChainAttestation,
    signature: string,
    expectedSigner?: string,
    nowSeconds = Math.floor(Date.now() / 1000),
  ): { valid: boolean; recoveredSigner: string; reason?: string } {
    if (!signature || !/^0x[0-9a-fA-F]{130}$/.test(signature.trim())) {
      return { valid: false, recoveredSigner: '', reason: 'Invalid 65-byte EIP-712 hex signature format.' };
    }

    const cfg = this.getChainConfig();
    if (prepared.typedData.domain.chainId !== this.chainId) {
      return {
        valid: false,
        recoveredSigner: '',
        reason: `Domain chainId mismatch: expected ${this.chainId}, got ${prepared.typedData.domain.chainId}.`,
      };
    }

    if (prepared.typedData.domain.verifyingContract.toLowerCase() !== cfg.attestationAddress.toLowerCase()) {
      return {
        valid: false,
        recoveredSigner: '',
        reason: `Domain verifyingContract mismatch for chain ${this.chainId}.`,
      };
    }

    const msgTs = Number(prepared.typedData.message.timestamp);
    if (!Number.isFinite(msgTs) || msgTs <= 0) {
      return { valid: false, recoveredSigner: '', reason: 'Invalid attestation timestamp.' };
    }
    if (Math.abs(nowSeconds - msgTs) > ATTESTATION_SIGNATURE_TTL_SECONDS) {
      return {
        valid: false,
        recoveredSigner: '',
        reason: `Attestation signature expired or timestamp out of window (>${ATTESTATION_SIGNATURE_TTL_SECONDS}s).`,
      };
    }

    try {
      const recovered = verifyTypedData(
        prepared.typedData.domain,
        { AttestationPayload: prepared.typedData.types.AttestationPayload },
        prepared.typedData.message,
        signature.trim(),
      );

      const expectedLead = prepared.typedData.message.leadAuditor;
      if (recovered.toLowerCase() !== expectedLead.toLowerCase()) {
        return {
          valid: false,
          recoveredSigner: recovered,
          reason: `Recovered signer ${recovered} does not match payload leadAuditor ${expectedLead}.`,
        };
      }

      if (expectedSigner && recovered.toLowerCase() !== expectedSigner.toLowerCase()) {
        return {
          valid: false,
          recoveredSigner: recovered,
          reason: `Recovered signer ${recovered} does not match expected reviewer ${expectedSigner}.`,
        };
      }

      return { valid: true, recoveredSigner: recovered };
    } catch (err: any) {
      return {
        valid: false,
        recoveredSigner: '',
        reason: `EIP-712 signature recovery failed: ${err.message}`,
      };
    }
  }

  async submitSignedAttestation(params: {
    prepared: PreparedChainAttestation;
    signature: string;
    protocolName: string;
    targetContractFile: string;
    gitCommit?: string | null;
    ipfsCid?: string | null;
    ipfsMetadataCid?: string | null;
    peerAuditor?: string | null;
  }): Promise<SubmittedChainAttestation> {
    if (!this.isTestnet) {
      throw new Error(`Safety refusal: automatic transaction submission to mainnet (${this.chainId}) is prohibited.`);
    }

    const cfg = this.getChainConfig();
    if (!cfg.attestationAddress || !ethers.isAddress(cfg.attestationAddress)) {
      throw new Error(
        this.getMissingConfigReason() ||
          `Attestation registry not configured for ${this.name} (${this.chainId}).`,
      );
    }

    const operatorPrivateKey = process.env.OPERATOR_PRIVATE_KEY?.trim();
    if (!operatorPrivateKey) {
      throw new Error(
        `OPERATOR_PRIVATE_KEY is not configured; refusing to fabricate a transaction hash on ${this.name} (${this.chainId}).`,
      );
    }

    const sigCheck = this.verifyAttestationSignature(params.prepared, params.signature);
    if (!sigCheck.valid) {
      throw new Error(`Cannot submit attestation with invalid signature: ${sigCheck.reason}`);
    }

    const provider = this.chainConfigService.getProvider(this.chainId);
    const wallet = new ethers.Wallet(operatorPrivateKey, provider);
    const contract = this.createContractInstance(cfg.attestationAddress, ZYRON_ATTESTATION_REGISTRY_ABI, wallet);

    const msg = params.prepared.typedData.message;
    const validPeer =
      params.peerAuditor && ethers.isAddress(params.peerAuditor) ? params.peerAuditor : ethers.ZeroAddress;

    const input = {
      auditId: msg.auditId,
      protocolName: params.protocolName || '',
      targetContract: params.targetContractFile || 'Contract.sol',
      gitCommit: params.gitCommit || '',
      repoTreeHash: msg.repoTreeHash,
      bytecodeHash: msg.bytecodeHash,
      merkleRoot: msg.merkleRoot,
      ipfsReportCid: params.ipfsCid || '',
      ipfsMetadataCid: params.ipfsMetadataCid || '',
      recipient: ethers.ZeroAddress,
      leadAuditor: msg.leadAuditor,
      peerAuditor: validPeer,
      sloc: msg.sloc,
    };

    const tx = await contract.publishAttestationWithSignature(
      input,
      msg.status,
      msg.timestamp,
      params.signature.trim(),
    );

    const receipt = await tx.wait(1);
    const txHash: string = receipt?.hash || tx.hash;
    const blockNumber: number | null = receipt?.blockNumber != null ? Number(receipt.blockNumber) : null;

    return {
      txHash,
      blockNumber,
      chainId: this.chainId,
      chainName: this.name,
      registryAddress: cfg.attestationAddress,
      status: receipt ? 'CONFIRMED' : 'SUBMITTED',
      explorerUrl: this.getExplorerTxUrl(txHash),
    };
  }

  async readAttestation(auditId: string): Promise<OnChainVerificationRecord> {
    const cfg = this.chainConfigService.getChainConfig(this.chainId);
    if (!cfg || !cfg.attestationAddress || !ethers.isAddress(cfg.attestationAddress)) {
      return {
        isVerified: false,
        auditId,
        chainId: this.chainId,
        chainName: this.name,
        contractAddress: cfg?.attestationAddress || '',
        reason: 'Attestation contract not configured for this chain',
      };
    }

    try {
      const provider = this.chainConfigService.getProvider(this.chainId);
      const contract = this.createContractInstance(cfg.attestationAddress, ZYRON_ATTESTATION_REGISTRY_ABI, provider);
      const auditIdBytes32 = keccak256(toUtf8Bytes(auditId));
      const record = await contract.verifyAttestation(auditIdBytes32);

      return {
        isVerified: Boolean(record.isVerified),
        auditId,
        chainId: this.chainId,
        chainName: this.name,
        contractAddress: cfg.attestationAddress,
        merkleRoot: record.merkleRoot,
        bytecodeHash: record.bytecodeHash,
        repoTreeHash: record.repoTreeHash,
        ipfsReportCid: record.ipfsReportCid,
        ipfsMetadataCid: record.ipfsMetadataCid,
        protocolName: record.protocolName,
        targetContract: record.targetContract,
        gitCommit: record.gitCommit,
        recipient: record.recipient,
        leadAuditor: record.leadAuditor,
        peerAuditor: record.peerAuditor,
        sloc: Number(record.sloc),
        timestamp: Number(record.timestamp),
        tokenId: Number(record.tokenId),
        status: Number(record.status),
        explorerUrl: this.getExplorerAddressUrl(cfg.attestationAddress),
      };
    } catch (err: any) {
      return {
        isVerified: false,
        auditId,
        chainId: this.chainId,
        chainName: this.name,
        contractAddress: cfg.attestationAddress,
        reason: err.message?.includes('No verified attestation')
          ? 'No verified attestation found on-chain'
          : err.message,
      };
    }
  }

  getExplorerTxUrl(txHash: string): string {
    const cfg = this.getChainConfig();
    return `${cfg.explorerUrl.replace(/\/+$/, '')}/tx/${txHash}`;
  }

  getExplorerAddressUrl(address: string): string {
    const cfg = this.getChainConfig();
    return `${cfg.explorerUrl.replace(/\/+$/, '')}/address/${address}`;
  }

  protected createContractInstance(address: string, abi: any, signerOrProvider: any): any {
    return new ethers.Contract(address, abi, signerOrProvider);
  }
}
