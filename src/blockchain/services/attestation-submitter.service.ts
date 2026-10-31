import { Injectable, Logger, BadRequestException, Optional } from '@nestjs/common';
import { ethers, keccak256, toUtf8Bytes } from 'ethers';
import { PrismaService } from '../../database/database.module';
import { ChainConfigService } from './chain-config.service';
import { ChainAdapterRegistry, PreparedChainAttestation } from '../adapters';
import { getDefaultAttestationChainId } from '../constants';
import { normalizeBytes32 } from '../utils';

// Mirrors ZyronAttestation.AttestationInput in zyron-contracts/src/ZyronAttestation.sol.
const ATTESTATION_INPUT =
  'tuple(bytes32 auditId, string protocolName, string targetContract, string gitCommit, bytes32 repoTreeHash, bytes32 bytecodeHash, bytes32 merkleRoot, string ipfsReportCid, string ipfsMetadataCid, address recipient, address leadAuditor, address peerAuditor, uint256 sloc)';

// Mirrors ZyronAttestation.AttestationRecord.
const ATTESTATION_RECORD =
  'tuple(bytes32 auditId, string protocolName, string targetContract, string gitCommit, bytes32 repoTreeHash, bytes32 bytecodeHash, bytes32 merkleRoot, string ipfsReportCid, string ipfsMetadataCid, address recipient, address leadAuditor, address peerAuditor, uint256 sloc, uint256 timestamp, uint256 tokenId, uint8 status, bool isVerified)';

const ZYRON_ATTESTATION_ABI = [
  `function publishAttestation(${ATTESTATION_INPUT} input) external returns (uint256)`,
  `function publishAttestationWithSignature(${ATTESTATION_INPUT} input, uint8 status, uint256 timestamp, bytes signature) external returns (uint256)`,
  `function verifyAttestation(bytes32 auditId) external view returns (${ATTESTATION_RECORD})`,
];

/** Build the on-chain AttestationInput struct from a persisted audit. */
function buildAttestationInput(
  audit: any,
  overrides: { leadAuditor: string; merkleRoot?: string; bytecodeHash?: string; repoTreeHash?: string; sloc?: number },
) {
  const validLeadAuditor =
    overrides.leadAuditor && ethers.isAddress(overrides.leadAuditor) && overrides.leadAuditor !== ethers.ZeroAddress
      ? overrides.leadAuditor
      : '0x48b106E3C8681D08c513268854Aef257883298d3';

  const validPeerAuditor =
    audit.peerAuditor?.walletAddress && ethers.isAddress(audit.peerAuditor.walletAddress)
      ? audit.peerAuditor.walletAddress
      : ethers.ZeroAddress;

  return {
    auditId: keccak256(toUtf8Bytes(audit.id)),
    protocolName: audit.protocolName || '',
    targetContract: audit.contractFileName || 'Contract.sol',
    gitCommit: audit.gitCommit || '',
    repoTreeHash: normalizeBytes32(overrides.repoTreeHash ?? audit.sourceHash),
    bytecodeHash: normalizeBytes32(overrides.bytecodeHash ?? audit.bytecodeHash),
    merkleRoot: normalizeBytes32(overrides.merkleRoot ?? audit.merkleRoot),
    ipfsReportCid: audit.ipfsCid || '',
    ipfsMetadataCid: audit.ipfsMetadataCid || '',
    // address(0) → the contract mints the soulbound badge to the lead auditor.
    recipient: ethers.ZeroAddress,
    leadAuditor: validLeadAuditor,
    peerAuditor: validPeerAuditor,
    sloc: overrides.sloc ?? (audit.sloc || 100),
  };
}

@Injectable()
export class AttestationSubmitterService {
  private readonly logger = new Logger(AttestationSubmitterService.name);
  private readonly adapterRegistry: ChainAdapterRegistry;

  constructor(
    private prisma: PrismaService,
    private chainConfig: ChainConfigService,
    @Optional() adapterRegistry?: ChainAdapterRegistry,
  ) {
    this.adapterRegistry = adapterRegistry || new ChainAdapterRegistry(this.chainConfig);
  }

  /**
   * Submit automated on-chain attestation via operator wallet.
   */
  async submitAutomatedAttestation(auditId: string, targetChainId?: number): Promise<{ txHash: string; chainId: number }> {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { leadAuditor: true, peerAuditor: true },
    });

    if (!audit) throw new BadRequestException(`Audit ${auditId} not found`);

    if (
      audit.onChainTxHash &&
      (audit.attestationStatus === 'CONFIRMED' ||
        audit.attestationStatus === 'AUTOMATED_ONLY' ||
        audit.attestationStatus === 'MANUALLY_ATTESTED')
    ) {
      throw new BadRequestException(`Audit ${auditId} has already been attested on-chain.`);
    }

    const chainId = targetChainId || audit.onChainChainId || getDefaultAttestationChainId();
    const config = this.chainConfig.getChainConfig(chainId);
    if (!config) throw new BadRequestException(`Chain ID ${chainId} not supported`);

    if (!config.attestationAddress) {
      throw new BadRequestException(`Attestation contract address not configured for chain ${chainId}`);
    }

    const operatorPrivateKey = process.env.OPERATOR_PRIVATE_KEY?.trim();
    if (!operatorPrivateKey) {
      throw new BadRequestException(
        `OPERATOR_PRIVATE_KEY is not configured; refusing to fabricate a transaction hash for audit ${auditId} on chain ${chainId}.`,
      );
    }

    const provider = this.chainConfig.getProvider(chainId);
    const wallet = new ethers.Wallet(operatorPrivateKey, provider);
    const contract = this.getContractInstance(config.attestationAddress, ZYRON_ATTESTATION_ABI, wallet);

    let leadAuditorAddr = audit.leadAuditor?.walletAddress || wallet.address;
    if (!leadAuditorAddr || !ethers.isAddress(leadAuditorAddr) || leadAuditorAddr === ethers.ZeroAddress) {
      leadAuditorAddr = wallet.address;
    }
    const input = buildAttestationInput(audit, { leadAuditor: leadAuditorAddr });

    this.logger.log(`Broadcasting publishAttestation to chain ${chainId} for ${auditId}...`);
    try {
      const tx = await contract.publishAttestation(input);

      const receipt = await tx.wait(1);
      const txHash = receipt.hash;

      await this.prisma.auditRequest.update({
        where: { id: auditId },
        data: {
          onChainTxHash: txHash,
          onChainChainId: chainId,
          attestationStatus: 'AUTOMATED_ONLY',
        },
      });

      this.logger.log(`On-chain attestation confirmed: ${txHash} on chain ${chainId}`);
      return { txHash, chainId };
    } catch (err: any) {
      this.logger.error(`Failed to publish attestation: ${err.message}`);
      throw new BadRequestException(`Attestation transaction failed: ${err.message}`);
    }
  }

  protected getContractInstance(address: string, abi: any, signerOrProvider: any): any {
    return new ethers.Contract(address, abi, signerOrProvider);
  }

  /**
   * Submit human-attested on-chain attestation with EIP-712 auditor signature.
   * Never fabricates a tx hash and never silently falls back to unsigned publishAttestation.
   */
  async submitSignedAttestation(
    auditId: string,
    signature: string,
    signerAddress: string,
    payloadMessage: any,
    targetChainId?: number,
  ): Promise<{ txHash: string; chainId: number; isRelayed: boolean }> {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { leadAuditor: true, peerAuditor: true },
    });

    if (!audit) throw new BadRequestException(`Audit ${auditId} not found`);

    const chainId = targetChainId || audit.onChainChainId || getDefaultAttestationChainId();
    const config = this.chainConfig.getChainConfig(chainId);
    if (!config) throw new BadRequestException(`Chain ID ${chainId} not supported`);

    if (!config.attestationAddress) {
      throw new BadRequestException(`Attestation contract address not configured for chain ${chainId}`);
    }

    const operatorPrivateKey = process.env.OPERATOR_PRIVATE_KEY?.trim();
    if (!operatorPrivateKey) {
      throw new BadRequestException(
        `OPERATOR_PRIVATE_KEY is not configured; refusing to fabricate a transaction hash for signed attestation ${auditId} on chain ${chainId}.`,
      );
    }

    const provider = this.chainConfig.getProvider(chainId);
    const wallet = new ethers.Wallet(operatorPrivateKey, provider);
    const contract = this.getContractInstance(config.attestationAddress, ZYRON_ATTESTATION_ABI, wallet);

    let leadAuditorAddr = signerAddress || audit.leadAuditor?.walletAddress || wallet.address;
    if (!leadAuditorAddr || !ethers.isAddress(leadAuditorAddr) || leadAuditorAddr === ethers.ZeroAddress) {
      leadAuditorAddr = wallet.address;
    }
    const input = buildAttestationInput(audit, {
      leadAuditor: leadAuditorAddr,
      merkleRoot: payloadMessage?.merkleRoot,
      bytecodeHash: payloadMessage?.bytecodeHash,
      repoTreeHash: payloadMessage?.repoTreeHash,
      sloc: payloadMessage?.sloc || audit.sloc || 100,
    });
    const status = payloadMessage?.status || 2; // MANUALLY_ATTESTED
    const timestamp = payloadMessage?.timestamp || Math.floor(Date.now() / 1000);

    this.logger.log(`Relaying signed attestation to chain ${chainId} for ${auditId}...`);
    try {
      const tx = await contract.publishAttestationWithSignature(input, status, timestamp, signature);
      const receipt = await tx.wait(1);
      const txHash = receipt.hash;
      const blockNumber = receipt?.blockNumber != null ? Number(receipt.blockNumber) : null;

      await this.prisma.auditRequest.update({
        where: { id: auditId },
        data: {
          onChainTxHash: txHash,
          onChainChainId: chainId,
          attestationStatus: 'MANUALLY_ATTESTED',
          attestationSig: signature,
        },
      });

      if ((this.prisma as any).chainAttestation?.upsert) {
        const explorerUrl = `${config.explorerUrl.replace(/\/+$/, '')}/tx/${txHash}`;
        const contractIdentity = `${chainId}:${(audit.contractAddress || ethers.ZeroAddress).toLowerCase()}`;
        await (this.prisma as any).chainAttestation.upsert({
          where: {
            auditId_chainId: {
              auditId,
              chainId,
            },
          },
          update: {
            status: 'CONFIRMED',
            signerAddress: leadAuditorAddr,
            signature,
            txHash,
            blockNumber,
            explorerUrl,
            errorReason: null,
          },
          create: {
            auditId,
            chainId,
            chainName: config.name,
            contractIdentity,
            targetContractAddress: audit.contractAddress || ethers.ZeroAddress,
            registryAddress: config.attestationAddress,
            bytecodeHash: input.bytecodeHash,
            evidenceRoot: input.merkleRoot,
            merkleRoot: input.merkleRoot,
            repoTreeHash: input.repoTreeHash,
            status: 'CONFIRMED',
            preparedPayloadJson: JSON.stringify(payloadMessage || {}),
            signerAddress: leadAuditorAddr,
            signature,
            approvedAt: new Date(),
            txHash,
            blockNumber,
            explorerUrl,
          },
        });
      }

      this.logger.log(`On-chain signed attestation confirmed: ${txHash} on chain ${chainId}`);
      return { txHash, chainId, isRelayed: true };
    } catch (err: any) {
      this.logger.error(`Failed to broadcast signed attestation on-chain: ${err.message}`);
      throw new BadRequestException(`On-chain transaction failed: ${err.message}`);
    }
  }

  /**
   * Submit an `APPROVED` chain-scoped attestation record via the target chain's `ChainAdapter`.
   */
  async submitApprovedChainAttestation(auditId: string, chainId: number) {
    const adapter = this.adapterRegistry.getAdapter(chainId);
    if (!adapter.isConfigured()) {
      throw new BadRequestException(
        adapter.getMissingConfigReason() || `Attestation registry not configured for chain ${chainId}.`,
      );
    }

    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { leadAuditor: true, peerAuditor: true },
    });
    if (!audit) throw new BadRequestException(`Audit ${auditId} not found`);

    const record = (this.prisma as any).chainAttestation?.findUnique
      ? await (this.prisma as any).chainAttestation.findUnique({
          where: { auditId_chainId: { auditId, chainId: adapter.chainId } },
        })
      : null;

    if (!record) {
      throw new BadRequestException(
        `No prepared attestation found for audit ${auditId} on ${adapter.name} (${adapter.chainId}).`,
      );
    }
    if (record.status === 'CONFIRMED' && record.txHash) {
      throw new BadRequestException(
        `Duplicate submission rejected: audit ${auditId} is already confirmed on ${adapter.name} (tx ${record.txHash}).`,
      );
    }
    if (record.status !== 'APPROVED' || !record.signature) {
      throw new BadRequestException(
        `Attestation for audit ${auditId} on ${adapter.name} must be APPROVED by an authorized human reviewer before submission (current status: ${record.status}).`,
      );
    }

    const prepared: PreparedChainAttestation = JSON.parse(record.preparedPayloadJson);

    try {
      const submitted = await adapter.submitSignedAttestation({
        prepared,
        signature: record.signature,
        protocolName: audit.protocolName,
        targetContractFile: audit.contractFileName,
        gitCommit: audit.gitCommit,
        ipfsCid: audit.ipfsCid,
        ipfsMetadataCid: audit.ipfsMetadataCid,
        peerAuditor: audit.peerAuditor?.walletAddress,
      });

      if ((this.prisma as any).chainAttestation?.update) {
        await (this.prisma as any).chainAttestation.update({
          where: { id: record.id },
          data: {
            status: submitted.status,
            txHash: submitted.txHash,
            blockNumber: submitted.blockNumber,
            explorerUrl: submitted.explorerUrl,
            errorReason: null,
          },
        });
      }

      await this.prisma.auditRequest.update({
        where: { id: auditId },
        data: {
          onChainTxHash: submitted.txHash,
          onChainChainId: adapter.chainId,
          attestationStatus: 'MANUALLY_ATTESTED',
          attestationSig: record.signature,
          merkleRoot: prepared.evidenceRoot,
        },
      });

      return submitted;
    } catch (err: any) {
      if ((this.prisma as any).chainAttestation?.update) {
        await (this.prisma as any).chainAttestation.update({
          where: { id: record.id },
          data: {
            status: 'FAILED',
            errorReason: err.message,
          },
        });
      }
      throw new BadRequestException(`Chain attestation submission failed on ${adapter.name}: ${err.message}`);
    }
  }

  /**
   * Directly verify audit attestation on-chain by calling ZyronAttestation.verifyAttestation(auditIdBytes32)
   */
  async verifyOnChain(auditId: string, targetChainId?: number): Promise<any> {
    const chainId = targetChainId || getDefaultAttestationChainId();
    const config = this.chainConfig.getChainConfig(chainId);
    if (!config || !config.attestationAddress) {
      return { isVerified: false, reason: 'Attestation contract not configured for this chain' };
    }

    try {
      const provider = this.chainConfig.getProvider(chainId);
      const contract = this.getContractInstance(config.attestationAddress, ZYRON_ATTESTATION_ABI, provider);
      const auditIdBytes32 = keccak256(toUtf8Bytes(auditId));

      const record = await contract.verifyAttestation(auditIdBytes32);
      return {
        isVerified: Boolean(record.isVerified),
        auditId,
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
        chainId,
        contractAddress: config.attestationAddress,
        explorerUrl: `${config.explorerUrl}/address/${config.attestationAddress}`,
      };
    } catch (err: any) {
      this.logger.warn(`On-chain verification query failed for ${auditId}: ${err.message}`);
      return {
        isVerified: false,
        reason: err.message?.includes('No verified attestation')
          ? 'No verified attestation found on-chain'
          : err.message,
      };
    }
  }
}
