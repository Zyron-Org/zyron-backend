import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { ethers, keccak256, toUtf8Bytes } from 'ethers';
import { PrismaService } from '../../database/database.module';
import { ChainConfigService } from './chain-config.service';

const ZYRON_ATTESTATION_ABI = [
  'function publishAttestation(bytes32 auditId, bytes32 bytecodeHash, bytes32 reportHash, address leadAuditor, address peerAuditor, uint256 sloc, string calldata contractFileName) external',
  'function publishAttestationWithSignature(bytes32 auditId, bytes32 merkleRoot, bytes32 bytecodeHash, bytes32 sourceHash, address leadAuditor, address peerAuditor, uint256 sloc, string calldata contractFileName, uint8 status, uint256 timestamp, bytes calldata signature) external',
  'function verifyAttestation(bytes32 auditId) external view returns (tuple(bytes32 auditId, bytes32 merkleRoot, bytes32 bytecodeHash, bytes32 sourceHash, bytes32 reportHash, address leadAuditor, address peerAuditor, uint256 sloc, uint256 timestamp, string contractFileName, uint8 status, bool isVerified))',
];

@Injectable()
export class AttestationSubmitterService {
  private readonly logger = new Logger(AttestationSubmitterService.name);

  constructor(
    private prisma: PrismaService,
    private chainConfig: ChainConfigService,
  ) {}

  /**
   * Submit automated on-chain attestation via operator wallet.
   */
  async submitAutomatedAttestation(auditId: string, targetChainId?: number): Promise<{ txHash: string; chainId: number }> {
    const audit = await this.prisma.auditRequest.findUnique({
      where: { id: auditId },
      include: { leadAuditor: true, peerAuditor: true },
    });

    if (!audit) throw new BadRequestException(`Audit ${auditId} not found`);

    const chainId = targetChainId || audit.onChainChainId || Number(process.env.DEFAULT_ATTESTATION_CHAIN_ID || 421614);
    const config = this.chainConfig.getChainConfig(chainId);
    if (!config) throw new BadRequestException(`Chain ID ${chainId} not supported`);

    const operatorPrivateKey = process.env.OPERATOR_PRIVATE_KEY;
    if (!operatorPrivateKey || operatorPrivateKey.trim() === '') {
      this.logger.warn(`OPERATOR_PRIVATE_KEY not set. Generating dev mock on-chain tx for audit ${auditId}`);
      const mockTxHash = `0x${keccak256(toUtf8Bytes(auditId + Date.now().toString())).substring(2, 66)}`;
      await this.prisma.auditRequest.update({
        where: { id: auditId },
        data: {
          onChainTxHash: mockTxHash,
          onChainChainId: chainId,
          attestationStatus: 'AUTOMATED_ONLY',
        },
      });
      return { txHash: mockTxHash, chainId };
    }

    if (!config.attestationAddress) {
      throw new BadRequestException(`Attestation contract address not configured for chain ${chainId}`);
    }

    const provider = this.chainConfig.getProvider(chainId);
    const wallet = new ethers.Wallet(operatorPrivateKey, provider);
    const contract = new ethers.Contract(config.attestationAddress, ZYRON_ATTESTATION_ABI, wallet);

    const auditIdBytes32 = keccak256(toUtf8Bytes(audit.id));
    const bytecodeHashBytes32 = audit.bytecodeHash || `0x${'0'.repeat(64)}`;
    const reportHashBytes32 = audit.ipfsCid
      ? keccak256(toUtf8Bytes(audit.ipfsCid))
      : audit.merkleRoot || `0x${'0'.repeat(64)}`;
    const leadAuditorAddr = audit.leadAuditor?.walletAddress || wallet.address;
    const peerAuditorAddr = audit.peerAuditor?.walletAddress || ethers.ZeroAddress;

    this.logger.log(`Broadcasting publishAttestation to chain ${chainId} for ${auditId}...`);
    const tx = await contract.publishAttestation(
      auditIdBytes32,
      bytecodeHashBytes32,
      reportHashBytes32,
      leadAuditorAddr,
      peerAuditorAddr,
      audit.sloc || 100,
      audit.contractFileName || 'Contract.sol',
    );

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
  }
}
