import { Controller, Get, Param, Query } from '@nestjs/common';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { BlockchainService } from './blockchain.service';
import { Public } from '../common/decorators';

@ApiTags('Blockchain & Attestation Registry')
@Controller('blockchain')
export class BlockchainController {
  constructor(private readonly blockchainService: BlockchainService) {}

  @Get('chains')
  @Public()
  @ApiOperation({ summary: 'Get list of supported blockchain networks, RPCs, and deployed contract addresses' })
  getSupportedChains() {
    return this.blockchainService.getSupportedChains();
  }

  @Get('chains/matrix')
  @Public()
  @ApiOperation({ summary: 'Get multichain attestation adapter matrix (Monad Testnet + Base Sepolia)' })
  getSupportedChainMatrix() {
    return this.blockchainService.getSupportedChainMatrix();
  }

  @Get('attestation/:auditId/onchain')
  @Public()
  @ApiOperation({ summary: 'Direct live on-chain lookup for verified audit attestation record in ZyronAttestation contract' })
  async verifyOnChain(
    @Param('auditId') auditId: string,
    @Query('chainId') chainId?: number,
  ) {
    return this.blockchainService.verifyOnChain(auditId, chainId ? Number(chainId) : undefined);
  }

  @Get('verify/:chainId/:auditId')
  @Public()
  @ApiOperation({ summary: 'Verify audit attestation on a specific EVM chain via its ChainAdapter' })
  async verifyByChainAndAudit(
    @Param('chainId') chainId: string,
    @Param('auditId') auditId: string,
  ) {
    return this.blockchainService.verifyOnChain(auditId, Number(chainId));
  }
}
