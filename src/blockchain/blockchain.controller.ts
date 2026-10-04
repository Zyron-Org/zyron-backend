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

  @Get('attestation/:auditId/onchain')
  @Public()
  @ApiOperation({ summary: 'Direct live on-chain lookup for verified audit attestation record in ZyronAttestation contract' })
  async verifyOnChain(
    @Param('auditId') auditId: string,
    @Query('chainId') chainId?: number,
  ) {
    return this.blockchainService.verifyOnChain(auditId, chainId ? Number(chainId) : undefined);
  }
}
