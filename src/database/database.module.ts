import { Injectable, OnModuleInit, OnModuleDestroy, Global, Module, Logger } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(PrismaService.name);

  async onModuleInit() {
    await this.$connect();
    await this.ensureSchemaUpToDate();
  }

  /**
   * Idempotently ensures new columns and tables (Privy DID, TrustPassport, TrustClaim,
   * ProverEvidence, ChainAttestation) exist in SQLite even if `prisma db push` was skipped during deploy.
   */
  private async ensureSchemaUpToDate() {
    const statements = [
      `ALTER TABLE "User" ADD COLUMN "privyDid" TEXT`,
      `CREATE UNIQUE INDEX IF NOT EXISTS "User_privyDid_key" ON "User"("privyDid")`,
      `ALTER TABLE "AuditRequest" ADD COLUMN "onChainChainId" INTEGER`,
      `ALTER TABLE "Payment" ADD COLUMN "chainId" INTEGER`,
      `CREATE TABLE IF NOT EXISTS "TrustPassport" (
        "id" TEXT NOT NULL PRIMARY KEY,
        "userId" TEXT NOT NULL,
        "handle" TEXT,
        "title" TEXT DEFAULT 'Zyron Trust Passport',
        "bio" TEXT,
        "reputationScore" INTEGER NOT NULL DEFAULT 100,
        "isVerified" BOOLEAN NOT NULL DEFAULT false,
        "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updatedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT "TrustPassport_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
      )`,
      `CREATE UNIQUE INDEX IF NOT EXISTS "TrustPassport_userId_key" ON "TrustPassport"("userId")`,
      `CREATE UNIQUE INDEX IF NOT EXISTS "TrustPassport_handle_key" ON "TrustPassport"("handle")`,
      `CREATE INDEX IF NOT EXISTS "TrustPassport_userId_idx" ON "TrustPassport"("userId")`,
      `CREATE TABLE IF NOT EXISTS "TrustClaim" (
        "id" TEXT NOT NULL PRIMARY KEY,
        "passportId" TEXT NOT NULL,
        "claimType" TEXT NOT NULL,
        "subject" TEXT NOT NULL,
        "issuer" TEXT NOT NULL,
        "evidence" TEXT NOT NULL,
        "evidenceHash" TEXT NOT NULL,
        "status" TEXT NOT NULL DEFAULT 'VERIFIED',
        "onChainTxHash" TEXT,
        "onChainChainId" INTEGER DEFAULT 10143,
        "onChainTokenId" INTEGER,
        "auditId" TEXT,
        "issuedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "revokedAt" DATETIME,
        CONSTRAINT "TrustClaim_passportId_fkey" FOREIGN KEY ("passportId") REFERENCES "TrustPassport" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
        CONSTRAINT "TrustClaim_auditId_fkey" FOREIGN KEY ("auditId") REFERENCES "AuditRequest" ("id") ON DELETE SET NULL ON UPDATE CASCADE
      )`,
      `CREATE INDEX IF NOT EXISTS "TrustClaim_passportId_idx" ON "TrustClaim"("passportId")`,
      `CREATE INDEX IF NOT EXISTS "TrustClaim_claimType_idx" ON "TrustClaim"("claimType")`,
      `CREATE INDEX IF NOT EXISTS "TrustClaim_evidenceHash_idx" ON "TrustClaim"("evidenceHash")`,
      `CREATE INDEX IF NOT EXISTS "TrustClaim_auditId_idx" ON "TrustClaim"("auditId")`,
      `CREATE TABLE IF NOT EXISTS "ProverEvidence" (
        "id" TEXT NOT NULL PRIMARY KEY,
        "auditId" TEXT NOT NULL,
        "findingId" TEXT NOT NULL,
        "findingDisplayId" TEXT,
        "schemaVersion" TEXT NOT NULL DEFAULT 'zyron.evidence/v1',
        "verifierVersion" TEXT NOT NULL DEFAULT 'zyron-verifier/2.0.0',
        "finalStatus" TEXT NOT NULL,
        "claimedVerdict" TEXT,
        "testFile" TEXT,
        "testFunction" TEXT,
        "testArtifactHash" TEXT,
        "sourceHashesJson" TEXT NOT NULL,
        "provider" TEXT NOT NULL DEFAULT 'meta',
        "model" TEXT NOT NULL DEFAULT 'muse-spark-1.3',
        "runsJson" TEXT NOT NULL,
        "investigationJson" TEXT,
        "canonicalJson" TEXT NOT NULL,
        "evidenceHash" TEXT NOT NULL,
        "rejectionReasonsJson" TEXT,
        "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT "ProverEvidence_auditId_fkey" FOREIGN KEY ("auditId") REFERENCES "AuditRequest" ("id") ON DELETE CASCADE ON UPDATE CASCADE
      )`,
      `CREATE UNIQUE INDEX IF NOT EXISTS "ProverEvidence_auditId_findingId_key" ON "ProverEvidence"("auditId", "findingId")`,
      `CREATE INDEX IF NOT EXISTS "ProverEvidence_auditId_idx" ON "ProverEvidence"("auditId")`,
      `CREATE INDEX IF NOT EXISTS "ProverEvidence_evidenceHash_idx" ON "ProverEvidence"("evidenceHash")`,
      `CREATE TABLE IF NOT EXISTS "ChainAttestation" (
        "id" TEXT NOT NULL PRIMARY KEY,
        "auditId" TEXT NOT NULL,
        "chainId" INTEGER NOT NULL,
        "chainName" TEXT NOT NULL,
        "contractIdentity" TEXT NOT NULL,
        "targetContractAddress" TEXT,
        "registryAddress" TEXT NOT NULL,
        "bytecodeHash" TEXT NOT NULL,
        "evidenceRoot" TEXT NOT NULL,
        "merkleRoot" TEXT NOT NULL,
        "repoTreeHash" TEXT NOT NULL,
        "status" TEXT NOT NULL DEFAULT 'PREPARED',
        "preparedPayloadJson" TEXT NOT NULL,
        "preparedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "signerAddress" TEXT,
        "signature" TEXT,
        "approvedAt" DATETIME,
        "txHash" TEXT,
        "blockNumber" INTEGER,
        "explorerUrl" TEXT,
        "errorReason" TEXT,
        "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updatedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT "ChainAttestation_auditId_fkey" FOREIGN KEY ("auditId") REFERENCES "AuditRequest" ("id") ON DELETE CASCADE ON UPDATE CASCADE
      )`,
      `CREATE UNIQUE INDEX IF NOT EXISTS "ChainAttestation_auditId_chainId_key" ON "ChainAttestation"("auditId", "chainId")`,
      `CREATE INDEX IF NOT EXISTS "ChainAttestation_chainId_contractIdentity_idx" ON "ChainAttestation"("chainId", "contractIdentity")`,
      `CREATE INDEX IF NOT EXISTS "ChainAttestation_evidenceRoot_idx" ON "ChainAttestation"("evidenceRoot")`,
    ];

    for (const sql of statements) {
      try {
        await this.$executeRawUnsafe(sql);
      } catch {
        // Ignore duplicate column or existing table/index errors
      }
    }
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
}

@Global()
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class DatabaseModule {}
