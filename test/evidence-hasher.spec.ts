import { describe, it, expect } from 'vitest';
import { EvidenceHasherService } from '../src/blockchain/services/evidence-hasher.service';
import { AttestationService } from '../src/blockchain/services/attestation.service';

describe('EvidenceHasherService – Deterministic Cryptographic Evidence (TDD)', () => {
  const hasher = new EvidenceHasherService();

  it('produces identical canonical JSON and SHA-256 evidence hash for identical objects with different key orders', () => {
    const payloadA = {
      auditId: 'ZYR-9481',
      protocolName: 'Monad Vault Core',
      contractFileName: 'VaultCore.sol',
      merkleRoot: '0x111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000',
      sloc: 450,
      issuer: 'ZYRON_AI_AUDITOR_001',
      findingsSummary: {
        critical: 0,
        high: 0,
        medium: 1,
        resolved: 1,
      },
    };

    const payloadB = {
      findingsSummary: {
        resolved: 1,
        medium: 1,
        high: 0,
        critical: 0,
      },
      issuer: 'ZYRON_AI_AUDITOR_001',
      sloc: 450,
      merkleRoot: '0x111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000',
      contractFileName: 'VaultCore.sol',
      protocolName: 'Monad Vault Core',
      auditId: 'ZYR-9481',
    };

    const canonicalA = hasher.canonicalize(payloadA);
    const canonicalB = hasher.canonicalize(payloadB);

    expect(canonicalA).toBe(canonicalB);

    const hashA = hasher.hashEvidence(payloadA);
    const hashB = hasher.hashEvidence(payloadB);

    expect(hashA).toBe(hashB);
    expect(hashA).toMatch(/^0x[a-f0-9]{64}$/);
  });

  it('produces different evidence hashes when any field or nested value changes', () => {
    const base = {
      auditId: 'ZYR-9481',
      protocolName: 'Monad Vault Core',
      merkleRoot: '0x111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000',
      findingsCount: 3,
    };

    const hashBase = hasher.hashEvidence(base);

    const mutatedAuditId = { ...base, auditId: 'ZYR-9482' };
    expect(hasher.hashEvidence(mutatedAuditId)).not.toBe(hashBase);

    const mutatedCount = { ...base, findingsCount: 4 };
    expect(hasher.hashEvidence(mutatedCount)).not.toBe(hashBase);

    const mutatedMerkle = {
      ...base,
      merkleRoot: '0x222222223333444455556666777788889999aaaabbbbccccddddeeeeffff0000',
    };
    expect(hasher.hashEvidence(mutatedMerkle)).not.toBe(hashBase);
  });

  it('correctly builds evidence for audit completion with Merkle root consistency', () => {
    const findings = [
      { displayId: 'ZYR-9481-001', severity: 'HIGH' },
      { displayId: 'ZYR-9481-002', severity: 'LOW' },
    ];

    // Reuse existing Merkle root logic from AttestationService
    const mockPrisma: any = {};
    const mockChainConfig: any = {};
    const attestationService = new AttestationService(mockPrisma, mockChainConfig);
    const merkleRoot = attestationService.computeFindingsMerkleRoot(findings);

    const auditEvidence = hasher.buildAuditClaimEvidence({
      auditId: 'ZYR-9481',
      protocolName: 'Monad Vault Core',
      contractFileName: 'VaultCore.sol',
      gitCommit: '9b821a0f',
      bytecodeHash: '0x3333444455556666777788889999000011112222333344445555666677778888',
      merkleRoot,
      sloc: 320,
      aiAuditorId: 'did:zyron:ai-auditor:001',
    });

    expect(auditEvidence.merkleRoot).toBe(merkleRoot);
    expect(auditEvidence.evidenceHash).toMatch(/^0x[a-f0-9]{64}$/);

    // Re-computing hash from the evidence object matches evidenceHash
    const recomputed = hasher.hashEvidence(auditEvidence.canonicalPayload);
    expect(recomputed).toBe(auditEvidence.evidenceHash);
  });
});
