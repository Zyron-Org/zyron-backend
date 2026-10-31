import { Injectable } from '@nestjs/common';
import { createHash } from 'crypto';

export const EVIDENCE_SCHEMA_V1 = 'zyron.evidence/v1';
export const DEFAULT_VERIFIER_VERSION = 'zyron-verifier/2.0.0';

export type VerificationStatusV1 = 'PROVEN_EXPLOIT' | 'PROVEN_FALSE_POSITIVE' | 'INCONCLUSIVE';

export interface SandboxRunSummaryV1 {
  exitCode: number;
  passed: boolean;
  stdoutHash: string;
  gasUsed?: number;
}

export interface FindingEvidenceV1Input {
  auditId: string;
  findingId: string;
  displayId?: string;
  repository?: string | null;
  gitCommit?: string | null;
  sourceHashes: Record<string, string>;
  targetContractFile: string;
  targetContractAddress?: string | null;
  chainId: number;
  bytecodeHash?: string | null;
  ruleId?: string | null;
  severity: string;
  taxonomy?: string | null;
  testFile?: string | null;
  testFunction?: string | null;
  testArtifactHash?: string | null;
  claimedVerdict?: string | null;
  finalStatus: VerificationStatusV1;
  runs?: SandboxRunSummaryV1[];
  rejectionReasons?: string[];
  verifierVersion?: string;
  provider?: string;
  model?: string;
  reportRef?: {
    ipfsCid?: string | null;
    reportUrl?: string | null;
  };
}

export interface FindingEvidenceV1Record {
  schemaVersion: typeof EVIDENCE_SCHEMA_V1;
  payload: Record<string, any>;
  canonicalJson: string;
  evidenceHash: string;
}

@Injectable()
export class EvidenceHasherService {
  /**
   * Deterministically serialize any JavaScript object to a canonical JSON string.
   * Object keys are recursively sorted alphabetically so identical structures always yield identical strings.
   */
  canonicalize(value: any): string {
    if (value === undefined) {
      return 'null';
    }
    if (value === null || typeof value !== 'object') {
      return JSON.stringify(value);
    }

    if (Array.isArray(value)) {
      return `[${value.map((item) => this.canonicalize(item)).join(',')}]`;
    }

    const sortedKeys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort();
    const pairs = sortedKeys.map((key) => {
      const val = value[key];
      return `${JSON.stringify(key)}:${this.canonicalize(val)}`;
    });

    return `{${pairs.join(',')}}`;
  }

  /**
   * Compute deterministic SHA-256 evidence hash from canonical payload.
   * Returns a 0x-prefixed 32-byte hex string.
   */
  hashEvidence(payload: any): string {
    const canonical = typeof payload === 'string' ? payload : this.canonicalize(payload);
    const digest = createHash('sha256').update(canonical, 'utf8').digest('hex');
    return `0x${digest}`;
  }

  /**
   * Verify that a canonical JSON or object payload matches an expected 0x-prefixed SHA-256 digest.
   */
  verifyEvidenceDigest(payloadOrJson: any, expectedHash: string): boolean {
    if (!expectedHash || typeof expectedHash !== 'string') return false;
    const obj = typeof payloadOrJson === 'string' ? JSON.parse(payloadOrJson) : payloadOrJson;
    const computed = this.hashEvidence(obj);
    return computed.toLowerCase() === expectedHash.trim().toLowerCase();
  }

  /**
   * Normalize prover status string to strict 3-state verification classification.
   */
  normalizeVerificationStatus(raw?: string | null): VerificationStatusV1 {
    const upper = (raw || '').trim().toUpperCase();
    if (upper === 'PROVEN_EXPLOIT') return 'PROVEN_EXPLOIT';
    if (upper === 'PROVEN_FALSE_POSITIVE') return 'PROVEN_FALSE_POSITIVE';
    return 'INCONCLUSIVE';
  }

  /**
   * Build a canonical, versioned (`zyron.evidence/v1`) cryptographic evidence record for a finding.
   */
  buildFindingEvidenceV1(input: FindingEvidenceV1Input): FindingEvidenceV1Record {
    const normalizedSources: Record<string, string> = {};
    for (const [k, v] of Object.entries(input.sourceHashes || {})) {
      normalizedSources[k] = v.startsWith('0x') ? v.toLowerCase() : `0x${v.toLowerCase()}`;
    }

    const payload: Record<string, any> = {
      schemaVersion: EVIDENCE_SCHEMA_V1,
      auditId: input.auditId,
      findingId: input.findingId,
      displayId: input.displayId || input.findingId,
      source: {
        repository: input.repository || '',
        gitCommit: input.gitCommit || '',
        sourceHashes: normalizedSources,
      },
      target: {
        chainId: Number(input.chainId),
        contractFile: input.targetContractFile,
        contractAddress: (input.targetContractAddress || '').toLowerCase(),
        bytecodeHash: (input.bytecodeHash || '').toLowerCase(),
      },
      scanner: {
        ruleId: input.ruleId || 'UNSPECIFIED',
        severity: input.severity,
        taxonomy: input.taxonomy || '',
      },
      prover: {
        model: {
          provider: input.provider || 'meta',
          model: input.model || 'muse-spark-1.3',
        },
        verifierVersion: input.verifierVersion || DEFAULT_VERIFIER_VERSION,
        testFile: input.testFile || '',
        testFunction: input.testFunction || '',
        testArtifactHash: (input.testArtifactHash || '').toLowerCase(),
        claimedVerdict: input.claimedVerdict || input.finalStatus,
        finalStatus: this.normalizeVerificationStatus(input.finalStatus),
        runs: (input.runs || []).map((r) => ({
          exitCode: Number(r.exitCode),
          passed: Boolean(r.passed),
          stdoutHash: r.stdoutHash,
          gasUsed: r.gasUsed ?? null,
        })),
        rejectionReasons: input.rejectionReasons || [],
      },
      reportRef: {
        ipfsCid: input.reportRef?.ipfsCid || '',
        reportUrl: input.reportRef?.reportUrl || `/api/v1/audits/${input.auditId}/report.pdf`,
      },
    };

    const canonicalJson = this.canonicalize(payload);
    const evidenceHash = this.hashEvidence(canonicalJson);

    return {
      schemaVersion: EVIDENCE_SCHEMA_V1,
      payload,
      canonicalJson,
      evidenceHash,
    };
  }

  /**
   * Compute a deterministic binary SHA-256 Merkle root from a list of finding evidence hashes.
   * Leaves are normalized to lowercase hex without 0x and sorted lexicographically before tree construction.
   */
  computeEvidenceMerkleRoot(evidenceHashes: string[]): string {
    if (!evidenceHashes || evidenceHashes.length === 0) {
      return '0x' + '0'.repeat(64);
    }

    let leaves = evidenceHashes
      .map((h) => h.trim().toLowerCase().replace(/^0x/, ''))
      .filter((h) => /^[0-9a-f]{64}$/.test(h))
      .sort();

    if (leaves.length === 0) {
      return '0x' + '0'.repeat(64);
    }

    while (leaves.length > 1) {
      const next: string[] = [];
      for (let i = 0; i < leaves.length; i += 2) {
        const left = leaves[i];
        const right = i + 1 < leaves.length ? leaves[i + 1] : left;
        next.push(createHash('sha256').update(left + right, 'utf8').digest('hex'));
      }
      leaves = next;
    }

    return `0x${leaves[0]}`;
  }

  /**
   * Build structured, canonical claim evidence for smart contract audit attestations (legacy + passport compatibility).
   */
  buildAuditClaimEvidence(params: {
    auditId: string;
    protocolName: string;
    contractFileName: string;
    gitCommit?: string;
    bytecodeHash?: string;
    merkleRoot: string;
    sloc: number;
    aiAuditorId: string;
    extraMetadata?: Record<string, any>;
  }): {
    auditId: string;
    protocolName: string;
    contractFileName: string;
    gitCommit: string;
    bytecodeHash: string;
    merkleRoot: string;
    sloc: number;
    aiAuditorId: string;
    evidenceHash: string;
    canonicalPayload: Record<string, any>;
  } {
    const canonicalPayload: Record<string, any> = {
      auditId: params.auditId,
      protocolName: params.protocolName,
      contractFileName: params.contractFileName,
      gitCommit: params.gitCommit || '',
      bytecodeHash: params.bytecodeHash || '',
      merkleRoot: params.merkleRoot,
      sloc: params.sloc,
      aiAuditorId: params.aiAuditorId,
      ...(params.extraMetadata || {}),
    };

    const evidenceHash = this.hashEvidence(canonicalPayload);

    return {
      auditId: params.auditId,
      protocolName: params.protocolName,
      contractFileName: params.contractFileName,
      gitCommit: params.gitCommit || '',
      bytecodeHash: params.bytecodeHash || '',
      merkleRoot: params.merkleRoot,
      sloc: params.sloc,
      aiAuditorId: params.aiAuditorId,
      evidenceHash,
      canonicalPayload,
    };
  }
}
