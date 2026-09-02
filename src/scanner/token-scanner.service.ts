import { Injectable, Logger } from '@nestjs/common';
import { FindingSeverity } from '../common/enum';

export interface TokenAnalysisFinding {
  title: string;
  severity: FindingSeverity;
  cvss: string;
  taxonomy: string;
  location: string;
  impact: string;
  description: string;
  vulnerableCode?: string;
  remediatedCode?: string;
}

export interface TokenScanResult {
  contractFileName: string;
  tokenRiskScore: number; // 0 (safest) - 100 (critical risk)
  summary: string;
  findings: TokenAnalysisFinding[];
}

@Injectable()
export class TokenScannerService {
  private readonly logger = new Logger(TokenScannerService.name);

  /**
   * Static rule-based token security analysis
   * Analyzes token contract code for honeypot taxes, admin minting privileges,
   * pause controls, blacklist censorship, and reentrancy vectors.
   */
  analyzeTokenCode(contractFileName: string, code: string): TokenScanResult {
    const findings: TokenAnalysisFinding[] = [];
    let riskScore = 0;

    // 1. Transfer Tax / Honeypot Detection
    if (/transfer[\s\S]*?\*\s*\d+/i.test(code) || /fee|tax/i.test(code) && /transfer/i.test(code)) {
      const isExtremeTax = /\*\s*([5-9]\d|100)\s*\/\s*100/.test(code);
      riskScore += isExtremeTax ? 40 : 20;

      findings.push({
        title: isExtremeTax ? 'CRITICAL: High Transfer Tax / Potential Sell Honeypot' : 'HIGH: Custom Transfer Fee/Tax Detected',
        severity: isExtremeTax ? FindingSeverity.CRITICAL : FindingSeverity.HIGH,
        cvss: isExtremeTax ? 'CVSS 9.8' : 'CVSS 7.5',
        taxonomy: 'SWC-135 · SWC-107',
        location: `${contractFileName}:transfer`,
        impact: isExtremeTax ? 'USERS CANNOT SELL OR RECEIVE VERY FEW TOKENS ON TRANSFER' : 'UNEXPECTED DEDUCTION OF TOKENS ON EVERY TRANSFER',
        description: 'The contract modifies the transfer amount using custom multipliers or fees. Extreme taxes can prevent users from selling or liquidating their tokens.',
        remediatedCode: 'Remove custom transfer fee deductions or cap maximum fee to <= 3%.',
      });
    }

    // 2. Unlimited Minting Privileges
    if (/function\s+mint\s*\(/i.test(code)) {
      const hasCap = /maxSupply|cap|MAX_SUPPLY/i.test(code);
      if (!hasCap) {
        riskScore += 25;
        findings.push({
          title: 'HIGH: Uncapped Owner Minting Privilege',
          severity: FindingSeverity.HIGH,
          cvss: 'CVSS 8.2',
          taxonomy: 'SWC-105 · CWE-269',
          location: `${contractFileName}:mint`,
          impact: 'UNLIMITED TOKEN INFLATION / DILUTION OF HOLDER VALUE',
          description: 'The owner or privileged admin can mint an arbitrary number of tokens without a hard maximum supply cap.',
          remediatedCode: 'Enforce a MAX_SUPPLY immutable constant in the mint function.',
        });
      }
    }

    // 3. Pause Control (Centralization Risk)
    if (/isPaused|paused|function\s+pause\s*\(/i.test(code)) {
      riskScore += 15;
      findings.push({
        title: 'MEDIUM: Admin Pause Control (Transfer Freeze Risk)',
        severity: FindingSeverity.MEDIUM,
        cvss: 'CVSS 5.3',
        taxonomy: 'SWC-106 · CWE-284',
        location: `${contractFileName}:pause`,
        impact: 'ADMIN CAN FREEZE ALL TOKEN TRANSFERS AT WILL',
        description: 'The contract includes pause functionality. An admin key compromise allows an attacker to permanently halt all protocol transactions.',
        remediatedCode: 'Use multi-sig admin keys or timelock for emergency pause actions.',
      });
    }

    // 4. Blacklist / Censorship Privilege
    if (/blacklist|isBlacklisted|freezeAccount/i.test(code)) {
      riskScore += 20;
      findings.push({
        title: 'HIGH: User Blacklisting / Censorship Capability',
        severity: FindingSeverity.HIGH,
        cvss: 'CVSS 7.1',
        taxonomy: 'CWE-284 · SWC-105',
        location: `${contractFileName}:blacklist`,
        impact: 'TARGETED USER WALLET ASSET FREEZING',
        description: 'The contract allows the owner to blacklist specific addresses, preventing them from transferring or withdrawing assets.',
      });
    }

    // 5. Raw External Calls / Reentrancy
    if (/\.call\{value:/i.test(code) && !/nonReentrant|ReentrancyGuard/i.test(code)) {
      riskScore += 30;
      findings.push({
        title: 'CRITICAL: Reentrancy Vector via Raw ETH Call',
        severity: FindingSeverity.CRITICAL,
        cvss: 'CVSS 9.1',
        taxonomy: 'SWC-107 · CWE-841',
        location: `${contractFileName}:call`,
        impact: 'COMPLETE PROTOCOL DRAIN VIA REENTRANT RECURSIVE CALL',
        description: 'The contract performs low-level `.call{value: ...}` transfers without OpenZeppelin ReentrancyGuard protection.',
        remediatedCode: 'Inherit OpenZeppelin ReentrancyGuard and apply nonReentrant modifier.',
      });
    }

    // Cap score at 100
    tokenRiskScore: riskScore = Math.min(100, riskScore);

    const summary = riskScore === 0
      ? `Clean Token Contract — 0 security risks detected for ${contractFileName}.`
      : `Token Scan Complete — Risk Score ${riskScore}/100 (${findings.length} issue(s) identified).`;

    return {
      contractFileName,
      tokenRiskScore: riskScore,
      summary,
      findings,
    };
  }
}
