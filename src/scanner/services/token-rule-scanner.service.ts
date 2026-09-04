import { Injectable, Logger } from '@nestjs/common';
import { FindingSeverity } from '../../common/enum';
import { TokenScanResult, TokenAnalysisFinding } from '../token-scanner.service';

@Injectable()
export class TokenRuleScannerService {
  private readonly logger = new Logger(TokenRuleScannerService.name);

  analyzeTokenCode(contractFileName: string, code: string): TokenScanResult {
    const findings: TokenAnalysisFinding[] = [];
    let riskScore = 0;

    if (/transfer[\s\S]*?\*\s*\d+/i.test(code) || (/fee|tax/i.test(code) && /transfer/i.test(code))) {
      const isExtremeTax = /\*\s*([5-9]\d|100)\s*\/\s*100/.test(code);
      riskScore += isExtremeTax ? 40 : 20;

      findings.push({
        title: isExtremeTax ? 'CRITICAL: High Transfer Tax / Potential Sell Honeypot' : 'HIGH: Custom Transfer Fee/Tax Detected',
        severity: isExtremeTax ? FindingSeverity.CRITICAL : FindingSeverity.HIGH,
        cvss: isExtremeTax ? 'CVSS 9.8' : 'CVSS 7.5',
        taxonomy: 'SWC-135 · SWC-107',
        location: `${contractFileName}:transfer`,
        impact: isExtremeTax ? 'USERS CANNOT SELL OR RECEIVE VERY FEW TOKENS ON TRANSFER' : 'UNEXPECTED DEDUCTION OF TOKENS ON EVERY TRANSFER',
        description: 'The contract modifies the transfer amount using custom multipliers or fees.',
        remediatedCode: 'Remove custom transfer fee deductions or cap maximum fee to <= 3%.',
      });
    }

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

    if (/isPaused|paused|function\s+pause\s*\(/i.test(code)) {
      riskScore += 15;
      findings.push({
        title: 'MEDIUM: Admin Pause Control (Transfer Freeze Risk)',
        severity: FindingSeverity.MEDIUM,
        cvss: 'CVSS 5.3',
        taxonomy: 'SWC-106 · CWE-284',
        location: `${contractFileName}:pause`,
        impact: 'ADMIN CAN FREEZE ALL TOKEN TRANSFERS AT WILL',
        description: 'The contract includes pause functionality.',
        remediatedCode: 'Use multi-sig admin keys or timelock for emergency pause actions.',
      });
    }

    if (/blacklist|isBlacklisted|freezeAccount/i.test(code)) {
      riskScore += 20;
      findings.push({
        title: 'HIGH: User Blacklisting / Censorship Capability',
        severity: FindingSeverity.HIGH,
        cvss: 'CVSS 7.1',
        taxonomy: 'CWE-284 · SWC-105',
        location: `${contractFileName}:blacklist`,
        impact: 'TARGETED USER WALLET ASSET FREEZING',
        description: 'The contract allows the owner to blacklist specific addresses.',
      });
    }

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

    const tokenRiskScore = Math.min(100, riskScore);
    const summary = tokenRiskScore === 0
      ? `Clean Token Contract — 0 security risks detected for ${contractFileName}.`
      : `Token Scan Complete — Risk Score ${tokenRiskScore}/100 (${findings.length} issue(s) identified).`;

    return {
      contractFileName,
      tokenRiskScore,
      summary,
      findings,
    };
  }
}
