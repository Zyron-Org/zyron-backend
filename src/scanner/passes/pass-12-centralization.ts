import { ParsedProject, PassFinding, ContractASTSymbol } from '../engine/types';
import { ScannerPass, PassConfig } from './pass-interface';

export class Pass12Centralization implements ScannerPass {
  passNumber = 12;
  name = 'Centralization & Privileged Role Risks';
  description = 'Detects single-key admin rugpull risks, emergency fund sweeping capabilities, and excessive centralization vectors.';
  swcIds = ['SWC-105', 'SWC-106'];
  cweIds = ['CWE-269', 'CWE-284'];
  defaultConfidence = 'HIGH_CONFIDENCE';

  async run(project: ParsedProject, config?: PassConfig): Promise<PassFinding[]> {
    const findings: PassFinding[] = [];

    for (const contract of project.contracts.values()) {
      if (config?.ignoreOpenZeppelin && contract.filePath.includes('node_modules')) continue;

      const privilegedFunctions: string[] = [];

      for (const fn of contract.functions) {
        if (!fn.astNode) continue;

        const isOwnerProtected = fn.modifiers.some((m) =>
          ['onlyowner', 'onlyadmin', 'auth'].includes(m.name.toLowerCase()),
        );

        if (!isOwnerProtected) continue;

        privilegedFunctions.push(fn.name);

        // Check for emergency sweep / drain functions
        if (/emergencywithdraw|sweeptokens|drain|rescue/i.test(fn.name)) {
          findings.push({
            ruleId: 'ZYRON-12-001',
            swcId: 'SWC-105',
            cweId: 'CWE-269',
            title: 'Privileged Fund Sweeping Capability (Single-Key Rugpull Risk)',
            description: `Function ${fn.name} in contract ${contract.name} allows a single owner address to instantly withdraw user deposits or vault tokens without a timelock delay.`,
            severity: 'HIGH',
            confidence: 'HIGH_CONFIDENCE',
            analysisPass: 12,
            filePath: contract.filePath,
            line: fn.astNode.loc?.start?.line || 1,
            codeSnippet: `function ${fn.name}(...) onlyOwner`,
            vulnerableCode: `function emergencyWithdraw() external onlyOwner { token.transfer(msg.sender, balance); }`,
            remediation: 'Place emergency fund sweeping behind an OpenZeppelin TimelockController (minimum 48-hour delay) and Multi-Sig wallet.',
          });
        }
      }

      // Check if contract accumulates excessive single-owner privileges (> 4 privileged functions)
      if (privilegedFunctions.length >= 4) {
        findings.push({
          ruleId: 'ZYRON-12-002',
          swcId: 'SWC-105',
          cweId: 'CWE-269',
          title: 'High Centralization Risk: Concentrated Administrative Control',
          description: `Contract ${contract.name} defines ${privilegedFunctions.length} admin-only functions (${privilegedFunctions.slice(0, 4).join(', ')}, ...). Single private key compromise leads to complete contract takeover.`,
          severity: 'MEDIUM',
          confidence: 'HIGH_CONFIDENCE',
          analysisPass: 12,
          filePath: contract.filePath,
          line: 1,
          codeSnippet: `Contract ${contract.name} with ${privilegedFunctions.length} onlyOwner functions`,
          vulnerableCode: `multiple onlyOwner administrative endpoints`,
          remediation: 'Migrate single EOA ownership to a Gnosis Safe Multi-Sig or Decentralized Governance DAO with Timelock.',
        });
      }
    }

    return findings;
  }
}
