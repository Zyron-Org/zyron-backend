import { ParsedProject, PassFinding, ContractASTSymbol, ASTFunctionSymbol } from '../engine/types';
import { ScannerPass, PassConfig } from './pass-interface';

export class Pass10TokenRisks implements ScannerPass {
  passNumber = 10;
  name = 'Tokenomics & Honeypot Risk Patterns';
  description = 'Detects un-capped transfer fees, owner blacklisting controls, un-capped minting, and fee honeypot vectors.';
  swcIds = ['SWC-105', 'SWC-101'];
  cweIds = ['CWE-284', 'CWE-682', 'CWE-400'];
  defaultConfidence = 'HIGH_CONFIDENCE';

  async run(project: ParsedProject, config?: PassConfig): Promise<PassFinding[]> {
    const findings: PassFinding[] = [];

    for (const contract of project.contracts.values()) {
      if (config?.ignoreOpenZeppelin && contract.filePath.includes('node_modules')) continue;

      this.checkUncappedFeeSetters(contract, findings);
      this.checkBlacklistMechanism(contract, findings);

      for (const fn of contract.functions) {
        if (!fn.astNode) continue;
        this.checkUncappedMinting(contract, fn, findings);
      }
    }

    return findings;
  }

  private checkUncappedFeeSetters(contract: ContractASTSymbol, findings: PassFinding[]): void {
    for (const fn of contract.functions) {
      if (!fn.astNode) continue;
      const fnName = fn.name || 'unnamed';

      const isFeeSetter = /set(tax|fee|buyfee|sellfee|transferfee)/i.test(fnName);
      if (!isFeeSetter) continue;

      const astBody = (fn.astNode as any).body;
      const hasCapCheck =
        astBody &&
        (JSON.stringify(astBody).includes('MAX_FEE') ||
          JSON.stringify(astBody).includes('MAX_TAX') ||
          JSON.stringify(astBody).includes('require('));

      if (!hasCapCheck) {
        findings.push({
          ruleId: 'ZYRON-10-001',
          swcId: 'SWC-105',
          cweId: 'CWE-284',
          title: 'Uncapped Transfer Fee Setter (Honeypot Risk)',
          description: `Function ${fnName} in contract ${contract.name} allows owner/admin to change transfer tax/fees without a hardcoded maximum ceiling. Owner can raise fees to 100%, blocking sell orders (honeypot).`,
          severity: 'CRITICAL',
          confidence: 'HIGH_CONFIDENCE',
          analysisPass: 10,
          filePath: contract.filePath,
          line: fn.astNode.loc?.start?.line || 1,
          codeSnippet: `function ${fnName}(...)`,
          vulnerableCode: `function setFee(uint256 _fee) external onlyOwner { fee = _fee; }`,
          remediation: 'Enforce a hardcoded immutable fee ceiling (e.g., require(_fee <= MAX_FEE, "Fee too high") where MAX_FEE <= 1000 [10%]).',
        });
      }
    }
  }

  private checkBlacklistMechanism(contract: ContractASTSymbol, findings: PassFinding[]): void {
    const hasBlacklistMap = contract.stateVariables.some(
      (v) => /blacklist|isblacklisted|isbot|frozen/i.test(v.name),
    );

    if (hasBlacklistMap) {
      for (const fn of contract.functions) {
        const fnName = fn.name || 'unnamed';
        if (/setblacklist|addblacklist|blacklistaddress|freeze/i.test(fnName)) {
          findings.push({
            ruleId: 'ZYRON-10-002',
            swcId: 'SWC-105',
            cweId: 'CWE-284',
            title: 'Owner Blacklist Control (Arbitrary Account Freezing)',
            description: `Contract ${contract.name} contains function ${fnName} allowing privileged account to blacklist/freeze wallet addresses, preventing funds transfer.`,
            severity: 'HIGH',
            confidence: 'HIGH_CONFIDENCE',
            analysisPass: 10,
            filePath: contract.filePath,
            line: fn.astNode?.loc?.start?.line || 1,
            codeSnippet: `function ${fnName}(...)`,
            vulnerableCode: `mapping(address => bool) public isBlacklisted;`,
            remediation: 'Remove arbitrary blacklisting capability, or restrict it to timelock governance / multi-sig for compliance.',
          });
        }
      }
    }
  }

  private checkUncappedMinting(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    const fnName = fn.name || 'unnamed';
    const isMintFn = /^mint$/i.test(fnName) || /_mint$/i.test(fnName);
    if (!isMintFn) return;

    const bodyStr = JSON.stringify((fn.astNode as any)?.body || {});
    const hasSupplyCap =
      bodyStr.includes('MAX_SUPPLY') || bodyStr.includes('maxSupply') || bodyStr.includes('totalSupply() +');

    const modifiers = fn.modifiers || [];
    const hasAuth = modifiers.some((m) =>
      ['onlyowner', 'onlyminter', 'onlyrole'].includes((m.name || '').toLowerCase()),
    );

    if (hasAuth && !hasSupplyCap) {
      findings.push({
        ruleId: 'ZYRON-10-003',
        swcId: 'SWC-101',
        cweId: 'CWE-400',
        title: 'Uncapped Minting Function (Infinite Token Dilution)',
        description: `Mint function ${fnName} in contract ${contract.name} does not enforce a hardcoded maximum supply limit (MAX_SUPPLY). Privileged minter can arbitrarily dilute supply.`,
        severity: 'HIGH',
        confidence: 'HIGH_CONFIDENCE',
        analysisPass: 10,
        filePath: contract.filePath,
        line: fn.astNode.loc?.start?.line || 1,
        codeSnippet: `function ${fnName}(...)`,
        vulnerableCode: `function mint(address to, uint256 amount) external onlyOwner { _mint(to, amount); }`,
        remediation: 'Enforce an absolute supply ceiling in the mint function: require(totalSupply() + amount <= MAX_SUPPLY, "Max supply exceeded").',
      });
    }
  }
}
