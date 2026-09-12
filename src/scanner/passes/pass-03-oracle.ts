import { ParsedProject, PassFinding, ContractASTSymbol, ASTFunctionSymbol } from '../engine/types';
import { ScannerPass, PassConfig } from './pass-interface';

export class Pass03Oracle implements ScannerPass {
  passNumber = 3;
  name = 'Oracle & Spot Price Safety';
  description = 'Detects flash-loan vulnerable spot price usage (getReserves, slot0) and unvalidated Chainlink oracle reads.';
  swcIds = ['SWC-116', 'SWC-367'];
  cweIds = ['CWE-367', 'CWE-829'];
  defaultConfidence = 'HIGH_CONFIDENCE';

  async run(project: ParsedProject, config?: PassConfig): Promise<PassFinding[]> {
    const findings: PassFinding[] = [];

    for (const contract of project.contracts.values()) {
      if (config?.ignoreOpenZeppelin && contract.filePath.includes('node_modules')) continue;

      for (const fn of contract.functions) {
        if (!fn.astNode) continue;
        this.checkSpotPriceOracle(contract, fn, findings);
        this.checkChainlinkOracleStaleness(contract, fn, findings);
        this.checkDeprecatedLatestAnswer(contract, fn, findings);
      }
    }

    return findings;
  }

  private checkSpotPriceOracle(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    const walkNode = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'FunctionCall' && node.expression?.type === 'MemberAccess') {
        const memberName = node.expression.memberName;
        if (memberName === 'getReserves' || memberName === 'slot0') {
          const line = node.loc?.start?.line || fn.astNode.loc?.start?.line || 1;
          findings.push({
            ruleId: 'ZYRON-03-001',
            swcId: 'SWC-116',
            cweId: 'CWE-367',
            title: 'Spot Price Manipulation (Uniswap getReserves / slot0)',
            description: `Function ${fn.name} in contract ${contract.name} fetches spot price/reserves via ${memberName}() which can be manipulated in a single transaction using flash loans.`,
            severity: 'CRITICAL',
            confidence: 'HIGH_CONFIDENCE',
            analysisPass: 3,
            filePath: contract.filePath,
            line,
            codeSnippet: `call to .${memberName}() in ${fn.name}()`,
            vulnerableCode: `(uint118 r0, uint118 r1,) = pair.getReserves();`,
            remediation: 'Use a Time-Weighted Average Price (TWAP) oracle or Chainlink Decentralized Data Feeds instead of instant spot reserves.',
          });
        }
      }

      for (const key of Object.keys(node)) {
        if (key === 'loc') continue;
        const child = node[key];
        if (Array.isArray(child)) child.forEach(walkNode);
        else if (child && typeof child === 'object') walkNode(child);
      }
    };

    walkNode(fn.astNode);
  }

  private checkChainlinkOracleStaleness(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    let hasLatestRoundData = false;
    let hasStalenessCheck = false;
    let targetLine = 1;

    const walkNode = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'FunctionCall' && node.expression?.type === 'MemberAccess') {
        if (node.expression.memberName === 'latestRoundData') {
          hasLatestRoundData = true;
          targetLine = node.loc?.start?.line || 1;
        }
      }

      // Check if updatedAt / roundId / answeredInRound or timestamp check is performed in require/if
      if (node.type === 'Identifier') {
        if (['updatedAt', 'updatedOn', 'answeredInRound', 'timestamp'].includes(node.name)) {
          hasStalenessCheck = true;
        }
      }

      for (const key of Object.keys(node)) {
        if (key === 'loc') continue;
        const child = node[key];
        if (Array.isArray(child)) child.forEach(walkNode);
        else if (child && typeof child === 'object') walkNode(child);
      }
    };

    walkNode(fn.astNode);

    if (hasLatestRoundData && !hasStalenessCheck) {
      findings.push({
        ruleId: 'ZYRON-03-002',
        swcId: 'SWC-116',
        cweId: 'CWE-829',
        title: 'Chainlink Oracle Missing Staleness Check',
        description: `Function ${fn.name} in contract ${contract.name} calls latestRoundData() but does not validate updatedAt timestamp or answeredInRound.`,
        severity: 'HIGH',
        confidence: 'HIGH_CONFIDENCE',
        analysisPass: 3,
        filePath: contract.filePath,
        line: targetLine,
        codeSnippet: `latestRoundData() call without staleness validation`,
        vulnerableCode: `(, int256 price, , , ) = priceFeed.latestRoundData();`,
        remediation: 'Validate that price > 0, updatedAt != 0, updatedAt >= block.timestamp - STALENESS_THRESHOLD, and answeredInRound >= roundId.',
      });
    }
  }

  private checkDeprecatedLatestAnswer(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    const walkNode = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'FunctionCall' && node.expression?.type === 'MemberAccess') {
        if (node.expression.memberName === 'latestAnswer') {
          const line = node.loc?.start?.line || 1;
          findings.push({
            ruleId: 'ZYRON-03-003',
            swcId: 'SWC-116',
            cweId: 'CWE-477',
            title: 'Use of Deprecated Chainlink latestAnswer()',
            description: `Function ${fn.name} in contract ${contract.name} calls deprecated latestAnswer() which does not revert if the oracle fails or returns stale data.`,
            severity: 'HIGH',
            confidence: 'HIGH_CONFIDENCE',
            analysisPass: 3,
            filePath: contract.filePath,
            line,
            codeSnippet: `call to .latestAnswer() in ${fn.name}()`,
            vulnerableCode: `int256 price = priceFeed.latestAnswer();`,
            remediation: 'Migrate to latestRoundData() with proper staleness and round completion checks.',
          });
        }
      }

      for (const key of Object.keys(node)) {
        if (key === 'loc') continue;
        const child = node[key];
        if (Array.isArray(child)) child.forEach(walkNode);
        else if (child && typeof child === 'object') walkNode(child);
      }
    };

    walkNode(fn.astNode);
  }
}
