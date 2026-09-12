import { ParsedProject, PassFinding, ContractASTSymbol, ASTFunctionSymbol } from '../engine/types';
import { ScannerPass, PassConfig } from './pass-interface';

export class Pass06Timestamp implements ScannerPass {
  passNumber = 6;
  name = 'Timestamp & Block Dependence';
  description = 'Detects dangerous dependence on block.timestamp, block.number, block.prevrandao, and blockhash for randomness or strict equality.';
  swcIds = ['SWC-116', 'SWC-120'];
  cweIds = ['CWE-829', 'CWE-330'];
  defaultConfidence = 'HIGH_CONFIDENCE';

  async run(project: ParsedProject, config?: PassConfig): Promise<PassFinding[]> {
    const findings: PassFinding[] = [];

    for (const contract of project.contracts.values()) {
      if (config?.ignoreOpenZeppelin && contract.filePath.includes('node_modules')) continue;

      for (const fn of contract.functions) {
        if (!fn.astNode) continue;
        this.checkTimestampDependence(contract, fn, findings);
        this.checkWeakRandomness(contract, fn, findings);
      }
    }

    return findings;
  }

  private checkTimestampDependence(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    const walkNode = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'BinaryOperation') {
        const isTimestampExpr = this.isTimestampExpression(node.left) || this.isTimestampExpression(node.right);
        if (isTimestampExpr) {
          if (node.operator === '==' || node.operator === '%') {
            const line = node.loc?.start?.line || fn.astNode.loc?.start?.line || 1;
            findings.push({
              ruleId: 'ZYRON-06-001',
              swcId: 'SWC-116',
              cweId: 'CWE-829',
              title: 'Block Timestamp Strict Equality / Modulo Dependence',
              description: `Function ${fn.name} in contract ${contract.name} relies on block.timestamp with '${node.operator}' operator. Validators can manipulate block timestamps slightly or delay blocks to win state conditions.`,
              severity: 'HIGH',
              confidence: 'HIGH_CONFIDENCE',
              analysisPass: 6,
              filePath: contract.filePath,
              line,
              codeSnippet: `block.timestamp ${node.operator} ...`,
              vulnerableCode: `require(block.timestamp % 2 == 0);`,
              remediation: 'Do not use block.timestamp for strict equality or randomness. Use interval inequalities (>=, <=) with safe margins.',
            });
          }
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

  private isTimestampExpression(node: any): boolean {
    if (!node || typeof node !== 'object') return false;
    if (node.type === 'MemberAccess' && node.expression?.name === 'block' && node.memberName === 'timestamp') return true;
    if (node.type === 'Identifier' && node.name === 'now') return true;
    return false;
  }

  private checkWeakRandomness(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    const walkNode = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'FunctionCall' && node.expression?.name === 'keccak256') {
        // Check if keccak256 uses block.timestamp, block.prevrandao, blockhash, block.difficulty
        const argStr = JSON.stringify(node.arguments);
        if (
          argStr.includes('timestamp') ||
          argStr.includes('prevrandao') ||
          argStr.includes('difficulty') ||
          argStr.includes('blockhash')
        ) {
          const line = node.loc?.start?.line || fn.astNode.loc?.start?.line || 1;
          findings.push({
            ruleId: 'ZYRON-06-002',
            swcId: 'SWC-120',
            cweId: 'CWE-330',
            title: 'Weak On-Chain Randomness Generation',
            description: `Function ${fn.name} generates pseudo-random numbers by hashing block parameters (timestamp/prevrandao/blockhash). Block proposers can predict or influence these values.`,
            severity: 'CRITICAL',
            confidence: 'HIGH_CONFIDENCE',
            analysisPass: 6,
            filePath: contract.filePath,
            line,
            codeSnippet: `keccak256(abi.encodePacked(block.timestamp, ...))`,
            vulnerableCode: `uint256 rand = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;`,
            remediation: 'Use Chainlink VRF (Verifiable Random Function) or a commit-reveal scheme for tamper-proof randomness.',
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
