import { ParsedProject, PassFinding, ContractASTSymbol, ASTFunctionSymbol } from '../engine/types';
import { ScannerPass, PassConfig } from './pass-interface';

export class Pass07DoS implements ScannerPass {
  passNumber = 7;
  name = 'Denial of Service (DoS) Vectors';
  description = 'Detects gas limit DoS via unbounded array loops, push vs pull transfer patterns, and revert-in-loop vulnerabilities.';
  swcIds = ['SWC-128', 'SWC-113'];
  cweIds = ['CWE-400', 'CWE-834'];
  defaultConfidence = 'HIGH_CONFIDENCE';

  async run(project: ParsedProject, config?: PassConfig): Promise<PassFinding[]> {
    const findings: PassFinding[] = [];

    for (const contract of project.contracts.values()) {
      if (config?.ignoreOpenZeppelin && contract.filePath.includes('node_modules')) continue;

      for (const fn of contract.functions) {
        if (!fn.astNode) continue;
        this.checkUnboundedLoop(contract, fn, findings);
        this.checkExternalCallInLoop(contract, fn, findings);
      }
    }

    return findings;
  }

  private checkUnboundedLoop(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    const walkNode = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'ForStatement' || node.type === 'WhileStatement') {
        const condStr = JSON.stringify(node.Expression || node.condition || node);
        if (condStr.includes('.length')) {
          // Check if variable referencing .length is a state variable array
          const line = node.loc?.start?.line || fn.astNode.loc?.start?.line || 1;
          findings.push({
            ruleId: 'ZYRON-07-001',
            swcId: 'SWC-128',
            cweId: 'CWE-400',
            title: 'Unbounded Loop Over Dynamic Storage Array (Gas Limit DoS)',
            description: `Function ${fn.name} in contract ${contract.name} iterates over dynamic array .length in a loop. As array elements grow, transaction gas will exceed block gas limit, causing permanent DoS.`,
            severity: 'HIGH',
            confidence: 'HIGH_CONFIDENCE',
            analysisPass: 7,
            filePath: contract.filePath,
            line,
            codeSnippet: `loop over .length in ${fn.name}()`,
            vulnerableCode: `for (uint256 i = 0; i < users.length; i++) { ... }`,
            remediation: 'Implement pagination, off-chain batch processing, or pull-payment architecture instead of iterating unbounded storage arrays.',
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

  private checkExternalCallInLoop(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    const walkNode = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'ForStatement' || node.type === 'WhileStatement') {
        const bodyStr = JSON.stringify(node.body || node);
        if (
          bodyStr.includes('.transfer(') ||
          bodyStr.includes('.send(') ||
          bodyStr.includes('.call(')
        ) {
          const line = node.loc?.start?.line || fn.astNode.loc?.start?.line || 1;
          findings.push({
            ruleId: 'ZYRON-07-002',
            swcId: 'SWC-113',
            cweId: 'CWE-834',
            title: 'External Call Inside Loop Body (Push Payment DoS)',
            description: `Function ${fn.name} makes external ETH/token transfers inside a loop. A single failing or malicious recipient contract reverting will lock the entire loop for all users.`,
            severity: 'HIGH',
            confidence: 'HIGH_CONFIDENCE',
            analysisPass: 7,
            filePath: contract.filePath,
            line,
            codeSnippet: `external call inside loop in ${fn.name}()`,
            vulnerableCode: `for (uint256 i = 0; i < payees.length; i++) { payees[i].transfer(amount); }`,
            remediation: 'Adopt OpenZeppelin PullPayment pattern where users withdraw funds individually rather than batch pushing payments.',
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
