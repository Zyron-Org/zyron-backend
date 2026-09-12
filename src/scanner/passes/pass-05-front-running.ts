import { ParsedProject, PassFinding, ContractASTSymbol, ASTFunctionSymbol } from '../engine/types';
import { ScannerPass, PassConfig } from './pass-interface';

export class Pass05FrontRunning implements ScannerPass {
  passNumber = 5;
  name = 'Front-Running & MEV Vulnerabilities';
  description = 'Detects zero slippage tolerance in DEX swaps, ineffective transaction deadlines, and sandwich attack vectors.';
  swcIds = ['SWC-114'];
  cweIds = ['CWE-362', 'CWE-665'];
  defaultConfidence = 'HIGH_CONFIDENCE';

  async run(project: ParsedProject, config?: PassConfig): Promise<PassFinding[]> {
    const findings: PassFinding[] = [];

    for (const contract of project.contracts.values()) {
      if (config?.ignoreOpenZeppelin && contract.filePath.includes('node_modules')) continue;

      for (const fn of contract.functions) {
        if (!fn.astNode) continue;
        this.checkZeroSlippageSwaps(contract, fn, findings);
        this.checkIneffectiveDeadline(contract, fn, findings);
      }
    }

    return findings;
  }

  private checkZeroSlippageSwaps(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    const walkNode = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'FunctionCall' && node.expression?.type === 'MemberAccess') {
        const method = node.expression.memberName;
        if (/^swapExact(TokensForTokens|ETHForTokens|TokensForETH|TokensForTokensSupportingFeeOnTransferTokens)$/i.test(method) || method === 'swap') {
          // Check minAmountOut parameter (typically index 1)
          const minOutArg = node.arguments?.[1];
          if (
            minOutArg &&
            (minOutArg.type === 'NumberLiteral' && (minOutArg.number === '0' || minOutArg.value === 0))
          ) {
            const line = node.loc?.start?.line || fn.astNode.loc?.start?.line || 1;
            findings.push({
              ruleId: 'ZYRON-05-001',
              swcId: 'SWC-114',
              cweId: 'CWE-362',
              title: 'Zero Slippage Tolerance (MEV Sandwich Vulnerable)',
              description: `Function ${fn.name} executes DEX swap ${method}() with minAmountOut = 0, allowing MEV searchers to sandwich the transaction and extract all value.`,
              severity: 'HIGH',
              confidence: 'HIGH_CONFIDENCE',
              analysisPass: 5,
              filePath: contract.filePath,
              line,
              codeSnippet: `call to .${method}(..., 0, ...) in ${fn.name}()`,
              vulnerableCode: `router.${method}(amountIn, 0, path, to, deadline);`,
              remediation: 'Pass a user-specified minAmountOut parameter and validate that minAmountOut > 0.',
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

  private checkIneffectiveDeadline(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    const walkNode = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'FunctionCall' && node.expression?.type === 'MemberAccess') {
        const method = node.expression.memberName;
        if (/^swap/i.test(method)) {
          // Check last argument (deadline)
          const lastArg = node.arguments?.[node.arguments.length - 1];
          if (
            lastArg &&
            lastArg.type === 'MemberAccess' &&
            lastArg.expression?.name === 'block' &&
            lastArg.memberName === 'timestamp'
          ) {
            const line = node.loc?.start?.line || fn.astNode.loc?.start?.line || 1;
            findings.push({
              ruleId: 'ZYRON-05-002',
              swcId: 'SWC-114',
              cweId: 'CWE-665',
              title: 'Ineffective Swap Deadline (block.timestamp Passed as Deadline)',
              description: `Function ${fn.name} passes block.timestamp directly as the deadline to ${method}(), which means the transaction will never expire regardless of miner delay.`,
              severity: 'MEDIUM',
              confidence: 'HIGH_CONFIDENCE',
              analysisPass: 5,
              filePath: contract.filePath,
              line,
              codeSnippet: `deadline parameter is block.timestamp`,
              vulnerableCode: `router.swapExactTokensForTokens(..., block.timestamp);`,
              remediation: 'Pass a signed or caller-provided absolute deadline timestamp (e.g. deadline parameter from user).',
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
}
