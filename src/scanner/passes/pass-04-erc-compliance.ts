import { ParsedProject, PassFinding, ContractASTSymbol, ASTFunctionSymbol } from '../engine/types';
import { ScannerPass, PassConfig } from './pass-interface';

export class Pass04ERCCompliance implements ScannerPass {
  passNumber = 4;
  name = 'ERC Standard Compliance & Safe ERC20';
  description = 'Detects unchecked ERC20 return values, USDT approval race conditions, and non-standard ERC interface implementations.';
  swcIds = ['SWC-104'];
  cweIds = ['CWE-252', 'CWE-362'];
  defaultConfidence = 'HIGH_CONFIDENCE';

  async run(project: ParsedProject, config?: PassConfig): Promise<PassFinding[]> {
    const findings: PassFinding[] = [];

    for (const contract of project.contracts.values()) {
      if (config?.ignoreOpenZeppelin && contract.filePath.includes('node_modules')) continue;

      const usingFor = contract.usingForDirectives || [];
      const usesSafeERC20 = usingFor.some(
        (u) => (u.libraryName || '').includes('SafeERC20') || (u.libraryName || '').includes('SafeToken'),
      );

      for (const fn of contract.functions) {
        if (!fn.astNode) continue;
        this.checkUncheckedERC20Return(contract, fn, usesSafeERC20, findings);
        this.checkApproveRaceCondition(contract, fn, findings);
      }
    }

    return findings;
  }

  private checkUncheckedERC20Return(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    usesSafeERC20: boolean,
    findings: PassFinding[],
  ): void {
    if (usesSafeERC20) return;
    const fnName = fn.name || 'unnamed';

    const walkNode = (node: any, parent: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'FunctionCall' && node.expression?.type === 'MemberAccess') {
        const method = node.expression.memberName;
        if (['transfer', 'transferFrom', 'approve'].includes(method)) {
          const isCaptured =
            parent &&
            (parent.type === 'VariableDeclarationStatement' ||
              parent.type === 'AssignmentExpression' ||
              parent.type === 'IfStatement' ||
              (parent.type === 'FunctionCall' && parent.expression?.name === 'require') ||
              (parent.type === 'FunctionCall' && parent.expression?.name === 'assert'));

          const isSafeCall =
            ['safeTransfer', 'safeTransferFrom', 'safeApprove', 'forceApprove'].includes(method);

          if (!isCaptured && !isSafeCall) {
            const line = node.loc?.start?.line || fn.astNode.loc?.start?.line || 1;
            findings.push({
              ruleId: 'ZYRON-04-001',
              swcId: 'SWC-104',
              cweId: 'CWE-252',
              title: 'Unchecked ERC20 Transfer / Approve Return Value',
              description: `Function ${fnName} in contract ${contract.name} calls ${method}() on an ERC20 token without checking the return value or using SafeERC20. Tokens like USDT do not return a boolean and will fail silently.`,
              severity: 'MEDIUM',
              confidence: 'HIGH_CONFIDENCE',
              analysisPass: 4,
              filePath: contract.filePath,
              line,
              codeSnippet: `call to .${method}() in ${fnName}()`,
              vulnerableCode: `IERC20(token).${method}(to, amount);`,
              remediation: 'Use OpenZeppelin SafeERC20 library (safeTransfer, safeTransferFrom, safeApprove or forceApprove) to handle non-compliant tokens safely.',
            });
          }
        }
      }

      for (const key of Object.keys(node)) {
        if (key === 'loc') continue;
        const child = node[key];
        if (Array.isArray(child)) child.forEach((c) => walkNode(c, node));
        else if (child && typeof child === 'object') walkNode(child, node);
      }
    };

    walkNode(fn.astNode, null);
  }

  private checkApproveRaceCondition(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    const fnName = fn.name || 'unnamed';

    const walkNode = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'FunctionCall' && node.expression?.type === 'MemberAccess') {
        const method = node.expression.memberName;
        if (method === 'approve') {
          const amountArg = node.arguments?.[1];
          if (amountArg && amountArg.type === 'Identifier') {
            const line = node.loc?.start?.line || fn.astNode.loc?.start?.line || 1;
            findings.push({
              ruleId: 'ZYRON-04-002',
              swcId: 'SWC-114',
              cweId: 'CWE-362',
              title: 'ERC20 Approval Race Condition / Non-Zero Approval',
              description: `Function ${fnName} approves non-zero token amount directly. Tokens like USDT revert if approving a non-zero amount when existing allowance is non-zero.`,
              severity: 'LOW',
              confidence: 'MEDIUM_CONFIDENCE',
              analysisPass: 4,
              filePath: contract.filePath,
              line,
              codeSnippet: `approve(spender, ${amountArg.name})`,
              vulnerableCode: `IERC20(token).approve(spender, amount);`,
              remediation: 'Set allowance to 0 before setting it to a new value (approve(spender, 0)), or use SafeERC20 forceApprove().',
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
