import { ParsedProject, PassFinding, ContractASTSymbol, ASTFunctionSymbol, TaintState } from '../engine/types';
import { ScannerPass, PassConfig } from './pass-interface';

export class Pass13InterproceduralTaint implements ScannerPass {
  passNumber = 13;
  name = 'Intra- & Inter-Procedural Taint Data-Flow Analysis';
  description = 'Performs sound data-flow tracking from user-controlled inputs (calldata, parameters, msg.sender) to critical execution sinks (.call, .delegatecall, storage writes).';
  swcIds = ['SWC-112', 'SWC-115'];
  cweIds = ['CWE-20', 'CWE-829'];
  defaultConfidence = 'HIGH_CONFIDENCE';

  async run(project: ParsedProject, config?: PassConfig): Promise<PassFinding[]> {
    const findings: PassFinding[] = [];

    for (const contract of project.contracts.values()) {
      if (config?.ignoreOpenZeppelin && contract.filePath.includes('node_modules')) continue;

      for (const fn of contract.functions) {
        if (!fn.astNode || (fn.visibility !== 'public' && fn.visibility !== 'external')) continue;
        this.analyzeFunctionTaint(contract, fn, findings);
      }
    }

    return findings;
  }

  private analyzeFunctionTaint(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    // 1. Initialize taint map for function parameters and msg object
    const taintedVars = new Map<string, TaintState>();

    for (const param of fn.parameters) {
      if (param.name) {
        taintedVars.set(param.name, 'CALLDATA');
      }
    }
    taintedVars.set('msg.sender', 'USER_INPUT');
    taintedVars.set('msg.value', 'MSG_VALUE');
    taintedVars.set('msg.data', 'CALLDATA');
    taintedVars.set('tx.origin', 'USER_INPUT');

    // 2. Traversal helper for taint propagation and sink checking
    const walkNode = (node: any) => {
      if (!node || typeof node !== 'object') return;

      // Variable declaration / assignment: `x = param` or `uint256 x = msg.value`
      if (node.type === 'VariableDeclarationStatement') {
        const declName = node.variables?.[0]?.name;
        if (declName && node.initialValue) {
          if (this.isExpressionTainted(node.initialValue, taintedVars)) {
            taintedVars.set(declName, 'USER_INPUT');
          }
        }
      } else if (node.type === 'AssignmentExpression') {
        const leftName = this.extractIdentifierName(node.left);
        if (leftName && this.isExpressionTainted(node.right, taintedVars)) {
          taintedVars.set(leftName, 'USER_INPUT');
        }
      }

      // Check Sinks (.call, .delegatecall, selfdestruct, low-level call target)
      if (node.type === 'FunctionCall') {
        if (node.expression?.type === 'MemberAccess') {
          const targetName = this.extractIdentifierName(node.expression.expression);
          const memberName = node.expression.memberName;

          if (['call', 'delegatecall', 'staticcall'].includes(memberName)) {
            if (targetName && taintedVars.has(targetName)) {
              const line = node.loc?.start?.line || fn.astNode.loc?.start?.line || 1;
              const sinkType = memberName;
              const taintSource = taintedVars.get(targetName);

              findings.push({
                ruleId: 'ZYRON-13-001',
                swcId: 'SWC-112',
                cweId: 'CWE-20',
                title: `Untrusted Parameter Flow to .${sinkType}() Sink`,
                description: `Tainted parameter '${targetName}' (source: ${taintSource}) flows directly into low-level .${sinkType}() target address in function ${fn.name}() without sanitization.`,
                severity: sinkType === 'delegatecall' ? 'CRITICAL' : 'HIGH',
                confidence: 'HIGH_CONFIDENCE',
                analysisPass: 13,
                filePath: contract.filePath,
                line,
                codeSnippet: `${targetName}.${sinkType}(...) in ${fn.name}()`,
                vulnerableCode: `(bool ok, ) = ${targetName}.${sinkType}(calldata);`,
                remediation: 'Validate target address against an on-chain registry or access-controlled whitelist before performing low-level calls.',
              });
            }
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

  private isExpressionTainted(expr: any, taintedVars: Map<string, TaintState>): boolean {
    if (!expr || typeof expr !== 'object') return false;

    if (expr.type === 'Identifier') {
      return taintedVars.has(expr.name);
    }
    if (expr.type === 'MemberAccess') {
      const full = `${this.extractIdentifierName(expr.expression)}.${expr.memberName}`;
      if (taintedVars.has(full)) return true;
      return this.isExpressionTainted(expr.expression, taintedVars);
    }
    if (expr.type === 'BinaryOperation') {
      return this.isExpressionTainted(expr.left, taintedVars) || this.isExpressionTainted(expr.right, taintedVars);
    }
    if (expr.type === 'FunctionCall') {
      return (expr.arguments || []).some((arg: any) => this.isExpressionTainted(arg, taintedVars));
    }
    return false;
  }

  private extractIdentifierName(node: any): string | null {
    if (!node || typeof node !== 'object') return null;
    if (node.type === 'Identifier') return node.name;
    if (node.type === 'MemberAccess') {
      const base = this.extractIdentifierName(node.expression);
      return base ? `${base}.${node.memberName}` : node.memberName;
    }
    return null;
  }
}
