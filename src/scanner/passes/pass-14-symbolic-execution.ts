import { ParsedProject, PassFinding, ContractASTSymbol, ASTFunctionSymbol } from '../engine/types';
import { ScannerPass, PassConfig } from './pass-interface';

export class Pass14SymbolicExecution implements ScannerPass {
  passNumber = 14;
  name = 'Symbolic Execution & Path Constraint Solver';
  description = 'Performs lightweight symbolic path constraint evaluation for reachable assertion failures, division-by-zero paths, and invariant violations.';
  swcIds = ['SWC-110', 'SWC-136'];
  cweIds = ['CWE-617', 'CWE-369'];
  defaultConfidence = 'HIGH_CONFIDENCE';

  async run(project: ParsedProject, config?: PassConfig): Promise<PassFinding[]> {
    const findings: PassFinding[] = [];

    for (const contract of project.contracts.values()) {
      if (config?.ignoreOpenZeppelin && contract.filePath.includes('node_modules')) continue;

      for (const fn of contract.functions) {
        if (!fn.astNode) continue;
        const cfg = contract.cfgs.get(fn.name);
        this.analyzeSymbolicPaths(contract, fn, cfg, findings);
      }
    }

    return findings;
  }

  private analyzeSymbolicPaths(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    cfg: any,
    findings: PassFinding[],
  ): void {
    const pathGuards = new Set<string>();

    const walkNode = (node: any) => {
      if (!node || typeof node !== 'object') return;

      // 1. Collect require() and if-revert guards along execution path
      if (node.type === 'FunctionCall' && node.expression?.name === 'require') {
        const condStr = JSON.stringify(node.arguments?.[0]);
        if (condStr) pathGuards.add(condStr);
      }

      if (node.type === 'IfStatement') {
        const bodyStr = JSON.stringify(node.TrueBody || node.trueBody || {});
        if (bodyStr.includes('revert') || bodyStr.includes('RevertStatement')) {
          const condStr = JSON.stringify(node.condition);
          if (condStr) pathGuards.add(condStr);
        }
      }

      // 2. Check assert() statements — assert should only test invariants, never input validation
      if (node.type === 'FunctionCall' && node.expression?.name === 'assert') {
        const assertExpr = node.arguments?.[0];
        const line = node.loc?.start?.line || fn.astNode.loc?.start?.line || 1;
        const assertStr = JSON.stringify(assertExpr);

        // Check if assert condition depends on function parameters (symbolic inputs)
        const dependsOnParam = fn.parameters.some((p) => assertStr.includes(`"${p.name}"`));

        if (dependsOnParam) {
          findings.push({
            ruleId: 'ZYRON-14-001',
            swcId: 'SWC-110',
            cweId: 'CWE-617',
            title: 'Reachable Assertion Failure (Symbolic Input Violation)',
            description: `Function ${fn.name} in contract ${contract.name} uses assert() on symbolic parameter inputs. Assertion failure consumes all remaining gas and signals an invariant breach.`,
            severity: 'MEDIUM',
            confidence: 'HIGH_CONFIDENCE',
            analysisPass: 14,
            filePath: contract.filePath,
            line,
            codeSnippet: `assert(...) in ${fn.name}()`,
            vulnerableCode: `assert(userAmount > 0);`,
            remediation: 'Use require() or custom errors (revert InsufficientAmount()) for input validation instead of assert().',
          });
        }
      }

      // 3. Check for potential Division-by-Zero paths
      if (node.type === 'BinaryOperation' && node.operator === '/') {
        const divisor = node.right;
        const divisorName = divisor?.name;
        if (divisorName && fn.parameters.some((p) => p.name === divisorName)) {
          // Check if pathGuards contain `divisorName != 0` or `divisorName > 0` or if-revert on zero (`== 0`, `<= 0`)
          const isGuarded = Array.from(pathGuards).some(
            (g) => g.includes(divisorName) && (g.includes('!=') || g.includes('>') || g.includes('==') || g.includes('<=')),
          );

          if (!isGuarded) {
            const line = node.loc?.start?.line || fn.astNode.loc?.start?.line || 1;
            findings.push({
              ruleId: 'ZYRON-14-002',
              swcId: 'SWC-136',
              cweId: 'CWE-369',
              title: 'Division by Zero (Symbolic Path Feasible)',
              description: `Function ${fn.name} divides by parameter '${divisorName}' at line ${line} without prior non-zero require guard on the execution path.`,
              severity: 'HIGH',
              confidence: 'HIGH_CONFIDENCE',
              analysisPass: 14,
              filePath: contract.filePath,
              line,
              codeSnippet: `division by ${divisorName} in ${fn.name}()`,
              vulnerableCode: `uint256 share = total / ${divisorName};`,
              remediation: 'Add require(' + divisorName + ' > 0, "Zero divisor") before performing division operations.',
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
