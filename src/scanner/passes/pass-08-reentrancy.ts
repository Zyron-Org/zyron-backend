import { ParsedProject, PassFinding, ContractASTSymbol, ASTFunctionSymbol, BasicBlock } from '../engine/types';
import { ScannerPass, PassConfig } from './pass-interface';

export class Pass08Reentrancy implements ScannerPass {
  passNumber = 8;
  name = 'Reentrancy & Call Order Safety';
  description = 'Detects single-function, cross-function, and read-only reentrancy using multi-block CFG control-flow analysis.';
  swcIds = ['SWC-107'];
  cweIds = ['CWE-841', 'CWE-667'];
  defaultConfidence = 'HIGH_CONFIDENCE';

  async run(project: ParsedProject, config?: PassConfig): Promise<PassFinding[]> {
    const findings: PassFinding[] = [];

    for (const contract of project.contracts.values()) {
      if (config?.ignoreOpenZeppelin && contract.filePath.includes('node_modules')) continue;

      for (const fn of contract.functions) {
        const cfg = contract.cfgs.get(fn.name || '');
        if (!cfg) continue;

        const modifiers = fn.modifiers || [];
        const hasReentrancyGuard = modifiers.some((m) =>
          ['nonreentrant', 'lock', 'no-reentrancy', 'reentrancyguard'].includes((m.name || '').toLowerCase()),
        );

        this.checkCFGReentrancy(project, contract, fn, cfg, hasReentrancyGuard, findings);
      }
    }

    return findings;
  }

  private collectAllStateVars(project: ParsedProject, contract: ContractASTSymbol): Set<string> {
    const names = new Set<string>();
    (contract.stateVariables || []).forEach((v) => names.add(v.name));
    (contract.linearizedBaseContracts || []).forEach((baseName) => {
      const base = project.contracts.get(baseName);
      if (base) {
        (base.stateVariables || []).forEach((v) => names.add(v.name));
      }
    });
    return names;
  }

  private checkCFGReentrancy(
    project: ParsedProject,
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    cfg: any,
    hasGuard: boolean,
    findings: PassFinding[],
  ): void {
    const fnName = fn.name || 'unnamed';
    const blocks: BasicBlock[] = Array.from(cfg.blocks.values());
    const stateVarNames = this.collectAllStateVars(project, contract);

    for (const block of blocks) {
      if (!block.hasExternalCall) continue;

      const callSites = (block.externalCallSites && block.externalCallSites.length > 0)
        ? block.externalCallSites
        : block.externalCalls || [];

      const firstCallLine = callSites[0]?.line || fn.line || 1;

      let hasMutationAfterCall = false;
      let mutationLine = firstCallLine;

      // Check current block statements
      for (const stmt of block.statements) {
        const line = (stmt as any).loc?.start?.line || (stmt as any).expression?.loc?.start?.line || 0;
        if ((line >= firstCallLine || line === 0) && this.isStateMutationStatement(stmt, stateVarNames)) {
          hasMutationAfterCall = true;
          mutationLine = line > 0 ? line : firstCallLine + 1;
          break;
        }
      }

      // Check successor blocks
      if (!hasMutationAfterCall) {
        const visited = new Set<string>();
        const searchSuccessors = (blockId: string) => {
          if (visited.has(blockId)) return;
          visited.add(blockId);
          const target = cfg.blocks.get(blockId);
          if (!target) return;
          if (target.hasStateMutation) {
            const hasRealMutation = (target.stateMutationSites || []).some((site) => {
              const root = site.variableName.split('.')[0].split('[')[0].trim();
              return stateVarNames.has(root);
            });
            if (hasRealMutation) {
              hasMutationAfterCall = true;
              mutationLine = target.stateMutationSites?.[0]?.line || firstCallLine + 1;
              return;
            }
          }
          (target.successors || []).forEach(searchSuccessors);
        };
        (block.successors || []).forEach(searchSuccessors);
      }

      if (hasMutationAfterCall) {
        const confidence = hasGuard ? 'LOW_CONFIDENCE' : 'HIGH_CONFIDENCE';
        const severity = hasGuard ? 'LOW' : 'CRITICAL';

        findings.push({
          ruleId: 'ZYRON-08-001',
          swcId: 'SWC-107',
          cweId: 'CWE-841',
          title: hasGuard
            ? 'Potential Reentrancy (ReentrancyGuard Present)'
            : 'State-Change After External Call (Reentrancy Vulnerability)',
          description: `Function ${fnName} in contract ${contract.name} executes external call before state variables are updated (e.g. at line ${mutationLine}). Violation of Checks-Effects-Interactions pattern.`,
          severity,
          confidence,
          analysisPass: 8,
          filePath: contract.filePath,
          line: firstCallLine,
          codeSnippet: `external call in ${fnName}() at line ${firstCallLine}`,
          vulnerableCode: `(bool ok, ) = target.call{value: amount}("");\nbalances[msg.sender] = 0;`,
          remediation: 'Follow Checks-Effects-Interactions pattern: update contract state (balances, flags) BEFORE executing external calls or transfers.',
        });
      }
    }
  }

  private isStateMutationStatement(stmt: any, stateVarNames: Set<string>): boolean {
    if (!stmt || typeof stmt !== 'object') return false;

    // Statements that never mutate storage
    if (
      stmt.type === 'EmitStatement' ||
      stmt.type === 'ReturnStatement' ||
      stmt.type === 'VariableDeclarationStatement'
    ) {
      return false;
    }

    // Don't count raw call/transfer statements or requires as state mutations
    if (stmt.type === 'ExpressionStatement' && stmt.expression?.type === 'FunctionCall') {
      const expr = stmt.expression;
      if (expr.expression?.type === 'MemberAccess') {
        const m = expr.expression.memberName;
        if (m === 'call' || m === 'delegatecall' || m === 'transfer' || m === 'send') return false;
      }
      if (expr.expression?.type === 'Identifier') {
        const idName = expr.expression.name;
        if (idName === 'require' || idName === 'assert' || idName === 'revert') return false;
      }
    }

    const extractRootName = (node: any): string | null => {
      if (!node) return null;
      if (node.type === 'Identifier') return node.name;
      if (node.type === 'IndexAccess') return extractRootName(node.base);
      if (node.type === 'MemberAccess') return extractRootName(node.expression);
      return null;
    };

    let targetName: string | null = null;
    if (stmt.type === 'Assignment' || (stmt.type === 'ExpressionStatement' && stmt.expression?.type === 'Assignment')) {
      const assignExpr = stmt.type === 'Assignment' ? stmt : stmt.expression;
      targetName = extractRootName(assignExpr.left);
    } else if (
      stmt.type === 'ExpressionStatement' &&
      stmt.expression?.type === 'BinaryOperation' &&
      ['=', '+=', '-=', '*=', '/=', '|=', '&=', '^=', '<<=', '>>='].includes(stmt.expression.operator)
    ) {
      targetName = extractRootName(stmt.expression.left);
    } else if (
      stmt.type === 'ExpressionStatement' &&
      stmt.expression?.type === 'UnaryOperation' &&
      ['++', '--', 'delete'].includes(stmt.expression.operator)
    ) {
      targetName = extractRootName(stmt.expression.subExpression);
    }

    if (targetName && stateVarNames.has(targetName)) {
      return true;
    }

    return false;
  }
}
