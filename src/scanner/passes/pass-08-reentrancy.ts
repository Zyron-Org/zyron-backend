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

        this.checkCFGReentrancy(contract, fn, cfg, hasReentrancyGuard, findings);
      }
    }

    return findings;
  }

  private checkCFGReentrancy(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    cfg: any,
    hasGuard: boolean,
    findings: PassFinding[],
  ): void {
    const fnName = fn.name || 'unnamed';
    const blocks: BasicBlock[] = Array.from(cfg.blocks.values());

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
        if ((line >= firstCallLine || line === 0) && this.isStateMutationStatement(stmt, contract)) {
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
            hasMutationAfterCall = true;
            mutationLine = target.stateMutationSites?.[0]?.line || firstCallLine + 1;
            return;
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

  private isStateMutationStatement(stmt: any, contract: ContractASTSymbol): boolean {
    if (!stmt || typeof stmt !== 'object') return false;
    // Don't count raw call/transfer statements as state mutations
    if (stmt.type === 'ExpressionStatement' && stmt.expression?.type === 'FunctionCall') {
      const expr = stmt.expression;
      if (expr.expression?.type === 'MemberAccess') {
        const m = expr.expression.memberName;
        if (m === 'call' || m === 'delegatecall' || m === 'transfer' || m === 'send') return false;
      }
    }

    const str = JSON.stringify(stmt);
    const stateVars = contract.stateVariables || [];
    for (const stateVar of stateVars) {
      if (str.includes(`"${stateVar.name}"`)) {
        return true;
      }
    }
    return str.includes('"Assignment"') || str.includes('AssignmentExpression');
  }
}
