import { ParsedProject, PassFinding, ContractASTSymbol, ASTFunctionSymbol } from '../engine/types';
import { ScannerPass, PassConfig } from './pass-interface';

export class Pass02Arithmetic implements ScannerPass {
  passNumber = 2;
  name = 'Arithmetic & Precision Safety';
  description = 'Detects division before multiplication, unsafe arithmetic in unchecked blocks, and unsafe downcasting.';
  swcIds = ['SWC-101', 'SWC-682'];
  cweIds = ['CWE-682', 'CWE-190', 'CWE-681'];
  defaultConfidence = 'HIGH_CONFIDENCE';

  async run(project: ParsedProject, config?: PassConfig): Promise<PassFinding[]> {
    const findings: PassFinding[] = [];

    for (const contract of project.contracts.values()) {
      if (config?.ignoreOpenZeppelin && contract.filePath.includes('node_modules')) continue;

      for (const fn of contract.functions) {
        if (!fn.astNode) continue;
        this.checkDivisionBeforeMultiplication(contract, fn, findings);
        this.checkUncheckedBlockOperations(contract, fn, findings);
        this.checkUnsafeDowncasting(contract, fn, findings);
      }
    }

    return findings;
  }

  private checkDivisionBeforeMultiplication(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    const fnName = fn.name || 'unnamed';

    const walkNode = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'BinaryOperation' && node.operator === '*') {
        if (this.containsDivision(node.left) || this.containsDivision(node.right)) {
          const line = node.loc?.start?.line || fn.astNode?.loc?.start?.line || 1;
          findings.push({
            ruleId: 'ZYRON-02-001',
            swcId: 'SWC-101',
            cweId: 'CWE-682',
            title: 'Division Before Multiplication (Precision Loss)',
            description: `Function ${fnName} in contract ${contract.name} performs division before multiplication, causing precision loss due to integer truncation.`,
            severity: 'MEDIUM',
            confidence: 'HIGH_CONFIDENCE',
            analysisPass: 2,
            filePath: contract.filePath,
            line,
            codeSnippet: `(a / b) * c in ${fnName}()`,
            vulnerableCode: `uint256 result = (a / b) * c;`,
            remediation: 'Perform all multiplications before divisions or use high-precision fixed-point math libraries (e.g. FullMath, PRBMath).',
          });
        }
      }

      for (const key of Object.keys(node)) {
        if (key === 'loc') continue;
        const child = node[key];
        if (Array.isArray(child)) {
          child.forEach(walkNode);
        } else if (child && typeof child === 'object') {
          walkNode(child);
        }
      }
    };

    walkNode(fn.astNode);
  }

  private containsDivision(node: any): boolean {
    if (!node || typeof node !== 'object') return false;
    if (Array.isArray(node)) return node.some((item) => this.containsDivision(item));
    if (node.type === 'BinaryOperation' && node.operator === '/') return true;
    if (node.type === 'TupleExpression') return this.containsDivision(node.components);
    if (node.type === 'ExpressionStatement' || node.type === 'ParenthesizedExpression') {
      return this.containsDivision(node.expression);
    }
    return false;
  }

  private checkUncheckedBlockOperations(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    const fnName = fn.name || 'unnamed';

    const walkUnchecked = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'UncheckedStatement') {
        const checkUncheckedOp = (child: any) => {
          if (!child || typeof child !== 'object') return;
          if (
            child.type === 'BinaryOperation' &&
            ['+', '-', '*', '**'].includes(child.operator)
          ) {
            const line = child.loc?.start?.line || node.loc?.start?.line || 1;
            findings.push({
              ruleId: 'ZYRON-02-002',
              swcId: 'SWC-101',
              cweId: 'CWE-190',
              title: 'Unchecked Arithmetic Overflow / Underflow Vulnerability',
              description: `Arithmetic operation (${child.operator}) inside unchecked block in ${fnName}() could overflow or underflow if parameters are unconstrained.`,
              severity: 'HIGH',
              confidence: 'MEDIUM_CONFIDENCE',
              analysisPass: 2,
              filePath: contract.filePath,
              line,
              codeSnippet: `unchecked { ... ${child.operator} ... }`,
              vulnerableCode: `unchecked { balance -= amount; }`,
              remediation: 'Ensure inputs are strictly bound or validated before entering an unchecked block.',
            });
          }

          for (const k of Object.keys(child)) {
            if (k === 'loc') continue;
            const sub = child[k];
            if (Array.isArray(sub)) sub.forEach(checkUncheckedOp);
            else if (sub && typeof sub === 'object') checkUncheckedOp(sub);
          }
        };

        checkUncheckedOp(node);
      }

      for (const key of Object.keys(node)) {
        if (key === 'loc') continue;
        const child = node[key];
        if (Array.isArray(child)) child.forEach(walkUnchecked);
        else if (child && typeof child === 'object') walkUnchecked(child);
      }
    };

    walkUnchecked(fn.astNode);
  }

  private checkUnsafeDowncasting(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    const fnName = fn.name || 'unnamed';

    const walkCasts = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (
        node.type === 'FunctionCall' &&
        node.expression?.type === 'ElementaryTypeName'
      ) {
        const typeName = node.expression.name;
        if (
          /^uint(8|16|32|64|96|128|160)$/.test(typeName) ||
          /^int(8|16|32|64|96|128|160)$/.test(typeName)
        ) {
          const line = node.loc?.start?.line || fn.astNode?.loc?.start?.line || 1;
          findings.push({
            ruleId: 'ZYRON-02-003',
            swcId: 'SWC-681',
            cweId: 'CWE-681',
            title: 'Unsafe Type Downcasting',
            description: `Explicit cast to lower bit-width type ${typeName} in function ${fnName}() without safeCast utility can cause silent truncation.`,
            severity: 'MEDIUM',
            confidence: 'MEDIUM_CONFIDENCE',
            analysisPass: 2,
            filePath: contract.filePath,
            line,
            codeSnippet: `${typeName}(...)`,
            vulnerableCode: `${typeName}(uint256Value)`,
            remediation: 'Use OpenZeppelin SafeCast library (e.g. SafeCast.toUint128(val)) to revert on overflow during downcasting.',
          });
        }
      }

      for (const key of Object.keys(node)) {
        if (key === 'loc') continue;
        const child = node[key];
        if (Array.isArray(child)) child.forEach(walkCasts);
        else if (child && typeof child === 'object') walkCasts(child);
      }
    };

    walkCasts(fn.astNode);
  }
}
