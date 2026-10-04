import { ParsedProject, PassFinding, ContractASTSymbol, ASTFunctionSymbol } from '../engine/types';
import { ScannerPass, PassConfig } from './pass-interface';

export class Pass01AccessControl implements ScannerPass {
  passNumber = 1;
  name = 'Access Control & Authorization';
  description = 'Detects tx.origin phishing, unprotected initializers, and un-guarded state-changing functions.';
  swcIds = ['SWC-105', 'SWC-118', 'SWC-284'];
  cweIds = ['CWE-284', 'CWE-862', 'CWE-477'];
  defaultConfidence = 'HIGH_CONFIDENCE';

  async run(project: ParsedProject, config?: PassConfig): Promise<PassFinding[]> {
    const findings: PassFinding[] = [];

    for (const contract of project.contracts.values()) {
      if (config?.ignoreOpenZeppelin && contract.filePath.includes('node_modules')) continue;

      for (const fn of contract.functions) {
        this.checkTxOrigin(contract, fn, findings);
        this.checkUnprotectedInitializer(contract, fn, findings);
        this.checkUnprotectedSensitiveFunction(contract, fn, findings);
      }
    }

    return findings;
  }

  private checkTxOrigin(contract: ContractASTSymbol, fn: ASTFunctionSymbol, findings: PassFinding[]): void {
    if (!fn.astNode) return;
    const fnName = fn.name || 'unnamed';

    const findTxOrigin = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'MemberAccess' && node.memberName === 'origin') {
        const expr = node.expression;
        if (expr && expr.type === 'Identifier' && expr.name === 'tx') {
          const line = node.loc?.start?.line || fn.astNode.loc?.start?.line || 1;
          findings.push({
            ruleId: 'ZYRON-01-001',
            swcId: 'SWC-105',
            cweId: 'CWE-284',
            title: 'Use of tx.origin for Authorization',
            description: `Function ${fnName} in contract ${contract.name} relies on tx.origin for authorization, making it vulnerable to phishing attacks.`,
            severity: 'HIGH',
            confidence: 'HIGH_CONFIDENCE',
            analysisPass: 1,
            filePath: contract.filePath,
            line,
            codeSnippet: `tx.origin check in ${fnName}()`,
            vulnerableCode: `tx.origin == owner`,
            remediation: 'Replace tx.origin with msg.sender to prevent authorization delegation attacks via phishing contracts.',
          });
        }
      }

      for (const key of Object.keys(node)) {
        if (key === 'loc') continue;
        const child = node[key];
        if (Array.isArray(child)) child.forEach(findTxOrigin);
        else if (child && typeof child === 'object') findTxOrigin(child);
      }
    };

    findTxOrigin(fn.astNode);
  }

  private checkUnprotectedInitializer(contract: ContractASTSymbol, fn: ASTFunctionSymbol, findings: PassFinding[]): void {
    const fnName = fn.name || '';
    const isInitializerName = /^init(ialize)?$/i.test(fnName) || fnName.toLowerCase().includes('initialize');
    if (!isInitializerName) return;

    const modifiers = fn.modifiers || [];
    const hasGuard = modifiers.some((m) =>
      ['initializer', 'reinitializer', 'onlyowner', 'onlyrole', 'protected'].includes((m.name || '').toLowerCase()),
    ) || this.hasInBodyInitializerGuard(fn);

    if (!hasGuard && (fn.visibility === 'public' || fn.visibility === 'external')) {
      findings.push({
        ruleId: 'ZYRON-01-002',
        swcId: 'SWC-118',
        cweId: 'CWE-284',
        title: 'Unprotected Initializer Function',
        description: `Function ${fnName} in ${contract.name} appears to be an initializer but lacks initialization guards (e.g. initializer or onlyOwner).`,
        severity: 'CRITICAL',
        confidence: 'HIGH_CONFIDENCE',
        analysisPass: 1,
        filePath: contract.filePath,
        line: fn.astNode?.loc?.start?.line || 1,
        codeSnippet: `function ${fnName}(...) ${fn.visibility}`,
        vulnerableCode: `function ${fnName}() external { ... }`,
        remediation: 'Apply OpenZeppelin Initializable modifier or restrict access with onlyOwner to prevent front-running hijacking.',
      });
    }
  }

  private checkUnprotectedSensitiveFunction(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    if (fn.visibility !== 'public' && fn.visibility !== 'external') return;
    if (fn.isConstructor || fn.isFallback || fn.isReceive) return;
    const fnName = fn.name || '';
    if (!fnName) return;

    // Initializer functions are handled specifically by checkUnprotectedInitializer
    const isInitializerName = /^init(ialize)?$/i.test(fnName) || fnName.toLowerCase().includes('initialize');
    if (isInitializerName) return;

    // View/pure functions cannot alter contract state
    if (fn.stateMutability === 'view' || fn.stateMutability === 'pure') return;

    const modifiers = fn.modifiers || [];
    const hasAuthModifier = modifiers.some((m) =>
      ['onlyowner', 'onlyadmin', 'onlyrole', 'onlygovernance', 'auth', 'restricted', 'authorized', 'onlyauthorized'].includes(
        (m.name || '').toLowerCase(),
      ),
    ) || this.hasInBodyAuthCheck(fn);

    if (hasAuthModifier) return;

    // Detect state variable mutations via AST traversal
    const modifiedVars = this.getModifiedStateVariables(contract, fn);
    const hasStateMutation = modifiedVars.length > 0;

    const hasCriticalVarMutation = modifiedVars.some((v) => this.isCriticalStateVar(v));

    // Exclude standard ERC20 / user vault interaction methods unless they mutate critical protocol variables
    const isStandardUserMethod = /^(deposit|mint|withdraw|redeem|transfer|approve)$/i.test(fnName);
    if (isStandardUserMethod && !hasCriticalVarMutation) return;

    const adminPrefixRegex = /^(set|update|change|notify|modify|reset|pause|unpause|rescue|drain|kill|destroy|upgrade|emergencywithdraw|withdrawall)/i;
    const isSensitivePattern = adminPrefixRegex.test(fnName);

    if (hasStateMutation && (isSensitivePattern || hasCriticalVarMutation)) {
      const varNames = modifiedVars.map((v) => v.name).join(', ') || 'contract state';
      findings.push({
        ruleId: 'ZYRON-01-003',
        swcId: 'SWC-284',
        cweId: 'CWE-862',
        title: 'Unprotected State-Modifying Function',
        description: `Function ${fnName} in contract ${contract.name} mutates critical state variables (${varNames}) without access control modifiers or caller authorization checks.`,
        severity: 'CRITICAL',
        confidence: 'HIGH_CONFIDENCE',
        analysisPass: 1,
        filePath: contract.filePath,
        line: fn.astNode?.loc?.start?.line || 1,
        codeSnippet: `function ${fnName}(...) ${fn.visibility}`,
        vulnerableCode: `function ${fnName}() ${fn.visibility} { /* mutates ${varNames} */ }`,
        remediation: 'Restrict access using onlyOwner, onlyRole, or require(msg.sender == ...) checks.',
      });
    }
  }

  private isCriticalStateVar(variable: any): boolean {
    const name = (variable.name || '').toLowerCase();
    const type = (variable.typeName || '').toLowerCase();

    // Skip mappings (e.g. mapping(address => uint256) balances / allowances / rewards)
    if (type.startsWith('mapping')) return false;

    // Scalar address configuration pointers: owner, admin, pool, router, oracle, distributor, implementation
    if (type === 'address') {
      return true;
    }

    // Protocol parameters (fee rates, paused flag, reward rates)
    return (
      name === 'paused' ||
      name === 'fee' ||
      name.endsWith('rate') ||
      name.endsWith('fee') ||
      name.endsWith('period') ||
      name.endsWith('finish') ||
      name.includes('oracle') ||
      name.includes('treasury')
    );
  }

  private getModifiedStateVariables(contract: ContractASTSymbol, fn: ASTFunctionSymbol): any[] {
    const node: any = fn.astNode;
    if (!node?.body) return [];

    const stateVarNames = new Set(contract.stateVariables.map((v) => v.name));
    const modified = new Set<string>();

    const walk = (n: any) => {
      if (!n || typeof n !== 'object') return;

      if (n.type === 'BinaryOperation' && ['=', '+=', '-=', '*=', '/='].includes(n.operator)) {
        const leftName = this.extractIdentifierName(n.left);
        if (leftName && stateVarNames.has(leftName)) {
          modified.add(leftName);
        }
      }

      if (n.type === 'UnaryOperation' && ['++', '--'].includes(n.operator)) {
        const subName = this.extractIdentifierName(n.subExpression);
        if (subName && stateVarNames.has(subName)) {
          modified.add(subName);
        }
      }

      for (const key of Object.keys(n)) {
        if (key === 'loc') continue;
        const child = n[key];
        if (Array.isArray(child)) child.forEach(walk);
        else if (child && typeof child === 'object') walk(child);
      }
    };

    walk(node.body);
    return contract.stateVariables.filter((v) => modified.has(v.name));
  }

  private extractIdentifierName(n: any): string | null {
    if (!n) return null;
    if (n.type === 'Identifier') return n.name;
    if (n.type === 'IndexAccess') return this.extractIdentifierName(n.base);
    if (n.type === 'MemberAccess' && n.expression?.type === 'Identifier' && n.expression.name === 'this') {
      return n.memberName;
    }
    return null;
  }

  private hasInBodyAuthCheck(fn: ASTFunctionSymbol): boolean {
    const node: any = fn.astNode;
    if (!node?.body) return false;
    const bodyStr = JSON.stringify(node.body);

    // 1. require(msg.sender == ...) or require(hasRole(...)) or require(isOwner(...))
    const hasRequireAuth =
      bodyStr.includes('msg.sender') && (bodyStr.includes('require') || bodyStr.includes('assert'));

    // 2. if (msg.sender != ...) revert ... or if (!isOwner) revert ...
    const hasRevertAuth =
      bodyStr.includes('revert') &&
      (bodyStr.includes('msg.sender') ||
        bodyStr.includes('_msgSender') ||
        bodyStr.includes('owner') ||
        bodyStr.includes('admin') ||
        bodyStr.includes('Unauthorized') ||
        bodyStr.includes('NotAuthorized') ||
        bodyStr.includes('OnlyOwner'));

    // 3. OpenZeppelin / Solady internal auth calls
    const hasInternalCheckCall =
      bodyStr.includes('_checkOwner') ||
      bodyStr.includes('_checkRole') ||
      bodyStr.includes('_onlyOwner') ||
      bodyStr.includes('_validateOwner') ||
      bodyStr.includes('enforceIsOwner');

    return hasRequireAuth || hasRevertAuth || hasInternalCheckCall;
  }

  private hasInBodyInitializerGuard(fn: ASTFunctionSymbol): boolean {
    const node: any = fn.astNode;
    if (!node?.body) return false;
    const bodyStr = JSON.stringify(node.body);

    const hasRequireCheck =
      (bodyStr.includes('require') || bodyStr.includes('assert')) &&
      (bodyStr.includes('initialized') ||
        bodyStr.includes('_initialized') ||
        bodyStr.includes('isInitialized') ||
        bodyStr.includes('ALREADY_INITIALIZED') ||
        bodyStr.includes('already initialized'));

    const hasRevertCheck =
      bodyStr.includes('revert') &&
      (bodyStr.includes('AlreadyInitialized') ||
        bodyStr.includes('InvalidInitialization') ||
        bodyStr.includes('initialized'));

    const hasDisableCall = bodyStr.includes('_disableInitializers');

    return hasRequireCheck || hasRevertCheck || hasDisableCall || this.hasInBodyAuthCheck(fn);
  }
}
