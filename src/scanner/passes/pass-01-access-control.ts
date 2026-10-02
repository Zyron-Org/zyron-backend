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
    const fnName = fn.name || '';
    if (!fnName) return;

    const sensitiveNames = [
      'setowner',
      'changeowner',
      'transferownership',
      'withdrawall',
      'emergencywithdraw',
      'setfee',
      'settreasury',
      'setvault',
      'upgradeto',
      'upgradetoandcall',
      'selfdestruct',
      'kill',
    ];

    const isSensitive = sensitiveNames.includes(fnName.toLowerCase());
    if (!isSensitive) return;

    const modifiers = fn.modifiers || [];
    const hasAuthModifier = modifiers.some((m) =>
      ['onlyowner', 'onlyadmin', 'onlyrole', 'onlygovernance', 'auth', 'restricted'].includes(
        (m.name || '').toLowerCase(),
      ),
    ) || this.hasInBodyAuthCheck(fn);

    if (!hasAuthModifier) {
      findings.push({
        ruleId: 'ZYRON-01-003',
        swcId: 'SWC-284',
        cweId: 'CWE-862',
        title: 'Unprotected Sensitive Function',
        description: `Critical function ${fnName} in contract ${contract.name} is public/external without access control modifiers or caller authorization checks.`,
        severity: 'CRITICAL',
        confidence: 'HIGH_CONFIDENCE',
        analysisPass: 1,
        filePath: contract.filePath,
        line: fn.astNode?.loc?.start?.line || 1,
        codeSnippet: `function ${fnName}(...) ${fn.visibility}`,
        vulnerableCode: `function ${fnName}() ${fn.visibility} { /* critical state modification */ }`,
        remediation: 'Restrict access using onlyOwner, onlyRole, or custom authorization modifiers.',
      });
    }
  }

  private hasInBodyAuthCheck(fn: ASTFunctionSymbol): boolean {
    if (!fn.astNode?.body) return false;
    const bodyStr = JSON.stringify(fn.astNode.body);

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
    if (!fn.astNode?.body) return false;
    const bodyStr = JSON.stringify(fn.astNode.body);

    const hasRequireCheck =
      bodyStr.includes('require') &&
      (bodyStr.includes('!initialized') ||
        bodyStr.includes('!_initialized') ||
        bodyStr.includes('initialized == false') ||
        bodyStr.includes('not initialized'));

    const hasRevertCheck =
      bodyStr.includes('revert') &&
      (bodyStr.includes('AlreadyInitialized') ||
        bodyStr.includes('InvalidInitialization') ||
        bodyStr.includes('initialized'));

    const hasDisableCall = bodyStr.includes('_disableInitializers');

    return hasRequireCheck || hasRevertCheck || hasDisableCall || this.hasInBodyAuthCheck(fn);
  }
}
