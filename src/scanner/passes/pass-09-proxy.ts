import { ParsedProject, PassFinding, ContractASTSymbol, ASTFunctionSymbol } from '../engine/types';
import { ScannerPass, PassConfig } from './pass-interface';

export class Pass09Proxy implements ScannerPass {
  passNumber = 9;
  name = 'Upgradeability & Proxy Storage Clashes';
  description = 'Detects arbitrary delegatecall targets, selfdestruct in implementations, and state variable initialization in upgradeable constructors.';
  swcIds = ['SWC-112', 'SWC-106'];
  cweIds = ['CWE-829', 'CWE-284', 'CWE-665'];
  defaultConfidence = 'HIGH_CONFIDENCE';

  async run(project: ParsedProject, config?: PassConfig): Promise<PassFinding[]> {
    const findings: PassFinding[] = [];

    for (const contract of project.contracts.values()) {
      if (config?.ignoreOpenZeppelin && contract.filePath.includes('node_modules')) continue;

      const bases = contract.baseContracts || contract.inheritance?.baseContracts || [];
      const isUpgradeable =
        bases.some((b: any) => (typeof b === 'string' ? b : b.name).toLowerCase().includes('upgradeable')) ||
        contract.name.toLowerCase().includes('upgradeable');

      if (isUpgradeable) {
        this.checkConstructorInUpgradeable(contract, findings);
      }

      for (const fn of contract.functions) {
        if (!fn.astNode) continue;
        this.checkDelegatecallTarget(contract, fn, findings);
        this.checkSelfdestructInProxy(contract, fn, isUpgradeable, findings);
      }
    }

    return findings;
  }

  private checkDelegatecallTarget(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    const fnName = fn.name || 'unnamed';

    const walkNode = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'FunctionCall' && node.expression?.type === 'MemberAccess') {
        if (node.expression.memberName === 'delegatecall') {
          const targetExpr = node.expression.expression;
          const targetName = targetExpr?.name || 'target';

          const isParam = (fn.parameters || []).some((p) => p.name === targetName);

          const line = node.loc?.start?.line || fn.astNode.loc?.start?.line || 1;
          const severity = isParam ? 'CRITICAL' : 'HIGH';

          findings.push({
            ruleId: 'ZYRON-09-001',
            swcId: 'SWC-112',
            cweId: 'CWE-829',
            title: isParam
              ? 'Arbitrary Delegatecall to User-Controlled Target'
              : 'Delegatecall Execution Risk',
            description: `Function ${fnName} executes delegatecall on ${targetName}. ${
              isParam ? 'Target address is directly passed as a function parameter.' : 'Delegatecall executes target code within caller storage context.'
            }`,
            severity,
            confidence: 'HIGH_CONFIDENCE',
            analysisPass: 9,
            filePath: contract.filePath,
            line,
            codeSnippet: `${targetName}.delegatecall(...) in ${fnName}()`,
            vulnerableCode: `(bool ok, ) = ${targetName}.delegatecall(data);`,
            remediation: 'Ensure target address is immutable or verified against a strict whitelist/ERC1967 implementation slot.',
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

  private checkConstructorInUpgradeable(contract: ContractASTSymbol, findings: PassFinding[]): void {
    const constructorFn = contract.functions.find((f) => f.isConstructor);
    if (!constructorFn || !constructorFn.astNode) return;

    let hasStateAssignment = false;
    let assignmentLine = constructorFn.astNode.loc?.start?.line || 1;

    const walkNode = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'AssignmentExpression') {
        hasStateAssignment = true;
        assignmentLine = node.loc?.start?.line || assignmentLine;
      }

      for (const key of Object.keys(node)) {
        if (key === 'loc') continue;
        const child = node[key];
        if (Array.isArray(child)) child.forEach(walkNode);
        else if (child && typeof child === 'object') walkNode(child);
      }
    };

    walkNode(constructorFn.astNode);

    const hasDisableInitializers = JSON.stringify(constructorFn.astNode).includes('_disableInitializers');

    if (hasStateAssignment && !hasDisableInitializers) {
      findings.push({
        ruleId: 'ZYRON-09-002',
        swcId: 'SWC-106',
        cweId: 'CWE-665',
        title: 'State Variable Assignment in Upgradeable Contract Constructor',
        description: `Upgradeable contract ${contract.name} initializes state variables in constructor instead of initializer function. Values set in constructor will NOT be present in proxy state.`,
        severity: 'HIGH',
        confidence: 'HIGH_CONFIDENCE',
        analysisPass: 9,
        filePath: contract.filePath,
        line: assignmentLine,
        codeSnippet: `constructor() in ${contract.name}`,
        vulnerableCode: `constructor() { owner = msg.sender; }`,
        remediation: 'Move state variable initializations into an initialize() function protected by initializer modifier, and call _disableInitializers() in constructor.',
      });
    }
  }

  private checkSelfdestructInProxy(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    isUpgradeable: boolean,
    findings: PassFinding[],
  ): void {
    const fnName = fn.name || 'unnamed';

    const walkNode = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (
        node.type === 'FunctionCall' &&
        (node.expression?.name === 'selfdestruct' || node.expression?.name === 'suicide')
      ) {
        const line = node.loc?.start?.line || fn.astNode.loc?.start?.line || 1;
        findings.push({
          ruleId: 'ZYRON-09-003',
          swcId: 'SWC-106',
          cweId: 'CWE-284',
          title: 'Selfdestruct in Implementation Contract',
          description: `Function ${fnName} calls selfdestruct. If invoked on an upgradeable implementation contract, it permanently destroys the logic contract, bricking all proxies.`,
          severity: 'CRITICAL',
          confidence: 'HIGH_CONFIDENCE',
          analysisPass: 9,
          filePath: contract.filePath,
          line,
          codeSnippet: `selfdestruct(...) in ${fnName}()`,
          vulnerableCode: `selfdestruct(payable(recipient));`,
          remediation: 'Avoid selfdestruct in implementation contracts behind proxy patterns.',
        });
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
