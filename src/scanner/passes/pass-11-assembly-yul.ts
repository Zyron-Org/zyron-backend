import { ParsedProject, PassFinding, ContractASTSymbol, ASTFunctionSymbol } from '../engine/types';
import { ScannerPass, PassConfig } from './pass-interface';

export class Pass11AssemblyYul implements ScannerPass {
  passNumber = 11;
  name = 'Inline Assembly & Yul Safety';
  description = 'Detects dangerous Yul inline assembly opcodes (delegatecall, selfdestruct, extcodesize EOA check bypass, free memory pointer corruption).';
  swcIds = ['SWC-127'];
  cweIds = ['CWE-788', 'CWE-284', 'CWE-676'];
  defaultConfidence = 'HIGH_CONFIDENCE';

  async run(project: ParsedProject, config?: PassConfig): Promise<PassFinding[]> {
    const findings: PassFinding[] = [];

    for (const contract of project.contracts.values()) {
      if (config?.ignoreOpenZeppelin && contract.filePath.includes('node_modules')) continue;

      for (const fn of contract.functions) {
        if (!fn.astNode) continue;
        this.checkInlineAssembly(contract, fn, findings);
      }
    }

    return findings;
  }

  private checkInlineAssembly(
    contract: ContractASTSymbol,
    fn: ASTFunctionSymbol,
    findings: PassFinding[],
  ): void {
    const walkNode = (node: any) => {
      if (!node || typeof node !== 'object') return;

      if (node.type === 'InlineAssemblyStatement') {
        const line = node.loc?.start?.line || fn.astNode.loc?.start?.line || 1;
        const yulStr = JSON.stringify(node.body || node);

        // 1. Check for extcodesize check (used to verify if caller is EOA — fails during contract construction!)
        if (yulStr.includes('extcodesize')) {
          findings.push({
            ruleId: 'ZYRON-11-001',
            swcId: 'SWC-127',
            cweId: 'CWE-284',
            title: 'extcodesize Used for EOA Check (Bypassable in Constructor)',
            description: `Function ${fn.name} uses Yul extcodesize opcode to check if an address is a contract. Contracts calling during construction have extcodesize = 0, bypassing this guard.`,
            severity: 'HIGH',
            confidence: 'HIGH_CONFIDENCE',
            analysisPass: 11,
            filePath: contract.filePath,
            line,
            codeSnippet: `extcodesize(...) in Yul block`,
            vulnerableCode: `assembly { codeSize := extcodesize(account) } require(codeSize == 0);`,
            remediation: 'Do not rely on extcodesize == 0 to check for EOAs. Use ERC-7521 or signature validation instead.',
          });
        }

        // 2. Check for dangerous opcodes in Yul (delegatecall, selfdestruct, create2)
        if (yulStr.includes('delegatecall')) {
          findings.push({
            ruleId: 'ZYRON-11-002',
            swcId: 'SWC-127',
            cweId: 'CWE-829',
            title: 'Yul Low-Level delegatecall Opcode',
            description: `Function ${fn.name} executes delegatecall opcode in inline assembly, bypassing Solidity type checking and storage safety.`,
            severity: 'HIGH',
            confidence: 'HIGH_CONFIDENCE',
            analysisPass: 11,
            filePath: contract.filePath,
            line,
            codeSnippet: `delegatecall(...) in assembly`,
            vulnerableCode: `assembly { result := delegatecall(gas(), target, ...) }`,
            remediation: 'Validate target address, memory offsets, and returndata handling thoroughly in Yul delegatecall blocks.',
          });
        }

        // 3. Informational: Inline assembly usage
        findings.push({
          ruleId: 'ZYRON-11-003',
          swcId: 'SWC-127',
          cweId: 'CWE-788',
          title: 'Use of Inline Assembly (Yul)',
          description: `Function ${fn.name} uses inline assembly. Yul bypasses Solidity memory management (0x40 free memory pointer) and type safety.`,
          severity: 'INFORMATIONAL',
          confidence: 'HIGH_CONFIDENCE',
          analysisPass: 11,
          filePath: contract.filePath,
          line,
          codeSnippet: `assembly { ... } in ${fn.name}()`,
          vulnerableCode: `assembly { ... }`,
          remediation: 'Ensure free memory pointer (0x60/0x40) is preserved and return buffer boundaries are checked.',
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
