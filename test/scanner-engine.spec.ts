import { describe, it, expect, beforeAll } from 'vitest';
import { ImportResolverService } from '../src/scanner/engine/import-resolver.service';
import { ASTParserService } from '../src/scanner/engine/ast-parser.service';
import { CFGBuilderService } from '../src/scanner/engine/cfg-builder.service';
import { InheritanceResolverService } from '../src/scanner/engine/inheritance-resolver.service';
import { PragmaAnalyzerService } from '../src/scanner/engine/pragma-analyzer.service';
import { PassRegistryService } from '../src/scanner/passes/pass-registry';
import { AttestationService } from '../src/blockchain/services/attestation.service';
import * as fs from 'fs';
import * as path from 'path';

describe('Scanner Engine Integration Tests', () => {
  let importResolver: ImportResolverService;
  let astParser: ASTParserService;
  let cfgBuilder: CFGBuilderService;
  let inheritanceResolver: InheritanceResolverService;
  let pragmaAnalyzer: PragmaAnalyzerService;
  let passRegistry: PassRegistryService;

  beforeAll(() => {
    importResolver = new ImportResolverService();
    astParser = new ASTParserService();
    cfgBuilder = new CFGBuilderService();
    inheritanceResolver = new InheritanceResolverService();
    pragmaAnalyzer = new PragmaAnalyzerService();
    passRegistry = new PassRegistryService();
  });

  describe('ImportResolverService', () => {
    it('should resolve a single inline file', async () => {
      const code = 'pragma solidity ^0.8.20;\ncontract Test { }';
      const files = await importResolver.resolveProject('Test.sol', code);
      expect(files.size).toBe(1);
    });

    it('should extract import paths from source code', async () => {
      const code = `pragma solidity ^0.8.20;\nimport "@openzeppelin/contracts/token/ERC20/ERC20.sol";\ncontract Test { }`;
      const files = await importResolver.resolveProject('Test.sol', code);
      const entry = files.get(path.normalize('Test.sol'));
      expect(entry).toBeDefined();
      expect(entry!.imports.length).toBe(1);
      expect(entry!.imports[0]).toContain('ERC20.sol');
    });
  });

  describe('PragmaAnalyzerService', () => {
    it('should analyze floating pragmas and outdated versions', async () => {
      const code = 'pragma solidity ^0.7.0;\ncontract Floating { }';
      const files = await importResolver.resolveProject('Floating.sol', code);
      const result = pragmaAnalyzer.analyzePragmas(files);
      expect(result.diagnostics.length).toBeGreaterThanOrEqual(1);
      expect(result.diagnostics.some((d) => d.code === 'FLOATING_PRAGMA')).toBe(true);
    });
  });

  describe('ASTParserService', () => {
    it('should parse a simple contract into AST symbols', async () => {
      const code = 'pragma solidity ^0.8.20;\ncontract Vault {\n  address public owner;\n  function withdraw() external { }\n}';
      const files = await importResolver.resolveProject('Vault.sol', code);
      const project = astParser.parseProject(files);
      expect(project.contracts.size).toBe(1);
      expect(project.contracts.has('Vault')).toBe(true);
      expect(project.contracts.get('Vault')!.functions.length).toBe(1);
    });
  });

  describe('InheritanceResolverService', () => {
    it('should linearize C3 inheritance chain', async () => {
      const code = `pragma solidity ^0.8.20;
contract Base { address public owner; }
contract Derived is Base { uint256 public value; }`;
      const files = await importResolver.resolveProject('Derived.sol', code);
      const project = astParser.parseProject(files);
      const res = inheritanceResolver.resolveInheritance(project);
      const derived = project.contracts.get('Derived');
      expect(derived).toBeDefined();
      expect(derived!.linearizedBaseContracts).toContain('Base');
    });
  });

  describe('CFGBuilderService', () => {
    it('should build CFGs with multiple basic blocks for branching', async () => {
      const code = `pragma solidity ^0.8.20;
contract Branch {
  function check(uint x) external pure returns (uint) {
    if (x > 10) {
      return 1;
    } else {
      return 0;
    }
  }
}`;
      const files = await importResolver.resolveProject('Branch.sol', code);
      const project = astParser.parseProject(files);
      cfgBuilder.buildCFGs(project);
      const contract = project.contracts.get('Branch');
      expect(contract!.cfgs.has('check')).toBe(true);
      const cfg = contract!.cfgs.get('check')!;
      expect(cfg.blocks.size).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Pass Registry (14 passes)', () => {
    it('should detect reentrancy in ReentrancyVault fixture', async () => {
      const fixturePath = path.join(__dirname, 'fixtures', 'ReentrancyVault.sol');
      const code = fs.readFileSync(fixturePath, 'utf-8');
      const files = await importResolver.resolveProject(fixturePath, code);
      const project = astParser.parseProject(files);
      cfgBuilder.buildCFGs(project);

      const { findings } = await passRegistry.runAllPasses(project);
      const reentrancyFindings = findings.filter((f) => f.ruleId === 'ZYRON-08-001');
      expect(reentrancyFindings.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect tx.origin in ReentrancyVault fixture', async () => {
      const fixturePath = path.join(__dirname, 'fixtures', 'ReentrancyVault.sol');
      const code = fs.readFileSync(fixturePath, 'utf-8');
      const files = await importResolver.resolveProject(fixturePath, code);
      const project = astParser.parseProject(files);
      cfgBuilder.buildCFGs(project);

      const { findings } = await passRegistry.runAllPasses(project);
      const txOriginFindings = findings.filter((f) => f.ruleId === 'ZYRON-01-001');
      expect(txOriginFindings.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect unprotected initializer', async () => {
      const fixturePath = path.join(__dirname, 'fixtures', 'UnprotectedInitializer.sol');
      const code = fs.readFileSync(fixturePath, 'utf-8');
      const files = await importResolver.resolveProject(fixturePath, code);
      const project = astParser.parseProject(files);
      cfgBuilder.buildCFGs(project);

      const { findings } = await passRegistry.runAllPasses(project);
      const initFindings = findings.filter((f) => f.ruleId === 'ZYRON-01-002');
      expect(initFindings.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect delegatecall in UnprotectedInitializer fixture', async () => {
      const fixturePath = path.join(__dirname, 'fixtures', 'UnprotectedInitializer.sol');
      const code = fs.readFileSync(fixturePath, 'utf-8');
      const files = await importResolver.resolveProject(fixturePath, code);
      const project = astParser.parseProject(files);
      cfgBuilder.buildCFGs(project);

      const { findings } = await passRegistry.runAllPasses(project);
      const delegateFindings = findings.filter((f) => f.ruleId === 'ZYRON-09-001');
      expect(delegateFindings.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect spot oracle in OracleManipulator fixture', async () => {
      const fixturePath = path.join(__dirname, 'fixtures', 'OracleManipulator.sol');
      const code = fs.readFileSync(fixturePath, 'utf-8');
      const files = await importResolver.resolveProject(fixturePath, code);
      const project = astParser.parseProject(files);
      cfgBuilder.buildCFGs(project);

      const { findings } = await passRegistry.runAllPasses(project);
      const oracleFindings = findings.filter((f) => f.ruleId === 'ZYRON-03-001');
      expect(oracleFindings.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect honeypot patterns in HoneypotToken fixture', async () => {
      const fixturePath = path.join(__dirname, 'fixtures', 'HoneypotToken.sol');
      const code = fs.readFileSync(fixturePath, 'utf-8');
      const files = await importResolver.resolveProject(fixturePath, code);
      const project = astParser.parseProject(files);
      cfgBuilder.buildCFGs(project);

      const { findings } = await passRegistry.runAllPasses(project);
      const honeypotFindings = findings.filter((f) => f.analysisPass === 10);
      expect(honeypotFindings.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect arithmetic precision loss in UncheckedArithmetic fixture', async () => {
      const fixturePath = path.join(__dirname, 'fixtures', 'UncheckedArithmetic.sol');
      const code = fs.readFileSync(fixturePath, 'utf-8');
      const files = await importResolver.resolveProject(fixturePath, code);
      const project = astParser.parseProject(files);
      cfgBuilder.buildCFGs(project);

      const { findings } = await passRegistry.runAllPasses(project);
      const divMulFindings = findings.filter((f) => f.ruleId === 'ZYRON-02-001');
      expect(divMulFindings.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect Chainlink staleness absence in StaleChainlinkOracle fixture', async () => {
      const fixturePath = path.join(__dirname, 'fixtures', 'StaleChainlinkOracle.sol');
      const code = fs.readFileSync(fixturePath, 'utf-8');
      const files = await importResolver.resolveProject(fixturePath, code);
      const project = astParser.parseProject(files);
      cfgBuilder.buildCFGs(project);

      const { findings } = await passRegistry.runAllPasses(project);
      const stalenessFindings = findings.filter((f) => f.ruleId === 'ZYRON-03-002');
      expect(stalenessFindings.length).toBeGreaterThanOrEqual(1);
    });

    it('should suppress critical reentrancy findings on CleanVault (False Positive Suppression)', async () => {
      const fixturePath = path.join(__dirname, 'fixtures', 'CleanVault.sol');
      const code = fs.readFileSync(fixturePath, 'utf-8');
      const files = await importResolver.resolveProject(fixturePath, code);
      const project = astParser.parseProject(files);
      cfgBuilder.buildCFGs(project);

      const { findings } = await passRegistry.runAllPasses(project);
      const criticalReentrancy = findings.filter(
        (f) => f.ruleId === 'ZYRON-08-001' && f.severity === 'CRITICAL',
      );
      expect(criticalReentrancy.length).toBe(0);
    });
  });

  describe('AttestationService', () => {
    let attestation: AttestationService;

    beforeAll(() => {
      attestation = new AttestationService(null as any);
    });

    it('should compute a deterministic merkle root', () => {
      const findings = [
        { displayId: 'ZYR-001-001', severity: 'CRITICAL' },
        { displayId: 'ZYR-001-002', severity: 'HIGH' },
        { displayId: 'ZYR-001-003', severity: 'MEDIUM' },
      ];
      const root1 = attestation.computeFindingsMerkleRoot(findings);
      const root2 = attestation.computeFindingsMerkleRoot(findings);
      expect(root1).toBe(root2);
      expect(root1.startsWith('0x')).toBe(true);
      expect(root1.length).toBe(66);
    });

    it('should return zero hash for empty findings', () => {
      const root = attestation.computeFindingsMerkleRoot([]);
      expect(root).toBe('0x' + '0'.repeat(64));
    });
  });
});
