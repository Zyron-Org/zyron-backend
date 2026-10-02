import { describe, it, expect, beforeAll } from 'vitest';
import { ImportResolverService } from '../src/scanner/engine/import-resolver.service';
import { ASTParserService } from '../src/scanner/engine/ast-parser.service';
import { CFGBuilderService } from '../src/scanner/engine/cfg-builder.service';
import { InheritanceResolverService } from '../src/scanner/engine/inheritance-resolver.service';
import { PragmaAnalyzerService } from '../src/scanner/engine/pragma-analyzer.service';
import { PassRegistryService } from '../src/scanner/passes/pass-registry';
import * as fs from 'fs';
import * as path from 'path';

describe('Uniswap V2 Pair Static Analysis Benchmark', () => {
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

  it('should scan UniswapV2Pair.sol across all 14 AST passes and print findings catalog', async () => {
    const fixturePath = path.join(__dirname, 'fixtures', 'UniswapV2Pair.sol');
    const code = fs.readFileSync(fixturePath, 'utf-8');

    const files = await importResolver.resolveProject(fixturePath, code);
    const pragmaRes = pragmaAnalyzer.analyzePragmas(files);
    const project = astParser.parseProject(files);
    inheritanceResolver.resolveInheritance(project);
    cfgBuilder.buildCFGs(project);

    const { findings, passTimings } = await passRegistry.runAllPasses(project);

    console.log('\n=============================================================');
    console.log('📊 UNISWAP V2 PAIR - STATIC AST ANALYSIS SCAN RESULTS');
    console.log('=============================================================');
    console.log(`Contracts parsed: ${project.contracts.size}`);
    console.log(`Total Findings: ${findings.length}`);
    console.log('Pass execution timings (ms):', passTimings);
    console.log('-------------------------------------------------------------');

    findings.forEach((f, idx) => {
      console.log(`\n[#${idx + 1}] [Pass ${f.analysisPass}] ${f.severity} | ${f.ruleId} | ${f.title}`);
      console.log(`    Location: Line ${f.line}`);
      console.log(`    Description: ${f.description}`);
      console.log(`    Taxonomy: ${f.swcId} · ${f.cweId}`);
    });
    console.log('\n=============================================================\n');

    expect(project.contracts.has('UniswapV2Pair')).toBe(true);
  });
});
