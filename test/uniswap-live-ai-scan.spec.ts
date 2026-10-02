import { describe, it } from 'vitest';
import { ImportResolverService } from '../src/scanner/engine/import-resolver.service';
import { ASTParserService } from '../src/scanner/engine/ast-parser.service';
import { CFGBuilderService } from '../src/scanner/engine/cfg-builder.service';
import { InheritanceResolverService } from '../src/scanner/engine/inheritance-resolver.service';
import { PragmaAnalyzerService } from '../src/scanner/engine/pragma-analyzer.service';
import { PassRegistryService } from '../src/scanner/passes/pass-registry';
import { GeminiProviderService } from '../src/scanner/ai-providers/gemini-provider.service';
import * as fs from 'fs';
import * as path from 'path';
import * as dotenv from 'dotenv';

dotenv.config({ path: path.resolve(__dirname, '../.env') });

describe('Live Uniswap V2 Scan -> AI Review Pipeline', () => {
  it('should run UniswapV2Pair.sol through 14 AST passes and send candidates to Google Gemini AI', async () => {
    // 1. Load source code
    const fixturePath = path.join(__dirname, 'fixtures', 'UniswapV2Pair.sol');
    const code = fs.readFileSync(fixturePath, 'utf-8');

    console.log('\n=============================================================');
    console.log('🔍 PHASE 1: EXECUTING 14 AST STATIC ANALYSIS PASSES');
    console.log('=============================================================');

    const importResolver = new ImportResolverService();
    const astParser = new ASTParserService();
    const cfgBuilder = new CFGBuilderService();
    const inheritanceResolver = new InheritanceResolverService();
    const pragmaAnalyzer = new PragmaAnalyzerService();
    const passRegistry = new PassRegistryService();

    const files = await importResolver.resolveProject(fixturePath, code);
    pragmaAnalyzer.analyzePragmas(files);
    const project = astParser.parseProject(files);
    inheritanceResolver.resolveInheritance(project);
    cfgBuilder.buildCFGs(project);

    const { findings, passTimings } = await passRegistry.runAllPasses(project);

    console.log(`✅ Static scan complete in total passes.`);
    console.log(`Found ${findings.length} candidate finding(s) across AST passes:`);
    findings.forEach((f, idx) => {
      console.log(`  [#${idx + 1}] [Pass ${f.analysisPass}] ${f.severity} | ${f.ruleId} | ${f.title} (Line ${f.line})`);
    });

    console.log('\n=============================================================');
    console.log('🤖 PHASE 2: CALLING CLOUD AI (GOOGLE GEMINI) WITH CANDIDATES');
    console.log('=============================================================');

    const geminiProvider = new GeminiProviderService();
    console.log(`Provider available: ${geminiProvider.isAvailable()}`);
    console.log(`API Key preview: ${process.env.GEMINI_API_KEY ? process.env.GEMINI_API_KEY.slice(0, 10) + '...' : 'NONE'}`);

    try {
      const startTime = Date.now();
      const aiResult = await geminiProvider.analyzeContract(
        'UniswapV2Pair.sol',
        code,
        findings,
        {
          protocolName: 'Uniswap V2',
          businessGoals:
            'Decentralized automated market maker (AMM) enabling permissionless token swaps using x*y=k formula. Features include Flash Swaps (optimistic balance transfers with callback) and TWAP (Time-Weighted Average Price) accumulators based on modular uint32 timestamps.',
        },
      );
      const elapsed = Date.now() - startTime;

      console.log(`\n🎉 SUCCESS! AI Review received from Google Gemini (${elapsed}ms)`);
      console.log(`Model: ${aiResult.modelUsed}`);
      console.log(`Summary:\n${aiResult.analysisSummary}\n`);
      console.log('-------------------------------------------------------------');
      console.log('AI TRIAGE & PROOF FINDINGS:');
      console.log('-------------------------------------------------------------');
      aiResult.findings.forEach((f, idx) => {
        console.log(`\n[#${idx + 1}] ${f.severity} | ${f.title} (${f.location})`);
        console.log(`    Decision: ${f.decision}`);
        console.log(`    Justification: ${f.justification}`);
        if (f.pocScenario) console.log(`    PoC / Safety Proof: ${f.pocScenario}`);
        if (f.remediatedCode) console.log(`    Remediation: ${f.remediatedCode}`);
      });
      console.log('=============================================================\n');
    } catch (err: any) {
      console.error('\n❌ CLOUD AI CALL FAILED!');
      console.error(`Error Message: ${err.message}`);
      if (err.response) {
        console.error(`HTTP Status: ${err.response.status} ${err.response.statusText}`);
        console.error('API Error Details:', JSON.stringify(err.response.data, null, 2));
      }
      console.log('=============================================================\n');
    }
  }, 60000);
});
