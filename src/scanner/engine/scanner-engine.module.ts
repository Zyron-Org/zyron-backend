import { Module } from '@nestjs/common';
import { ImportResolverService } from './import-resolver.service';
import { ASTParserService } from './ast-parser.service';
import { CFGBuilderService } from './cfg-builder.service';
import { InheritanceResolverService } from './inheritance-resolver.service';
import { PragmaAnalyzerService } from './pragma-analyzer.service';

@Module({
  providers: [
    ImportResolverService,
    ASTParserService,
    CFGBuilderService,
    InheritanceResolverService,
    PragmaAnalyzerService,
  ],
  exports: [
    ImportResolverService,
    ASTParserService,
    CFGBuilderService,
    InheritanceResolverService,
    PragmaAnalyzerService,
  ],
})
export class ScannerEngineModule {}
