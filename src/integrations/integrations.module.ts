import { Module } from '@nestjs/common';
import { GithubService } from './github.service';
import { GithubController } from './github.controller';
import { AuthModule } from '../auth/auth.module';
import {
  GithubParserService,
  GithubApiService,
  GithubCommentService,
} from './services';

@Module({
  imports: [AuthModule],
  controllers: [GithubController],
  providers: [
    GithubService,
    GithubParserService,
    GithubApiService,
    GithubCommentService,
  ],
  exports: [
    GithubService,
    GithubParserService,
    GithubApiService,
    GithubCommentService,
  ],
})
export class IntegrationsModule {}
