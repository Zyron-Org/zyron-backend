import { Global, Module } from '@nestjs/common';
import { EventEmitterModule } from '@nestjs/event-emitter';
import {
  EmailTransportService,
  EmailTemplateService,
  EmailDispatcherService,
} from './services';

@Global()
@Module({
  imports: [EventEmitterModule.forRoot()],
  providers: [
    EmailTransportService,
    EmailTemplateService,
    EmailDispatcherService,
  ],
  exports: [
    EmailTransportService,
    EmailTemplateService,
    EmailDispatcherService,
  ],
})
export class EmailModule {}
