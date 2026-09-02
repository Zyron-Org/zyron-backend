import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';
import { PORT, SWAGGER_USER, SWAGGER_PASS, origins } from './config';
import { AllExceptionsFilter } from './common/filters/exceptions.filter';
import { swaggerAuth } from './common/middleware/swagger-auth.middleware';
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Global Prefix (/api/v1) matching codebase pattern
  app.setGlobalPrefix('api/v1', {
    exclude: ['/docs', '/docs-json'],
  });

  // Security Middleware
  app.use(helmet());
  app.enableCors({ origin: origins, credentials: true });

  // Global Validation & Exception Handling
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    }),
  );
  app.useGlobalFilters(new AllExceptionsFilter());

  // Swagger OpenAPI Documentation with Basic Auth Protection
  const swaggerConfig = new DocumentBuilder()
    .setTitle('Zyron Protocol — Smart Contract Security API')
    .setDescription(
      'Production REST API engine for Zyron smart contract security auditing, automated vulnerability scanning, SIWE wallet authentication, dual-auditor code review workbench, and cryptographic attestation generation.',
    )
    .setVersion('1.0.0')
    .addBearerAuth()
    .addTag('Authentication', 'Login, registration, SIWE wallet authentication, and profile endpoints')
    .addTag('User Administration', 'Platform user management and Role-Based Access Control (Admin only)')
    .addTag('Audit Engagements', 'Audit request creation, stage progression, and auditor ticket claiming')
    .addTag('Vulnerability Findings', 'Finding creation, severity/status updates, and remediation comment threads')
    .addTag('File Storage', 'Direct S3 upload presigned URLs and PDF report downloads')
    .addTag('GitHub Integration', 'GitHub repository selection and branch metadata retrieval')
    .addTag('Payments & Escrow', 'Web3 crypto escrow deposits and corporate Net-30 invoice generation')
    .addTag('Organizations', 'Organization management, member invitations, and subscription tier settings')
    .addTag('Automated Scanner', 'Automated Slither/Mythril security scans, token risk analysis, and @zyron-bot PR webhooks')
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);

  // Basic Auth Protection for Swagger UI (/docs)
  app.use('/docs', swaggerAuth(SWAGGER_USER, SWAGGER_PASS));
  SwaggerModule.setup('docs', app, document);

  await app.listen(PORT, '0.0.0.0');

  console.log(`🚀 Zyron Security API server running on: http://localhost:${PORT}/api/v1`);
  console.log(`📚 Interactive Swagger OpenAPI Docs available at: http://localhost:${PORT}/docs (User: ${SWAGGER_USER})`);
}

bootstrap();
