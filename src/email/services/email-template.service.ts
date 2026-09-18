import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as Handlebars from 'handlebars';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class EmailTemplateService implements OnModuleInit {
  private readonly logger = new Logger(EmailTemplateService.name);
  private compiledTemplates = new Map<string, Handlebars.TemplateDelegate>();
  private baseLayout: Handlebars.TemplateDelegate | null = null;

  onModuleInit() {
    this.registerHelpers();
    this.loadTemplates();
  }

  private registerHelpers() {
    Handlebars.registerHelper('year', () => new Date().getFullYear());
    Handlebars.registerHelper('eq', (a: any, b: any) => a === b);
    Handlebars.registerHelper('uppercase', (str: string) => str?.toUpperCase());
  }

  private loadTemplates() {
    const candidateDirs = [
      path.join(__dirname, '..', 'templates'),
      path.join(process.cwd(), 'src', 'email', 'templates'),
      path.join(process.cwd(), 'backend', 'src', 'email', 'templates'),
      path.join(process.cwd(), 'dist', 'email', 'templates'),
    ];

    const templatesDir = candidateDirs.find((dir) => fs.existsSync(dir));

    if (!templatesDir) {
      this.logger.warn(`Templates directory not found in candidates: ${candidateDirs.join(', ')}`);
      return;
    }


    // Load and register base layout as a partial
    const layoutPath = path.join(templatesDir, 'base-layout.hbs');
    if (fs.existsSync(layoutPath)) {
      const layoutSource = fs.readFileSync(layoutPath, 'utf-8');
      this.baseLayout = Handlebars.compile(layoutSource);
      Handlebars.registerPartial('base-layout', layoutSource);
      this.logger.debug('Registered base-layout partial');
    }

    // Load all .hbs template files
    const files = fs.readdirSync(templatesDir).filter((f) => f.endsWith('.hbs') && f !== 'base-layout.hbs');

    for (const file of files) {
      const templateName = file.replace('.hbs', '');
      const filePath = path.join(templatesDir, file);
      const source = fs.readFileSync(filePath, 'utf-8');
      this.compiledTemplates.set(templateName, Handlebars.compile(source));
      this.logger.debug(`Compiled email template: ${templateName}`);
    }

    this.logger.log(`📧 Loaded ${this.compiledTemplates.size} email template(s)`);
  }

  render(templateName: string, data: Record<string, any> = {}): string {
    const template = this.compiledTemplates.get(templateName);

    if (!template) {
      this.logger.error(`Email template "${templateName}" not found`);
      return `<p>Email template "${templateName}" not found.</p>`;
    }

    // Inject global data available to all templates
    const globalData = {
      ...data,
      currentYear: new Date().getFullYear(),
      platformName: 'Zyron Security',
      platformUrl: data.platformUrl || process.env.APP_URL || 'http://localhost:3000',
    };

    return template(globalData);
  }

  getAvailableTemplates(): string[] {
    return Array.from(this.compiledTemplates.keys());
  }
}
