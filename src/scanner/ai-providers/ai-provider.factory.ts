import { Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import { AiProvider } from './ai-provider.interface';
import { GeminiProviderService } from './gemini-provider.service';
import { AnthropicProviderService } from './anthropic-provider.service';
import { OpenAiProviderService } from './openai-provider.service';
import { DeepSeekProviderService } from './deepseek-provider.service';

@Injectable()
export class AiProviderFactory {
  private readonly logger = new Logger(AiProviderFactory.name);
  private providers: Map<string, AiProvider> = new Map();

  constructor(
    private gemini: GeminiProviderService,
    private anthropic: AnthropicProviderService,
    private openai: OpenAiProviderService,
    private deepseek: DeepSeekProviderService,
  ) {
    this.providers.set(gemini.id, gemini);
    this.providers.set(anthropic.id, anthropic);
    this.providers.set(openai.id, openai);
    this.providers.set(deepseek.id, deepseek);
  }

  getProvider(preferredId?: string): AiProvider {
    const targetId = (preferredId || process.env.AI_PROVIDER || 'gemini').toLowerCase().trim();
    const provider = this.providers.get(targetId);

    if (provider && provider.isAvailable()) {
      return provider;
    }

    // Try any configured fallback cloud provider
    for (const [id, candidate] of this.providers.entries()) {
      if (candidate.isAvailable()) {
        this.logger.warn(
          `Preferred AI provider "${targetId}" is unavailable (${provider?.getMissingConfigReason() || 'not found'}). Falling back to "${id}".`,
        );
        return candidate;
      }
    }

    const missingDetails = Array.from(this.providers.values())
      .map((p) => `${p.displayName}: ${p.getMissingConfigReason() || 'Offline'}`)
      .join(' | ');

    throw new ServiceUnavailableException(
      `Cloud AI review unavailable. Audit paused. Admin action required: ${missingDetails}`,
    );
  }

  getSupportedProviders(): { id: string; name: string; available: boolean }[] {
    return Array.from(this.providers.values()).map((p) => ({
      id: p.id,
      name: p.displayName,
      available: p.isAvailable(),
    }));
  }
}
