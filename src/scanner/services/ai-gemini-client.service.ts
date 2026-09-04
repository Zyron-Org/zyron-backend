import { Injectable } from '@nestjs/common';
import axios from 'axios';
import { AiScanResult } from '../ai-audit.service';

@Injectable()
export class AiGeminiClientService {
  async callGeminiApi(
    contractFileName: string,
    code: string,
    apiKey: string,
  ): Promise<AiScanResult> {
    const prompt = `
You are Zyron AI, a world-class smart contract security auditor specializing in EVM Solidity, Rust, and Vyper security.
Analyze the following contract file "${contractFileName}" for critical vulnerabilities, logic flaws, reentrancy, access control bypasses, and flash loan exploits.

Source Code:
\`\`\`solidity
${code}
\`\`\`

Return a JSON object with:
- "analysisSummary": Short executive summary
- "findings": Array of findings with fields:
  - "title": Concise finding title
  - "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL"
  - "cvss": e.g. "CVSS 9.8"
  - "taxonomy": e.g. "SWC-107 · CWE-841"
  - "location": e.g. "${contractFileName}:14"
  - "impact": Brief impact description
  - "description": Detailed vulnerability explanation
  - "remediatedCode": Fixed code snippet
`;

    const res = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key=${apiKey}`,
      {
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { responseMimeType: 'application/json' },
      },
      { timeout: 15000 },
    );

    const jsonText = res.data?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!jsonText) {
      throw new Error('Empty response from Gemini API');
    }

    const parsed = JSON.parse(jsonText);
    return {
      modelUsed: 'Gemini 1.5 Pro (Google AI)',
      contractFileName,
      analysisSummary: parsed.analysisSummary || `Gemini 1.5 Pro audit complete for ${contractFileName}.`,
      findings: parsed.findings || [],
    };
  }
}
