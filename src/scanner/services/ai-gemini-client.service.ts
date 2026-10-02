import { Injectable } from '@nestjs/common';
import axios from 'axios';
import { AiScanResult } from '../ai-audit.service';

@Injectable()
export class AiGeminiClientService {
  async callGeminiApi(
    contractFileName: string,
    code: string,
    apiKey: string,
    staticFindings?: any[],
    protocolContext?: { protocolName?: string; businessGoals?: string },
  ): Promise<AiScanResult> {
    const staticFindingsText =
      staticFindings && staticFindings.length > 0
        ? JSON.stringify(
            staticFindings.map((f) => ({
              ruleId: f.ruleId,
              title: f.title,
              severity: f.severity,
              line: f.line,
              description: f.description,
              snippet: f.codeSnippet || f.vulnerableCode,
            })),
            null,
            2,
          )
        : 'No prior static findings provided.';

    const prompt = `
You are Zyron AI, an institutional smart contract security auditor specializing in EVM Solidity, Rust, and Vyper.
Review the contract file "${contractFileName}"${protocolContext?.protocolName ? ` for protocol "${protocolContext.protocolName}"` : ''}.
${protocolContext?.businessGoals ? `Business Goals & Architecture: "${protocolContext.businessGoals}"` : ''}

Candidate Static Analysis Findings from 14 AST Passes:
\`\`\`json
${staticFindingsText}
\`\`\`

Source Code:
\`\`\`solidity
${code}
\`\`\`

YOUR TASK:
Critically evaluate each candidate static finding against the protocol's business intent, architecture, and code context:
1. Determine if the issue is a genuine exploit or an intentional protocol pattern / false positive:
   - "decision": "CONFIRMED" | "DOWNGRADE" | "DISMISS_INTENDED_DESIGN" | "FALSE_POSITIVE"
2. Provide technical justification:
   - "justification": Detailed technical explanation (e.g. "Protected by outer reentrancy lock", "Intentional modular timestamp overflow in TWAP")
3. Provide an attack scenario or proof of safety:
   - "pocScenario": Step-by-step exploit scenario, or why it cannot be exploited
4. Provide the exact fix if confirmed:
   - "remediatedCode": Clean drop-in fix snippet
5. Identify any novel high-severity business logic vulnerabilities missed by static AST rules.

Return a JSON object with:
- "analysisSummary": Executive summary of findings and triage
- "findings": Array of findings with fields:
  - "title": Concise finding title
  - "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL"
  - "ruleId": string (e.g. "ZYRON-08-001" or "ZYRON-AI-001")
  - "cvss": e.g. "CVSS 9.8"
  - "taxonomy": e.g. "SWC-107 · CWE-841"
  - "location": e.g. "${contractFileName}:14"
  - "impact": Brief impact description
  - "description": Detailed vulnerability explanation
  - "decision": "CONFIRMED" | "DOWNGRADE" | "DISMISS_INTENDED_DESIGN" | "FALSE_POSITIVE"
  - "justification": Explanation of decision
  - "falsePositive": boolean (true if DISMISS_INTENDED_DESIGN or FALSE_POSITIVE)
  - "fpJustification": string
  - "pocScenario": Exploit steps or safety proof
  - "remediatedCode": Corrected code snippet
`;

    const res = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key=${apiKey}`,
      {
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { responseMimeType: 'application/json' },
      },
      { timeout: 25000 },
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
