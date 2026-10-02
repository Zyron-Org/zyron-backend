export function buildSecurityAuditPrompt(
  contractFileName: string,
  code: string,
  staticFindings?: any[],
  protocolContext?: { protocolName?: string; businessGoals?: string },
): string {
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

  return `
You are Zyron AI, an institutional smart contract security auditor specializing in EVM Solidity, Vyper, and Rust/Move.
Review the contract file "${contractFileName}"${protocolContext?.protocolName ? ` for protocol "${protocolContext.protocolName}"` : ''}.
${protocolContext?.businessGoals ? `Business Goals & Architecture Context: "${protocolContext.businessGoals}"` : ''}

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
   - "justification": Detailed technical explanation (e.g. "Protected by outer reentrancy lock modifier", "Intentional modular timestamp overflow in TWAP")
3. Provide an attack scenario or proof of safety:
   - "pocScenario": Step-by-step exploit scenario, or why it cannot be exploited
4. Provide the exact fix if confirmed:
   - "remediatedCode": Clean drop-in fix snippet
5. Identify any novel high-severity business logic vulnerabilities missed by static AST rules.

Return a valid JSON object strictly matching this schema:
{
  "analysisSummary": "Executive summary of findings and triage",
  "findings": [
    {
      "title": "Concise finding title",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL",
      "ruleId": "ZYRON-08-001 or ZYRON-AI-001",
      "cvss": "CVSS 9.8",
      "taxonomy": "SWC-107 · CWE-841",
      "location": "${contractFileName}:14",
      "impact": "Brief impact description",
      "description": "Detailed vulnerability explanation",
      "decision": "CONFIRMED" | "DOWNGRADE" | "DISMISS_INTENDED_DESIGN" | "FALSE_POSITIVE",
      "justification": "Explanation of decision",
      "falsePositive": false,
      "fpJustification": "",
      "pocScenario": "Step-by-step exploit steps or safety proof",
      "remediatedCode": "Corrected code snippet"
    }
  ]
}
`;
}
