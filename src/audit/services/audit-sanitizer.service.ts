import { Injectable } from '@nestjs/common';

@Injectable()
export class AuditSanitizerService {
  sanitizeUser(user: any) {
    if (!user) return user;
    const { passwordHash, ...sanitized } = user;
    return sanitized;
  }

  sanitizeAuditResult(audit: any) {
    if (!audit) return audit;
    if (audit.submittedBy) audit.submittedBy = this.sanitizeUser(audit.submittedBy);
    if (audit.leadAuditor) audit.leadAuditor = this.sanitizeUser(audit.leadAuditor);
    if (audit.peerAuditor) audit.peerAuditor = this.sanitizeUser(audit.peerAuditor);
    if (audit.findings) {
      audit.findings = audit.findings.map((f: any) => {
        if (f.comments) {
          f.comments = f.comments.map((c: any) => {
            if (c.sender) c.sender = this.sanitizeUser(c.sender);
            return c;
          });
        }
        return f;
      });
    }
    return audit;
  }
}
