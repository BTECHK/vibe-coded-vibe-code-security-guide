# Vibe Code Security Guide [In Progress]

A security checklist for AI-assisted development. I built this as a personal learning project, synthesizing research from [Databricks, Replit, Supabase, OWASP, and others](./sources.md), then iterating with multiple LLMs to pressure-test coverage.

---

## Core Security Checklist

### 🔴 HIGH Priority (Do before any deployment)

#### 1. AI & Prompting
- [ ] Use security-focused system prompts when generating code
- [ ] Apply self-reflection after code generation ("Review for vulnerabilities...")
- [ ] Verify AI actually implemented security measures (don't assume)

#### 2. Secrets Management
- [ ] Never hardcode secrets — use environment variables
- [ ] Verify `.gitignore` covers `.env`, `*.pem`, `*.key`, `credentials/`
- [ ] Understand key types: publishable (frontend OK) vs secret (backend only)

#### 3. Authentication
- [ ] Use established auth providers (Clerk, Auth0, Supabase Auth, NextAuth)
- [ ] Secure session management (`HttpOnly`, `Secure`, `SameSite` cookies)
- [ ] Rate limit login attempts (5-10 per minute per IP)

#### 4. Authorization
- [ ] Enable Row Level Security (RLS) on all database tables
- [ ] Test the "ID swap" attack — can User A access User B's data?
- [ ] Verify authorization on every request (backend, not just frontend)

#### 5. Input Validation
- [ ] Server-side validation is mandatory (client-side is for UX only)
- [ ] Use parameterized queries or ORMs — never concatenate SQL
- [ ] Sanitize user input before rendering (prevent XSS)

#### 6. Frontend Security
- [ ] HTTPS everywhere (verify custom domains have SSL)
- [ ] Prevent XSS: avoid `dangerouslySetInnerHTML`, `innerHTML`, `eval()`
- [ ] No secrets in client code — only publishable keys allowed

#### 7. Backend & API Security
- [ ] Protect all non-public endpoints with authentication
- [ ] Implement rate limiting on sensitive endpoints
- [ ] Secure error handling — no stack traces or file paths to clients

#### 8. Database Security
- [ ] Principle of least privilege — app DB users have minimal permissions
- [ ] Encrypt sensitive data at rest (PII, financial, health)
- [ ] Use SSL/TLS for database connections

#### 9. Dependencies
- [ ] Audit dependencies regularly (`npm audit`, `pip-audit`)
- [ ] Verify package authenticity (check for typosquatting)
- [ ] Lock dependency versions (commit lockfiles)

#### 10. Infrastructure & Deployment
- [ ] Separate environments (dev, staging, production)
- [ ] Use TLS 1.2+ in production
- [ ] Secure CI/CD pipeline — secrets in CI secrets manager, not logs

#### 11. Testing & Validation
- [ ] Test authorization bypass (User A accessing User B's resources)
- [ ] Test input validation (special chars, SQL payloads, boundary values)
- [ ] Verify RLS policies with automated tests

#### 12. AI Agent Security
- [ ] Apply least privilege to AI agents (limit file/network access)
- [ ] Define credential boundaries (what can the agent access?)
- [ ] Require human confirmation for high-impact actions

---

### 🟡 MEDIUM Priority (Before scaling / sensitive data)

<!-- TODO: Consolidate MEDIUM priority items from source materials -->

- [ ] Implement MFA for admin accounts
- [ ] Set up security headers (CSP, X-Frame-Options, etc.)
- [ ] Configure CORS properly (whitelist specific origins)
- [ ] File upload security (validate types server-side, size limits)
- [ ] Implement key rotation schedule
- [ ] Review AI-generated dependencies for maintenance status
- [ ] Container security (non-root users, scan images)
- [ ] Create incident response plan

---

### 🟢 LOW Priority (Mature applications)

<!-- TODO: Consolidate LOW priority items from source materials -->

- [ ] Penetration testing / bug bounty
- [ ] SIEM implementation
- [ ] Compliance certifications (SOC 2, GDPR, etc.)
- [ ] Advanced monitoring and anomaly detection

See [AI Agent Security](./ai-agent-security.md) for expanded guidance.

---

## Reference Sections

> Brief mentions — see linked docs for details

### Monitoring & Incident Response
- Enable logging for auth events and API errors (never log sensitive data)
- Set up alerts for failed logins and error spikes
- See [AI Agent Security](./ai-agent-security.md) for agent-specific monitoring

### Compliance Considerations
- Data minimization — only collect what you need
- User rights — data export, account deletion
- See expansion docs for GDPR, HIPAA, SOC 2, PCI-DSS specifics

---

## Expand Further

- **[Stack-Specific Security](./stack-specific-security.md)** — Supabase, Next.js, Firebase, Docker, Stripe, React Native, and more
- **[AI Agent Security](./ai-agent-security.md)** — MoltBot, Claude Code, agentic principles deep dive
- **[Sources](./sources.md)** — Research and references used to build this guide

---

## Future: Claude Skill

This guide will become a Claude skill with sub-commands:

| Command | Behavior |
|---------|----------|
| `/vibe-security:review` | Audit current codebase against this checklist |
| `/vibe-security:preflight` | Interactive pre-deployment walkthrough |
| `/vibe-security:mode` | Inject security principles into session context |

---

## Contributing

This is a personal learning project, but suggestions are welcome. Open an issue or PR if you have improvements.

---

## License

MIT License — Use freely, but security is your responsibility.
