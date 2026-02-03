# Vibe Code Security Guide

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Claude Code Skill](https://img.shields.io/badge/Claude%20Code-Skill-blue)](https://github.com/BTECHK/vibe-coded-vibe-code-security-guide)

> **A comprehensive, platform-agnostic security reference for AI-assisted development**
>
> Includes a Claude Code skill (`check-your-vibe`) for automated security audits

Created for web and mobile applications built with AI coding assistants (Cursor, Claude Code, Lovable, Bolt, v0, Replit Agent, etc.)

A security checklist synthesizing research from [Databricks, Replit, Supabase, OWASP, and others](./sources.md), pressure-tested across multiple LLMs.

**GitHub Topics:** `security` `vibe-coding` `ai-security` `claude-code` `claude-skill` `owasp` `supabase` `firebase` `nextjs`

---

## How to Use This Guide

**For AI Agents/IDEs:** Copy relevant sections into your system prompt, `.cursorrules`, or project documentation folder.

**For Manual Review:** Work through each category before deploying. Items are tiered by implementation priority:
- **HIGH** — Must address before any production deployment
- **MEDIUM** — Should address before scaling or handling sensitive data
- **LOW** — Best practices for mature/enterprise applications

**Verification Principle:** If you asked the AI to implement something and it can't show you the code doing it, it probably didn't do it. Always verify.

---

## Table of Contents

0. [MVP Launch Gate](#0-mvp-launch-gate-gono-go)
1. [AI & Prompting Layer](#1-ai--prompting-layer)
2. [Secrets & Key Management](#2-secrets--key-management)
3. [Authentication & Identity](#3-authentication--identity)
4. [Authorization & Access Control](#4-authorization--access-control)
5. [Input Validation](#5-input-validation)
6. [Frontend Security](#6-frontend-security)
7. [Backend & API Security](#7-backend--api-security)
8. [Database Security](#8-database-security)
9. [Dependencies & Supply Chain](#9-dependencies--supply-chain)
10. [Infrastructure & Deployment](#10-infrastructure--deployment)
11. [Testing & Validation](#11-testing--validation)
12. [AI Agent Security](#12-ai-agent-security)
13. [Monitoring & Incident Response](#13-monitoring--incident-response)
14. [Compliance Considerations](#14-compliance-considerations)
15. [Quick Reference Prompts](#15-quick-reference-prompts)

---

## 0. MVP Launch Gate (Go/No-Go)

> **If you do nothing else, do this.** These are the top vibe coding failure modes.

### HIGH (Non-negotiable before launch)

- [ ] **Secrets are not in code or client bundles** — No API keys in frontend/mobile apps (except truly public keys). `.env` is gitignored; secret scanning is on.
- [ ] **Auth is real + session storage is safe** — Cookies are `HttpOnly`, `Secure`, `SameSite`. No auth tokens in `localStorage` for web.
- [ ] **Object-level authorization is enforced everywhere** — You cannot "ID swap" (`/users/123` → `/users/124`) to access others' data.
- [ ] **BaaS policies / RLS are enabled and tested** — Supabase/Postgres RLS or Firebase rules are explicit and validated by tests.
- [ ] **Input validation exists server-side** — Schema validation for every write endpoint.
- [ ] **Rate limiting on sensitive endpoints** — Login, signup, password reset, OTP, webhook endpoints.
- [ ] **File uploads are constrained** — Size/type limits + non-executable storage + randomized names.
- [ ] **Error handling does not leak internals** — No stack traces, SQL errors, or secrets in client responses.

### MEDIUM (Strongly recommended)

- [ ] WAF/CDN protections for public apps (bot/abuse control)
- [ ] Dependabot/Renovate + CI checks for critical CVEs
- [ ] Backups + restore tested (at least once)
- [ ] Basic monitoring + alerting (auth failures, spikes, 5xx errors)

---

## 1. AI & Prompting Layer

> **Research shows that targeted security prompting reduces insecure code generation by 30-50%** (Databricks AI Red Team, 2025). Top foundation models generate at least 36% insecure code by default (BaxBench).

### HIGH Priority

- [ ] **Use Security-Focused System Prompts** — Start sessions with security context: *"You are a security-conscious developer. Prioritize input validation, use parameterized queries, avoid hardcoding secrets, and follow the principle of least privilege."*

- [ ] **Apply Self-Reflection After Code Generation** — After AI generates complex code, prompt: *"Review your last output for security vulnerabilities including injection flaws, improper error handling, hardcoded secrets, and insecure data handling."* This technique reduced vulnerabilities by 48-50% in testing.

- [ ] **Audit for Package Hallucination** — AI often hallucinates npm/pip packages that *sound* real but don't exist. Attackers register these names (typosquatting). Never run `npm install` or `pip install` on an AI-generated list without verifying each package exists on npmjs.com/pypi.org with downloads/history.

- [ ] **Verify AI Didn't Skip Security** — LLMs optimize for "working code," not secure code. Explicitly ask: *"Show me where input validation happens"* or *"How are you preventing SQL injection here?"*

- [ ] **Avoid Unsafe Serialization** — Never accept AI code using Python's `pickle`, PHP's `unserialize()`, or Java's native serialization for untrusted data. Force JSON or other safe formats.

### MEDIUM Priority

- [ ] **Prevent Context Window Leaks** — Copy-pasting entire files into LLMs often accidentally includes hardcoded secrets or PII. Use `.cursorignore` or equivalent to prevent your IDE AI from indexing `.env` files or test data containing real customer info.

- [ ] **Prevent Logic-Washing** — AI is great at syntax, terrible at business consequence. Prompt check: *"Review the payment flow. Is there any path where the state updates to 'paid' BEFORE the Stripe webhook returns success?"*

- [ ] **Use IDE Security Integrations** — Configure `.cursorrules` with security requirements. Integrate static analysis (Semgrep, Snyk) into agentic workflows.

- [ ] **Review AI-Generated Dependencies** — AI may suggest outdated or vulnerable packages. Verify package names (typosquatting is common). Check last update date and maintenance status.

### LLM/AppSec (if your app uses LLMs, RAG, or tool calling)

- [ ] **Treat prompts + retrieved docs as untrusted input** — Prompt injection is "XSS for LLM logic"
- [ ] **Tool/function calling must be allowlisted** — Only allow explicit actions; deny dangerous tools by default (filesystem write, arbitrary HTTP to internal networks, shell exec)
- [ ] **Constrain tool parameters** — Allowlist domains, enforce timeouts, block link-local + metadata IPs
- [ ] **Prevent data exfiltration** — Don't pass secrets into prompts; redact logs; prevent LLM from returning raw PII
- [ ] **Output handling** — LLM output is untrusted; encode/escape before rendering (prevents XSS via model output)

### LOW Priority

- [ ] **Maintain Security Prompt Library** — Build reusable prompts for your common patterns. Version control your system prompts alongside code.
- [ ] **Document AI Decisions** — Note when AI made security-relevant architectural choices for audits and future maintenance.

---

## 2. Secrets & Key Management

> **The #1 cause of vibe coding breaches is exposed API keys.** If a key is hidden by default in a dashboard (requires "Reveal" click), it's secret.

### HIGH Priority

- [ ] **Never Hardcode Secrets** — Search codebase for: `sk_`, `api_key`, `secret`, `password`, `token`, `private`, `BEGIN PRIVATE KEY`

- [ ] **Use Environment Variables** — Store in `.env` files (excluded from git). Platform secrets: Replit Secrets, Vercel Environment Variables, AWS Secrets Manager

- [ ] **Verify .gitignore Includes**
  ```
  .env
  .env.local
  .env*.local
  *.pem
  *.key
  secrets/
  credentials/
  ```

- [ ] **Understand Key Types**
  | Key Type | Exposure Risk | Where to Use |
  |----------|--------------|--------------|
  | Publishable/Anon (Stripe `pk_`, Supabase `anon`) | Safe for frontend | Client-side |
  | Secret/Service Role | **Never expose** | Backend only |
  | API Keys (OpenAI, etc.) | **Never expose** | Backend only |

- [ ] **Rotate Compromised Keys Immediately** — If accidentally committed, rotate even if you force-pushed removal. Git history preserves secrets.

### MEDIUM Priority

- [ ] **Separate Development/Production Keys** — Use different API keys per environment
- [ ] **Implement Key Rotation Schedule** — Rotate secrets periodically (90 days recommended)
- [ ] **Audit Third-Party Access** — Review OAuth app permissions; remove unused integrations
- [ ] **Set Up Key Usage Alerts** — Many providers (AWS, Stripe, OpenAI) support usage alerts

### LOW Priority

- [ ] **Use Secret Scanning Tools** — GitHub Secret Scanning, GitGuardian, TruffleHog in CI/CD
- [ ] **Implement Vault Solutions** — HashiCorp Vault, AWS Secrets Manager for enterprise

---

## 3. Authentication & Identity

> **Never roll your own auth crypto.** Use battle-tested libraries and providers.

### HIGH Priority

- [ ] **Use Established Auth Providers** — Clerk, Auth0, Supabase Auth, Firebase Auth, NextAuth.js, Replit Auth

- [ ] **Secure Password Storage (if handling passwords)** — Use bcrypt, Argon2, or scrypt — **never** plain text, MD5, or SHA1

- [ ] **Implement Secure Session Management** — Use `HttpOnly`, `Secure`, `SameSite=Strict` cookie flags. Regenerate session ID after login.

- [ ] **Protect Authentication Endpoints** — Rate limit login attempts (5-10 per minute per IP). Implement account lockout after failures. Use CAPTCHA for signup/login.

### MEDIUM Priority

- [ ] **Implement Multi-Factor Authentication (MFA)** — Especially for admin accounts. TOTP or WebAuthn/Passkeys.
- [ ] **Secure Password Reset Flow** — Time-limited tokens (15-60 minutes), single-use, don't reveal if email exists
- [ ] **JWT Best Practices** — Use strong secrets (256+ bits), validate `iss`/`aud`/`exp`, never use `alg: none`, don't store sensitive data in payload
- [ ] **Secure OAuth Implementation** — Always validate `state` parameter (CSRF), validate redirect URIs strictly, use PKCE for public clients

### LOW Priority

- [ ] **Implement Passwordless Options** — Magic links, WebAuthn, passkeys
- [ ] **Add Login Anomaly Detection** — Flag logins from new devices/locations

---

## 4. Authorization & Access Control

> **Most MVP breaches are authorization failures, not authentication failures.** This is where most vibe coding vulnerabilities occur.

### HIGH Priority

- [ ] **Enable Row Level Security (RLS)** — Supabase: Enable RLS on ALL tables. Policy-less tables = no access (secure default when RLS enabled).

- [ ] **Implement Proper RLS Policies**
  ```sql
  -- Basic patterns:
  -- 1. Public read: USING (true)
  -- 2. Owner only: USING (auth.uid() = user_id)
  -- 3. No access: (no policy = denied when RLS enabled)
  -- NEVER: USING (true) for INSERT/UPDATE/DELETE without ownership
  ```

- [ ] **Test the "ID Swap" Attack** — Can User A access User B's data by changing IDs in URLs/requests? Every endpoint must verify ownership.

- [ ] **Verify Authorization on Every Request** — Backend must check permissions, not just frontend. Frontend checks are for UX, backend checks are for security.

- [ ] **Prevent Mass Assignment** — Never blindly assign user input to model fields. Explicitly allowlist updateable fields.

### MEDIUM Priority

- [ ] **Implement Role-Based Access Control (RBAC)** — Define clear roles (admin, user, viewer). Check roles server-side.
- [ ] **Protect Sensitive Operations** — Admin functions require admin role. Destructive actions require confirmation.
- [ ] **Use Supabase Security Advisor** — Dashboard → Advisor → Security. Note: Advisor doesn't catch all issues.
- [ ] **Prevent Privilege Escalation** — Users cannot modify their own roles. Role changes require admin privileges.

### LOW Priority

- [ ] **Implement Attribute-Based Access Control (ABAC)** — For complex permission scenarios
- [ ] **Add Resource-Level Permissions** — Granular control (read, write, delete, share)

---

## 5. Input Validation

> **Server-side validation is mandatory.** Client-side validation is for UX only.

### HIGH Priority

- [ ] **Validate All Inputs Server-Side** — Use schema validation (Zod, Joi, Pydantic). Validate type, length, format, range.
  ```typescript
  // Example with Zod
  const UserSchema = z.object({
    email: z.string().email().max(255),
    age: z.number().int().min(0).max(150),
  });
  ```

- [ ] **Prevent SQL Injection** — Use ORMs (Prisma, Drizzle, SQLAlchemy) or parameterized queries. **Never** concatenate user input into SQL strings.
  ```python
  # Bad
  cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

  # Good
  cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
  ```

- [ ] **Prevent NoSQL Injection** — MongoDB: Avoid operators in user input (`$where`, `$regex`, etc.). Validate input types strictly.
  ```javascript
  // Bad - allows operator injection
  db.users.find({ username: req.body.username });
  // If req.body.username = { "$gt": "" } -> returns all users

  // Good - ensure string type
  const username = String(req.body.username);
  ```

- [ ] **Sanitize User Input Before Rendering** — Prevent XSS with DOMPurify or framework escaping

### MEDIUM Priority

- [ ] **File Upload Security** — Validate file types server-side (check magic bytes, not just extension). Set size limits. Store outside web root. Generate random filenames.
- [ ] **Prevent Path Traversal** — Sanitize file paths. Don't use user input directly in file operations.

---

## 6. Frontend Security

> **The browser is hostile territory.** Assume everything client-side can be viewed and manipulated.

### HIGH Priority

- [ ] **HTTPS Everywhere** — Verify custom domains have SSL. Redirect HTTP → HTTPS.

- [ ] **Prevent Cross-Site Scripting (XSS)** — Use framework escaping (React auto-escapes JSX). Avoid `dangerouslySetInnerHTML`, `innerHTML`, `eval()`
  ```javascript
  // Bad
  element.innerHTML = userInput;

  // Good
  import DOMPurify from 'dompurify';
  element.innerHTML = DOMPurify.sanitize(userInput);
  ```

- [ ] **No Secrets in Client Code** — Only publishable keys (Stripe `pk_`, Supabase `anon`) allowed. Check bundled code.

- [ ] **Don't Store Sensitive Data in Browser** — Avoid localStorage/sessionStorage for tokens, PII. Use `HttpOnly` cookies.

- [ ] **Next.js/React Server Component (RSC) Leaks** — Don't accidentally pass server-side objects (containing keys/secrets) to Client Components. Use the `server-only` package.

### MEDIUM Priority

- [ ] **Implement Security Headers** — Check at securityheaders.com
  ```
  Content-Security-Policy: default-src 'self'; script-src 'self'
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  Permissions-Policy: geolocation=(), microphone=(), camera=()
  ```

- [ ] **CSRF Protection** — Use anti-CSRF tokens for forms. `SameSite=Strict` cookies help.
- [ ] **Prevent Clickjacking** — Set `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`
- [ ] **Prevent Open Redirects** — Validate redirect targets against an allowlist

### LOW Priority

- [ ] **Subresource Integrity (SRI)** — Add `integrity` attribute to external scripts
- [ ] **Content Security Policy (CSP) Refinement** — Start with report-only mode, gradually tighten

---

## 7. Backend & API Security

> **Every API endpoint is an attack surface.** Treat all input as potentially malicious.

### HIGH Priority

- [ ] **Protect API Endpoints** — Require authentication for non-public endpoints. Check authorization on every request.

- [ ] **Implement Rate Limiting** — Protect login, signup, password reset, expensive endpoints.

- [ ] **Prevent Server-Side Request Forgery (SSRF)** — Never fetch arbitrary URLs provided by users. Allowlist permitted domains. Block internal IPs (127.0.0.1, 10.x, 172.16-31.x, 192.168.x, 169.254.x, ::1)

- [ ] **Audit for Shadow Routes** — AI might create routes like `/api/test/reset-db` or `/api/debug/user/{id}` and leave them in production.
  ```bash
  grep -r "router.get" . | grep -iE "test|debug|temp"
  ```

- [ ] **Secure Error Handling** — Don't expose stack traces, file paths, or SQL errors. Log detailed errors server-side, return generic messages to clients.

### MEDIUM Priority

- [ ] **Configure CORS Properly** — Don't use `*` for credentials requests. Whitelist specific origins.
- [ ] **Webhook Security** — Validate signatures (Stripe, GitHub, etc.). Handle idempotently. Implement replay protection.
- [ ] **Prevent Host Header Injection** — Validate Host header against allowlist. Don't use Host header for generating URLs in emails.

### LOW Priority

- [ ] **API Versioning** — `/api/v1/` prefix
- [ ] **Idempotency Keys** — For payment and critical operations

---

## 8. Database Security

> **Your database is your crown jewels.** Defense in depth applies here.

### HIGH Priority

- [ ] **Use Parameterized Queries/ORMs** — Never construct SQL with string concatenation
- [ ] **Principle of Least Privilege** — Application database users should have minimal permissions. Don't use root/admin credentials.
- [ ] **Enable RLS (Supabase/Postgres)** — Test policies thoroughly
- [ ] **Secure Connection Strings** — Use SSL/TLS. Connection strings in environment variables only.

### MEDIUM Priority

- [ ] **Encrypt Sensitive Data at Rest** — PII, financial data, health records
- [ ] **Regular Backups** — Automated daily minimum. Test restore procedures.
- [ ] **Database-Level Audit Logging** — Log access to sensitive tables

### LOW Priority

- [ ] **Database Firewall Rules** — Restrict IP access to known sources
- [ ] **Query Performance Monitoring** — Detect anomalous query patterns

---

## 9. Dependencies & Supply Chain

> **Your app is only as secure as its weakest dependency.**

### HIGH Priority

- [ ] **Audit Dependencies Regularly**
  ```bash
  npm audit
  pip-audit
  yarn audit
  ```

- [ ] **Keep Dependencies Updated** — Security patches especially. Use Dependabot, Renovate, or Snyk.

- [ ] **Verify Package Authenticity** — Check package names carefully (typosquatting: `lodash` vs `1odash`). Verify publisher/maintainer.

- [ ] **Lock Dependency Versions** — Use lockfiles (`package-lock.json`, `yarn.lock`). Commit to version control.

- [ ] **Lockfile Poisoning Check** — If AI agent fixes build errors, it might force-update dependencies or delete your lockfile. Treat lockfile changes as code changes. Review diffs manually.

### MEDIUM Priority

- [ ] **Review New Dependencies** — Check GitHub stars, issues, maintenance activity
- [ ] **Minimize Dependencies** — Each dependency is a potential vulnerability
- [ ] **CI Hardening** — No untrusted PRs running with secret access; protect main branch

### LOW Priority

- [ ] **Software Composition Analysis (SCA)** — Snyk, OWASP Dependency-Check in CI/CD
- [ ] **Private Package Registry** — For enterprise: internal package management

---

## 10. Infrastructure & Deployment

> **Secure code can still be deployed insecurely.**

### HIGH Priority

- [ ] **Separate Environments** — Dev, Staging, Production with different credentials
- [ ] **HTTPS/TLS in Production** — Use TLS 1.2+ only
- [ ] **DDoS Protection** — Use platforms with built-in protection (Cloudflare, Vercel, AWS)
- [ ] **Secure CI/CD Pipeline** — Store secrets in CI/CD secrets manager. Don't print secrets in logs.

### MEDIUM Priority

- [ ] **Infrastructure as Code (IaC) Security** — Scan Terraform, CloudFormation. Use Checkov, tfsec.
- [ ] **Container Security** — Use official base images. Don't run as root. Scan images.
- [ ] **Network Security** — Restrict ports. Use VPCs/private networks.

### LOW Priority

- [ ] **Immutable Infrastructure** — Replace rather than patch
- [ ] **Disaster Recovery Plan** — Document recovery procedures. Regular DR testing.

---

## 11. Testing & Validation

> **Test like an attacker.** If you don't find the bugs, someone else will.

### HIGH Priority

- [ ] **Test Authorization Bypass** — Log in as User A, try to access User B's resources. Test with missing/expired/invalid tokens.

- [ ] **Test Input Validation** — Empty values, extremely long strings, special characters, SQL injection payloads, boundary values

- [ ] **Verify RLS Policies with Automated Tests**
  ```typescript
  describe('RLS Policies', () => {
    it('user cannot update another user profile', async () => {
      await signIn(userA);
      await insertProfile(userA);
      await signOut();
      await signIn(userB);
      const result = await updateProfile(userA.id, { name: 'hacked' });
      const profile = await getProfile(userA.id);
      expect(profile.name).not.toBe('hacked');
    });
  });
  ```

### MEDIUM Priority

- [ ] **Static Application Security Testing (SAST)** — Semgrep, CodeQL, Bandit (Python) in PR workflow
- [ ] **Security Regression Tests** — Test for previously found vulnerabilities

### LOW Priority

- [ ] **Penetration Testing** — Professional assessment for production apps
- [ ] **Dynamic Application Security Testing (DAST)** — OWASP ZAP, Burp Suite

---

## 12. AI Agent Security

> **24/7 AI agents with system access present unique security challenges.**

### HIGH Priority

- [ ] **Apply Least Privilege to AI Agents** — Limit file/network access. Define explicit permission matrices.
- [ ] **Define Credential Boundaries** — Map all credentials the agent can access. Minimize blast radius.
- [ ] **Require Human Confirmation for High-Impact Actions** — File deletion, external API calls, credential access, payment operations

### MEDIUM Priority

- [ ] **Sandbox Agent Execution** — Use Docker or similar containerization
- [ ] **Audit Agent Actions** — Log all agent actions (without logging sensitive data)
- [ ] **Memory Hygiene** — Audit accumulated context for sensitive data

See **[AI Agent Security](./ai-agent-security.md)** for expanded guidance on MoltBot, Claude Code, and agentic workflows.

---

## 13. Monitoring & Incident Response

> **Assume breach.** You need to know when it happens and respond quickly.

### HIGH Priority

- [ ] **Enable Logging** — Authentication events, authorization failures, API errors. Don't log sensitive data.
- [ ] **Set Up Alerts** — Multiple failed login attempts, unusual API patterns, error rate spikes

### MEDIUM Priority

- [ ] **Create Incident Response Plan** — Contact information, containment procedures, communication templates
- [ ] **Regular Log Review** — Weekly at minimum

### LOW Priority

- [ ] **SIEM Implementation** — Centralized log analysis, automated threat detection
- [ ] **User Behavior Analytics** — Detect anomalous patterns

---

## 14. Compliance Considerations

> **Design with compliance in mind**, even if not currently required.

### General Principles

- [ ] **Data Minimization** — Only collect what you need
- [ ] **User Rights** — Data export capability, account deletion (true deletion for PII), privacy policy

### Compliance Matrix

| Requirement | GDPR | HIPAA | SOC 2 | PCI-DSS |
|-------------|------|-------|-------|---------|
| Encryption at rest | Yes | Yes | Yes | Yes |
| Encryption in transit | Yes | Yes | Yes | Yes |
| Access controls | Yes | Yes | Yes | Yes |
| Audit logging | Yes | Yes | Yes | Yes |
| Data retention policy | Yes | Yes | Yes | Yes |
| Breach notification | Yes | Yes | Yes | Yes |
| User consent | Yes | Varies | - | - |
| Right to erasure | Yes | - | - | - |
| Penetration testing | - | - | Yes | Yes |

---

## 15. Quick Reference Prompts

### Security-Focused System Prompt

```
You are a security-conscious developer. Follow these principles:
1. Validate and sanitize all user inputs on the backend
2. Use parameterized queries or ORMs for database operations
3. Never hardcode secrets—use environment variables
4. Apply the principle of least privilege for access control
5. Handle errors gracefully without exposing sensitive details
6. Use established libraries for authentication and cryptography
7. Protect against SSRF when handling user-provided URLs
8. Use secure random number generation for tokens and secrets
```

### Self-Reflection Prompt (Post-Generation)

```
Review the code you just generated for:
1. SQL/NoSQL injection vulnerabilities
2. XSS vulnerabilities
3. SSRF vulnerabilities (fetching user-provided URLs)
4. Hardcoded secrets or sensitive data
5. Missing input validation
6. Improper error handling that leaks information
7. Missing authentication or authorization checks
8. Insecure direct object references (IDOR)
9. Race conditions in multi-step operations
10. Mass assignment vulnerabilities

For each issue found, explain the vulnerability and provide a fix.
```

### AI Security Self-Audit Prompt

```
Act as a hostile security auditor. Scan this codebase for "Vibe Coding" vulnerabilities:

1. Shadow Routes: Are there any /test, /debug, or commented-out routes actually active?
2. Hardcoded Secrets: Look for strings resembling keys (sk_, eyJ, etc.) even in comments.
3. Mass Assignment: Do update endpoints accept req.body directly without filtering keys?
4. Client-Side Trust: Are we trusting localStorage or cookies for permission checks?
5. Hallucinated Packages: Flag any obscure or "testing" packages in production deps.

Output a report in Markdown with High, Medium, and Low risk findings.
```

### Supabase RLS Review Prompt

```
Review my Supabase RLS policies for security issues:
1. Are there any tables with RLS disabled?
2. Do any INSERT/UPDATE/DELETE policies use 'true' without ownership checks?
3. Can users access other users' data by manipulating IDs?
4. Are there missing policies for any CRUD operations?
5. Can users escalate their own privileges?

Provide specific policy corrections if issues are found.
```

---

## Pre-Flight Security Checklist

> **2-minute deployment sanity check**

```
[ ] Secrets
    [ ] No API keys in code (grep -r "sk_\|api_key\|secret" .)
    [ ] .env in .gitignore
    [ ] Environment variables set in hosting platform

[ ] Authentication
    [ ] Login rate limited
    [ ] Sessions expire appropriately
    [ ] Logout works (session destroyed)

[ ] Authorization
    [ ] RLS enabled on all tables (Supabase/Postgres)
    [ ] Tested "ID swap" attack
    [ ] Admin functions require admin role

[ ] Inputs
    [ ] Server-side validation on all endpoints
    [ ] File uploads validated (type, size)
    [ ] No raw user input in SQL/shell/HTML

[ ] Outputs
    [ ] Errors don't leak stack traces
    [ ] AI output sanitized before display

[ ] HTTPS
    [ ] Site loads over HTTPS
    [ ] HTTP redirects to HTTPS

[ ] Headers (check at securityheaders.com)
    [ ] X-Frame-Options set
    [ ] Content-Type-Options: nosniff
```

---

## Expand Further

- **[Stack-Specific Security](./stack-specific-security.md)** — Supabase, Next.js, Firebase, Docker, Stripe, React Native, and more
- **[AI Agent Security](./ai-agent-security.md)** — MoltBot, Claude Code, agentic principles deep dive
- **[Sources](./sources.md)** — Research and references used to build this guide

---

## Claude Code Skill

This guide is available as a Claude Code skill with the following commands:

| Command | Behavior |
|---------|----------|
| `/check-your-vibe:review` | Run a structured security audit against vibe-coding-specific vulnerabilities |
| `/check-your-vibe:preflight` | Interactive pre-deployment security gate with go/no-go questions |
| `/check-your-vibe:mode` | Inject security-conscious coding principles into the current session |

### Installation

Copy the `check-your-vibe` skill folder to your Claude Code skills directory:

```bash
# macOS/Linux
cp -r check-your-vibe ~/.claude/skills/

# Windows
xcopy /E check-your-vibe %USERPROFILE%\.claude\skills\check-your-vibe\
```

Or clone directly from the repository:

```bash
git clone https://github.com/BTECHK/vibe-coded-vibe-code-security-guide.git
cp -r vibe-coded-vibe-code-security-guide/check-your-vibe ~/.claude/skills/
```

---

## Contributing

This is a personal learning project, but suggestions are welcome. Open an issue or PR if you have improvements.

---

## License

MIT License — Use freely, but security is your responsibility.

---

> **Remember:** Security is a process, not a destination. This checklist is a starting point, not a guarantee. Stay curious, stay paranoid, and always verify.
