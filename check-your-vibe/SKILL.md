---
name: check-your-vibe
description: Use when reviewing vibe-coded apps for security, before deployment, or when coding with AI assistance. Covers RLS, secrets exposure, IDOR, shadow routes, and AI agent vulnerabilities common in rapid AI-assisted development.
---

# Vibe Security

Security audit and guidance for vibe-coded applications built with AI assistance.

## Commands

### :review - Security Audit

Structured security audit against vibe-coding-specific vulnerabilities.

**Workflow:**
1. Detect stack (Supabase, Firebase, Next.js, etc.)
2. Run HIGH priority checks first - **must execute verification commands**
3. Output findings by severity
4. Do not claim "secure" without running verification

**CRITICAL**: You must RUN the verification commands, not just mention them. "I would check..." is not a check.

**HIGH Priority Checks (must verify explicitly):**

| Check | What to Look For | Verification |
|-------|------------------|--------------|
| Secrets in client | Service keys in frontend bundle | `grep -r "service_role\|sk_live\|PRIVATE" src/` |
| RLS policies | Tables without policies = public data | See RLS verification below |
| IDOR vulnerabilities | Can user A access user B's data? | Manual ID swap test |
| Shadow routes | AI-generated `/admin`, `/debug`, `/test` | `grep -r "admin\|debug\|test" src/pages src/app` |
| localStorage tokens | Auth tokens accessible to XSS | `grep -r "localStorage.*token\|localStorage.*auth"` |
| Rate limiting | Auth/sensitive endpoints unprotected | `grep -rE "rateLimit\|throttle" src/` + check package.json |
| File upload limits | No size/type constraints on uploads | `grep -rE "multer\|upload" src/` then check for limits |
| Error leakage | Stack traces or SQL errors in responses | `grep -rE "\.stack\|error\.message" src/` in catch blocks |

**RLS Verification (Supabase/Postgres):**
```sql
-- List tables without RLS
SELECT schemaname, tablename
FROM pg_tables
WHERE schemaname = 'public'
AND tablename NOT IN (
  SELECT tablename FROM pg_policies WHERE schemaname = 'public'
);

-- Test policy: Can I read another user's data?
-- Run as authenticated user, try to SELECT with different user_id
```

**IDOR Test Pattern:**
1. Log in as User A
2. Find a resource ID (e.g., `/api/orders/123`)
3. Log in as User B
4. Request User A's resource ID
5. If data returns = CRITICAL vulnerability

**Rate Limiting Verification:**
1. Search for rate limiting: `grep -rE "rateLimit|throttle|RateLimiter" src/`
2. Check dependencies: Look for `express-rate-limit`, `@nestjs/throttler`, `slowapi`, `flask-limiter`
3. Find unprotected auth endpoints: `grep -rE "login|signup|password-reset|otp|webhook" src/app src/pages`
4. Verify limits are reasonable (5-10 attempts per minute for login)
5. Red flags: Auth endpoints with no rate limiting imports nearby, missing rate-limit package

**File Upload Verification:**
1. Find upload handlers: `grep -rE "multer|formidable|busboy|upload|multipart" src/`
2. Check for size limits: `grep -rE "maxFileSize|fileSizeLimit|limits.*size" src/`
3. Verify file type validation exists (magic bytes, not just extension)
4. Ensure filenames are randomized, not user-controlled
5. Confirm storage is outside web root or in cloud storage
6. Red flags: Upload handlers without `limits` or `fileFilter`, original filenames used directly

**Error Handling Verification:**
1. Find catch blocks: `grep -rE "catch.*\{" src/ -A 5`
2. Look for stack trace exposure: `grep -rE "\.stack|error\.message" src/`
3. Check for debug mode: `grep -rE "DEBUG=true|NODE_ENV.*development" src/ .env*`
4. Find raw error passing: `grep -rE "res\.status\(500\)\.json\(\{.*error" src/`
5. Verify generic error messages in production
6. Red flags: `catch (e) { res.json({ error: e.message })` patterns, `DEBUG=true` in production

**Output Format:**
```
## Security Audit Results

### HIGH (Fix before deploy)
- [ ] Finding 1...

### MEDIUM (Fix soon)
- [ ] Finding 2...

### LOW (Consider fixing)
- [ ] Finding 3...
```

---

### :preflight - Pre-deployment Gate

Interactive checklist before deploying to production.

**Go/No-Go Questions:**

1. **Secrets**: "Show me your .gitignore - is .env listed? Show me frontend bundle - any API keys?"
2. **RLS**: "Run the RLS verification query. Any tables listed?"
3. **Auth storage**: "Where are auth tokens stored? localStorage = No-Go"
4. **IDOR test**: "Pick any user-owned resource. Can you access it as another user?"
5. **Shadow routes**: "Search for /admin, /debug, /test in your routes"
6. **Error responses**: "Trigger an error. Does it show stack trace or SQL?"

**Stack-specific checks:**

- **Supabase**: RLS enabled? Service key only on server?
- **Firebase**: Security rules configured? Not `allow read, write: if true`?
- **Next.js**: API routes protected? Middleware checking auth?
- **Vercel**: Environment variables set? Not hardcoded?

**Gate result**: All HIGH items must pass or deployment blocked.

---

### :mode - Security-Conscious Coding

Inject security principles into the current session.

**Active checks during code generation:**

1. **Every API route**: Does it verify the user owns the requested resource?
2. **Every form**: Is there server-side validation, not just client?
3. **Every secret**: Is it in environment variable, not code?
4. **Every file upload**: Size limit? Type check? Randomized name?
5. **Every database query**: Parameterized? RLS will filter?

**On each code block generated, ask:**
- "Could a malicious user exploit this by changing IDs?"
- "What happens if input is 10MB? What if it's script tags?"
- "Is this secret safe to expose in browser?"

---

## AI Agent Security

When reviewing or building AI agents:

| Risk | Check |
|------|-------|
| Tool over-permission | Does agent have minimal required tools? |
| Credential scope | Can agent access more than needed? |
| Prompt injection | Is user input ever in system prompt? |
| Confirmation gates | High-impact actions require human approval? |
| MCP server trust | Which servers have write access? |

---

## Rationalizations to Reject

| Excuse | Reality |
|--------|---------|
| "Looks secure enough" | Must verify each HIGH item explicitly with commands |
| "AI said it's secure" | AI-generated security claims require verification |
| "I'll add auth later" | Auth-after = data breach before |
| "Only I use this app" | URLs get shared; bots scan everything |
| "RLS is probably on" | "Probably" = definitely check |
| "That route is hidden" | Hidden != protected; bots find everything |

---

## Red Flags - Stop and Fix

- Tables without RLS policies
- Service keys in client bundle
- `localStorage.setItem('token', ...)`
- API routes with no auth check
- `/admin` or `/debug` routes without protection
- Error responses with stack traces
- File uploads without type/size limits

If any red flag found, fix before continuing.

---

## Quick Reference

**Minimum viable security:**
1. Secrets in env vars only
2. RLS on all tables
3. Auth tokens in httpOnly cookies
4. Server-side validation on all inputs
5. IDOR test passes
6. No shadow admin routes

**Source**: [Vibe Code Security Guide](https://github.com/BTECHK/vibe-coded-vibe-code-security-guide)
