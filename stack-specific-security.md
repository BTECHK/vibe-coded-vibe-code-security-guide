# Stack-Specific Security [In Progress]

Technology-specific security guidance for common vibe code stacks.

---

## Table of Contents

- [Supabase](#supabase)
- [Firebase](#firebase)
- [Next.js](#nextjs)
- [React Native & Expo](#react-native--expo)
- [Docker](#docker)
- [Stripe](#stripe)
- [Auth Providers](#auth-providers)
- [ORMs (Prisma, Drizzle)](#orms)
- [AI SDKs & LLM Integration](#ai-sdks--llm-integration)
- [Hosting Platforms](#hosting-platforms)

---

## Supabase

<!-- TODO: Consolidate from stack consideration docs -->

### 🔴 HIGH Priority
- [ ] Enable RLS on ALL tables — tables without RLS allow full public access with anon key
- [ ] Never expose Service Role Key in frontend — backend only
- [ ] Write explicit policies for SELECT, INSERT, UPDATE, DELETE
- [ ] Use `auth.uid()` to restrict access to owner's data

### 🟡 MEDIUM Priority
- [ ] Check Dashboard → Advisor → Security regularly
- [ ] Store Edge Function secrets in function secrets manager
- [ ] Audit database functions with `SECURITY DEFINER`

---

## Firebase

<!-- TODO: Consolidate from stack consideration docs -->

### 🔴 HIGH Priority
- [ ] Security Rules — test in Rules Playground before deploying
- [ ] Never use default "test mode" rules in production
- [ ] Storage rules — validate file types and sizes

### 🟡 MEDIUM Priority
- [ ] Use custom claims for RBAC
- [ ] Enable App Check
- [ ] Admin SDK — server-side only, never expose service account

---

## Next.js

<!-- TODO: Consolidate from stack consideration docs -->

### 🔴 HIGH Priority
- [ ] Server Actions — always validate auth and inputs
- [ ] Understand client vs server boundaries
- [ ] Never put secrets in `NEXT_PUBLIC_` variables

### 🟡 MEDIUM Priority
- [ ] Configure middleware for auth checks
- [ ] Prevent open redirects
- [ ] Review image optimization for SSRF risks

---

## React Native & Expo

<!-- TODO: Consolidate from stack consideration docs -->

### 🔴 HIGH Priority
- [ ] Use Expo SecureStore, not AsyncStorage for sensitive data
- [ ] Implement certificate pinning for API calls
- [ ] Validate deep links

### 🟡 MEDIUM Priority
- [ ] Prevent screenshot in sensitive screens
- [ ] Handle app backgrounding (clear sensitive data from memory)

---

## Docker

<!-- TODO: Consolidate from stack consideration docs -->

### 🔴 HIGH Priority
- [ ] Don't run containers as root
- [ ] Never put secrets in Docker images
- [ ] Use multi-stage builds to minimize attack surface

### 🟡 MEDIUM Priority
- [ ] Scan images for vulnerabilities
- [ ] Use `.dockerignore` to exclude sensitive files
- [ ] Pin base image versions

---

## Stripe

<!-- TODO: Consolidate from stack consideration docs -->

### 🔴 HIGH Priority
- [ ] Validate webhook signatures
- [ ] Keep pricing logic server-side
- [ ] Use idempotency keys for payment operations

### 🟡 MEDIUM Priority
- [ ] Verify payment status before fulfilling orders
- [ ] Use Stripe's test mode for development (separate keys)

---

## Auth Providers

<!-- TODO: Consolidate Clerk, NextAuth, Lucia specifics -->

### Clerk
- [ ] Configure allowed redirect URLs
- [ ] Review webhook security

### NextAuth.js
- [ ] Set `NEXTAUTH_SECRET` properly
- [ ] Configure CSRF protection
- [ ] Review provider-specific security settings

### Lucia
- [ ] Understand session management model
- [ ] Configure secure cookie settings

---

## ORMs

<!-- TODO: Consolidate Prisma, Drizzle specifics -->

### Prisma
- [ ] Avoid `$queryRaw` with user input
- [ ] Review mass assignment risks

### Drizzle
- [ ] Same raw query cautions
- [ ] Validate inputs before queries

---

## AI SDKs & LLM Integration

<!-- TODO: Consolidate from stack consideration docs -->

### 🔴 HIGH Priority
- [ ] Proxy API calls through your backend (never expose API keys to client)
- [ ] Implement cost controls and rate limiting
- [ ] Guard against prompt injection

### 🟡 MEDIUM Priority
- [ ] Track token usage
- [ ] Sanitize LLM outputs before rendering
- [ ] Review LangChain agent permissions if using agents

---

## Hosting Platforms

### Vercel
- [ ] Use platform secrets manager for environment variables
- [ ] Review preview deployment security (different context)
- [ ] Serverless functions are public endpoints — validate all inputs

### Netlify
- [ ] Same environment variable guidance
- [ ] Review function permissions

### Replit
- [ ] Use Replit Secrets for all API keys
- [ ] Replit Auth handles auth securely out of the box
- [ ] Deployments include DDoS protection

### Railway / Render / Fly.io
- [ ] Review platform-specific secret management
- [ ] Configure network restrictions where available
