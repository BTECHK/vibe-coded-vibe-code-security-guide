# Sources

Research and references used to build this security guide.

---

## Primary Research

### Academic & Industry Research

- **Databricks AI Red Team** — "Passing the Security Vibe Check: The Dangers of Vibe Coding"
  - https://www.databricks.com/blog/passing-security-vibe-check-dangers-vibe-coding
  - Key finding: Security-focused prompting reduces insecure code generation by 30-50%

- **BaxBench** — AI Code Security Benchmark
  - Finding: Top foundation models generate at least 36% insecure code by default

- **Google Secure AI Framework (SAIF)**
  - https://cloud.google.com/blog/products/identity-security/introducing-googles-secure-ai-framework
  - Enterprise framework for securing AI systems

### Platform Documentation

- **Replit Security Checklist**
  - https://docs.replit.com/tutorials/vibe-code-security-checklist
  - Official vibe coding security guidance from Replit

- **Supabase Security Documentation**
  - https://supabase.com/docs/guides/auth/row-level-security
  - Row Level Security patterns and best practices

- **Firebase Security Rules Guide**
  - https://firebase.google.com/docs/rules
  - Firestore and Storage security rules

---

## Video Resources

### Vibe Code Security

- **"Secure Your App: Fundamentals of App Security for Vibe Coding"** — Supabase
  - https://youtu.be/0RUBfAKLlf8
  - RLS fundamentals, common mistakes, testing strategies

- **"16 Ways to Vibe Code Securely"** — Matt Palmer (Replit)
  - https://youtu.be/0D9FMFyNBWo
  - Practical security checklist from Replit's security team

### AI Agent Security

- **"Why Most AI Agents Are a Security Risk"** — Web Dev Cody
  - https://www.youtube.com/watch?v=mvq1146ThIk
  - Docker sandboxing, volume mounts, agent isolation

- **"Securing AI Systems: Protecting Data, Models, & Usage"** — IBM Technology
  - https://www.youtube.com/watch?v=2A94Mxn3jAc
  - "Donut of defense" model: Discover, Assess, Control, Report

- **"Data Security with AI Powered Agents"** — Google Cloud Tech
  - https://www.youtube.com/watch?v=J4Naxhm9y5g
  - Sensitive Data Protection, DLP API, output filtering

- **"n8n Webhook Security: A Deep Dive"** — Bart Slodyczka
  - https://www.youtube.com/watch?v=sQn6W2SJWwY
  - Server, webhook, and workflow security layers

---

## PDF Documents

### Google Cloud Security

- **"Best Practices for Securing AI Deployments on Google Cloud"**
  - Infrastructure patterns for secure AI deployment
  - Network isolation and access control

- **"Secure AI Agents with Google Cloud"**
  - SAIF framework implementation
  - Agent security architecture patterns

### CrowdStrike

- **"AI Security Research Paper"**
  - Attack surface categories for AI systems
  - Defense layers and monitoring strategies

---

## GitHub Resources

- **astoj/vibe-security**
  - https://github.com/astoj/vibe-security
  - Security tools and checklists for vibe coding

- **obra/superpowers**
  - https://github.com/obra/superpowers
  - Claude skill architecture and patterns

---

## OWASP References

- **OWASP Top 10**
  - https://owasp.org/www-project-top-ten/
  - Foundation for web application security

- **OWASP Top 10 for LLM Applications**
  - https://owasp.org/www-project-top-10-for-large-language-model-applications/
  - Prompt injection, insecure output handling, supply chain

- **OWASP API Security Top 10**
  - https://owasp.org/www-project-api-security/
  - BOLA, authentication, authorization

---

## LLM Iteration

This guide was synthesized through iterative conversations with multiple LLMs:

- **Claude** (Anthropic) — Comprehensive structure, code examples, cryptography section
- **Gemini** (Google) — Package hallucination, context window leak, shadow routes
- **ChatGPT** (OpenAI) — MVP Launch Gate format, actionable checklists

Each model contributed unique perspectives that were validated and consolidated.

---

## Standards & Frameworks

- **NIST Cybersecurity Framework**
- **MITRE ATT&CK**
- **MITRE ATLAS** (Adversarial Threat Landscape for AI Systems)
- **CIS Controls**

---

## Additional Reading

### Authentication & Authorization

- Auth0 Security Best Practices
- Clerk Security Documentation
- NextAuth.js Security Considerations

### Container Security

- Docker Security Best Practices
- CIS Docker Benchmark

### Deployment Platforms

- Vercel Security Documentation
- Cloudflare Workers Security
- Railway Security Model

---

> **Back to main guide:** [README.md](./README.md)
