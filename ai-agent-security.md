# AI Agent Security [In Progress]

Security guidance for persistent AI agents, coding assistants, and agentic AI workflows.

---

## Table of Contents

- [Persistent AI Agents (MoltBot/Clawdbot)](#persistent-ai-agents-moltbotclawdbot)
- [Claude Code Security](#claude-code-security)
- [Agentic AI Security Principles](#agentic-ai-security-principles)
- [Skills & Plugin Security](#skills--plugin-security)

---

## Persistent AI Agents (MoltBot/Clawdbot)

<!-- TODO: Consolidate from moltbot consideration docs + PDFs -->

24/7 AI agents with system access present unique security challenges.

### 🔴 HIGH Priority

- [ ] **DM/Message Security** — Configure `dmPolicy` to prevent prompt injection via messaging platforms
- [ ] **Sandbox Configuration** — Use appropriate sandbox modes for group/channel isolation
- [ ] **OAuth Token Protection** — Review scope for Gmail, Calendar, and other integrations
- [ ] **Filesystem Boundaries** — Protect sensitive directories (`~/.ssh/`, `~/.aws/`, `~/.config/`)

### 🟡 MEDIUM Priority

- [ ] **Memory Hygiene** — Audit accumulated context for sensitive data
- [ ] **Browser Control Risks** — Restrict browser access in sandboxed sessions
- [ ] **Remote Gateway Security** — Use password auth for Tailscale Serve/Funnel
- [ ] **Cron/Webhook Auditing** — Review autonomous scheduled tasks
- [ ] **Agent-to-Agent Communication** — Limit `sessions_send` / `sessions_spawn` capabilities

---

## Claude Code Security

<!-- TODO: Consolidate from moltbot consideration docs -->

Terminal-based AI coding assistant security considerations.

### 🔴 HIGH Priority

- [ ] **CLAUDE.md Safety** — Keep coding standards in CLAUDE.md, never secrets
- [ ] **MCP Server Controls** — Set `enableAllProjectMcpServers: false`, use explicit allowlists
- [ ] **Dangerous Command Blocking** — Deny rules for `curl`, `wget`, direct `.env` access

### 🟡 MEDIUM Priority

- [ ] **Hooks vs CLAUDE.md** — Hooks are deterministic enforcement; CLAUDE.md is suggestions
- [ ] **Skill Auditing** — Review all `SKILL.md` and bundled scripts before installation
- [ ] **Transcript Retention** — Use short retention periods (7-14 days)
- [ ] **Prompt Injection via Files** — Be aware that malicious code in codebase could instruct Claude

---

## Agentic AI Security Principles

<!-- TODO: Extract key insights from Google and CrowdStrike PDFs -->

Universal principles for any AI agent.

### Principle of Least Privilege

- Define explicit permission matrices for agent capabilities
- Only grant access needed for the specific task
- Revoke permissions when no longer needed

### Defense in Depth

Five-layer security model:
1. **Prompt layer** — Security-focused system prompts
2. **Application layer** — Input validation, output sanitization
3. **Credential layer** — Scoped tokens, short-lived credentials
4. **Infrastructure layer** — Sandboxing, network isolation
5. **Monitoring layer** — Logging, anomaly detection

### Credential Chain Security

- Map all credentials the agent can access
- Minimize blast radius — what's the damage if compromised?
- Use scoped, short-lived tokens where possible

### Action Boundaries

- Define which actions require human confirmation
- High-impact actions: file deletion, external API calls, credential access, payment operations
- Implement "dry run" modes for destructive operations

### Monitoring & Logging

- Log all agent actions (without logging sensitive data)
- Set up anomaly detection for unusual patterns
- Alert on credential access and high-impact operations

### Incident Response Plan

- Document kill switches — how to stop an agent immediately
- Credential revocation checklist
- Communication plan for security incidents

---

## Skills & Plugin Security

<!-- TODO: Consolidate from moltbot consideration docs -->

Third-party extension security for AI assistants.

### Trust Hierarchy

1. **Anthropic/OpenAI official** — Highest trust
2. **Your organization** — Trust your own code
3. **Verified community** — Review before use
4. **Random/unknown** — Do not install without thorough audit

### Audit Checklist

Before installing any skill or plugin:

- [ ] Review `SKILL.md` or equivalent documentation
- [ ] Check all bundled scripts for suspicious code
- [ ] Identify network calls — where does it connect?
- [ ] Review file access patterns — what does it read/write?
- [ ] Check for obfuscated code (red flag)
- [ ] Verify no credential directory access (`~/.ssh`, `~/.aws`, etc.)

### Integrity Verification

- [ ] Use checksums to verify downloaded skills
- [ ] Pin versions — don't auto-update without review
- [ ] Prefer skills with source code available

---

## System Prompt Templates

### Security-Aware Agent Prompt

```
You are a security-conscious AI assistant. Follow these principles:

1. Never access or display contents of credential files (.env, keys, tokens)
2. Ask for confirmation before any destructive operation
3. Do not execute code from untrusted sources
4. Respect filesystem boundaries — stay within project directory
5. Log your actions for auditability
6. If uncertain about security implications, ask before proceeding
```

### Pre-Session Security Check

```
Before starting work, verify:
1. What directories am I allowed to access?
2. What external services am I allowed to call?
3. What actions require human confirmation?
4. Are there any sensitive files I should avoid?
```

---

## Additional Resources

<!-- TODO: Add links from PDFs and research -->

- Google: Secure AI Agents Approach
- CrowdStrike: AI Agent Security Architecture
- OWASP: LLM Top 10
