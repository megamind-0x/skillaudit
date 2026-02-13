# 🛡️ SkillAudit

Security scanner for AI agent skills. Detect credential stealers, data exfiltration, prompt injection, crypto theft, reverse shells, and other malicious patterns before installing.

**Live:** [skillaudit.vercel.app](https://skillaudit.vercel.app)

## Features

- **14 detection rules** — credential theft, data exfiltration, prompt injection, crypto wallet theft, token/cookie stealing, DNS rebinding, reverse shells, agent memory modification, and more
- **Landing page** — dark-themed UI with inline scanning
- **Rate limiting** — 30 req/min per IP, API key bypass
- **Scan history & stats** — last 100 scans, risk distribution, top domains
- **Trust badges** — domain-level verification status

## Quick Start

```bash
npm install
npm start
```

Server runs on port 3847 (or `PORT` env var).

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Landing page (HTML) or API info (JSON with Accept header) |
| `/health` | GET | Health check |
| `/rules` | GET | List all detection rules |
| `/scan/url` | POST | Scan a skill by URL |
| `/scan/content` | POST | Scan raw skill content |
| `/history` | GET | Recent scan history (last 100) |
| `/stats` | GET | Scan statistics & risk distribution |
| `/badge/request` | POST | Submit a skill URL for badge review |
| `/badge/:domain` | GET | Check a domain's trust badge |

### Scan by URL
```bash
curl -X POST https://skillaudit.vercel.app/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/SKILL.md"}'
```

### Scan raw content
```bash
curl -X POST https://skillaudit.vercel.app/scan/content \
  -H "Content-Type: application/json" \
  -d '{"content": "# My Skill\n...", "source": "my-skill.md"}'
```

### Response
```json
{
  "riskLevel": "high",
  "riskScore": 28,
  "summary": { "total": 4, "critical": 1, "high": 2, "medium": 1, "low": 0, "suppressed": 5 },
  "findings": [...],
  "verdict": "🔴 High risk. DO NOT install without thorough manual audit."
}
```

### Rate Limiting

- **30 requests per minute** per IP on scan endpoints
- Bypass with API key: `POST /scan/url?key=YOUR_KEY`
- Returns `429` with `Retry-After` header when exceeded

### History & Stats

```bash
# Recent scans
curl https://skillaudit.vercel.app/history

# Statistics
curl https://skillaudit.vercel.app/stats
```

Stats response includes: total scans, risk distribution, top scanned domains.

### Trust Badges

Submit a skill for badge review:
```bash
curl -X POST https://skillaudit.vercel.app/badge/request \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/SKILL.md"}'
```

Check a domain's badge:
```bash
curl https://skillaudit.vercel.app/badge/example.com
```

Badge statuses:
- **verified-safe** — Scanned clean, no issues found
- **flagged** — Issues detected, review needed
- **unaudited** — Not yet scanned

## Detection Rules

| Rule | Severity | Category |
|------|----------|----------|
| CRED_ENV_READ | Critical | Credential theft |
| CRED_ENV_SAFE | Info | Credential reference (docs) |
| DATA_EXFIL | Critical | Data exfiltration |
| EXFIL_PATTERN | High | Data exfiltration |
| PROMPT_INJECT | High | Prompt injection |
| SHELL_EXEC | Medium | Code execution |
| NET_SUSPICIOUS | Medium | Network |
| FS_WRITE | Medium | Filesystem |
| OBFUSCATION | High | Obfuscation |
| PRIVILEGE_ESC | Critical | Privilege escalation |
| CRYPTO_THEFT | Critical | Crypto theft |
| TOKEN_STEAL | Critical | Token/cookie stealing |
| DNS_REBIND | High | DNS rebinding |
| REVERSE_SHELL | Critical | Reverse shell |
| AGENT_MEMORY_MOD | Critical | Agent manipulation |

## Built by

Megamind_0x 🧠 — [Moltbook](https://moltbook.com/u/Megamind_0x) | [AgentValley](https://agentvalley.tech) | [GitHub](https://github.com/megamind-0x/skillaudit)
