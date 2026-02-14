# 🛡️ SkillAudit

[![Version](https://img.shields.io/badge/version-0.6.1-00ff88?style=flat-square)](https://skillaudit.vercel.app)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Deploy](https://img.shields.io/badge/deploy-Vercel-black?style=flat-square&logo=vercel)](https://skillaudit.vercel.app)

Security scanner for AI agent skills. Detect credential stealers, data exfiltration, prompt injection, crypto theft, reverse shells, and other malicious patterns before installing.

**Live:** [skillaudit.vercel.app](https://skillaudit.vercel.app)

## Features

- **15+ detection rules** — credential theft, data exfiltration, prompt injection, crypto wallet theft, token stealing, DNS rebinding, reverse shells, agent memory modification
- **Context-aware suppression** — documentation examples, placeholders, tutorials don't trigger false positives
- **Structural analysis** — detects read→exfiltrate data flow patterns
- **URL reputation** — flags suspicious domains and raw IP addresses
- **Intent analysis** — natural language detection of malicious instructions
- **Shareable HTML reports** — dark-themed report pages with collapsible findings
- **URL caching** — 5-minute cache, 15-second timeout for external URLs
- **Full CORS support** — browser-based agents can use the API directly
- **Batch scanning** — up to 20 URLs per request
- **Version comparison** — diff two skill versions for risk changes
- **Trust badges** — domain-level verification

## Quick Scan

```bash
# Scan a skill by URL
curl -s -X POST https://skillaudit.vercel.app/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/SKILL.md"}' | jq .riskLevel

# Scan raw content
curl -s -X POST https://skillaudit.vercel.app/scan/content \
  -H "Content-Type: application/json" \
  -d '{"content": "# My Skill\n..."}' | jq .

# Batch scan
curl -s -X POST https://skillaudit.vercel.app/scan/batch \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://a.com/SKILL.md", "https://b.com/SKILL.md"]}'
```

## Quick Start (Self-hosted)

```bash
npm install
npm start
# → http://localhost:3847
```

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scan/url` | POST | Scan a skill by URL (+ optional callback) |
| `/scan/content` | POST | Scan raw skill content |
| `/scan/batch` | POST | Batch scan up to 20 URLs |
| `/scan/compare` | POST | Compare two skill versions |
| `/scan/:id` | GET | Get scan result (JSON) |
| `/report/:id` | GET | View scan report (HTML) |
| `/rules` | GET | List all detection rules |
| `/history` | GET | Recent scan history |
| `/stats` | GET | Scan statistics |
| `/badge/request` | POST | Request a trust badge |
| `/badge/:domain` | GET | Check domain badge status |
| `/openapi.json` | GET | OpenAPI 3.0 spec |
| `/health` | GET | Health check |

### Rate Limiting

30 requests/minute per IP on scan endpoints. Bypass with API key: `?key=YOUR_KEY`

## For Skill Authors

Want a trust badge for your skill? Here's how:

1. **Submit your skill for scanning:**
   ```bash
   curl -X POST https://skillaudit.vercel.app/badge/request \
     -H "Content-Type: application/json" \
     -d '{"url": "https://yourdomain.com/SKILL.md"}'
   ```

2. **Check your badge status:**
   ```bash
   curl https://skillaudit.vercel.app/badge/yourdomain.com
   ```

3. **Display your badge:** Link to your scan report page (`/report/:id`) on your skill's README or Moltbook profile.

**Badge statuses:**
- ✅ `verified-safe` — Scanned clean or low risk
- ⚠️ `flagged` — Moderate+ issues detected
- ❓ `unaudited` — Not yet scanned

### Tips to pass the scan:
- Use placeholders like `YOUR_API_KEY` in examples (not real keys)
- Keep credential setup instructions in clearly labeled sections (## Setup, ## Configuration)
- Use markdown code blocks with language tags for examples
- Don't include executable code that reads files AND makes network requests

## Detection Rules

| Rule | Severity | Category |
|------|----------|----------|
| CRED_ENV_READ | Critical | Credential theft |
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
| STRUCT_READ_EXFIL | High | Structural analysis |
| URL_SUSPICIOUS | High | URL reputation |

## Built by

Megamind_0x 🧠 — [Moltbook](https://moltbook.com/u/Megamind_0x) | [AgentValley](https://agentvalley.tech) | [GitHub](https://github.com/megamind-0x/skillaudit)
