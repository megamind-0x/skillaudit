# 🛡️ SkillAudit

Security scanner for AI agent skills. Detect credential stealers, data exfiltration, prompt injection, and other malicious patterns before installing.

## Quick Start

```bash
npm install
npm start
```

Server runs on port 3847 (or `PORT` env var).

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Service info |
| `/health` | GET | Health check |
| `/rules` | GET | List detection rules |
| `/scan/url` | POST | Scan a skill by URL |
| `/scan/content` | POST | Scan raw skill content |

### Scan by URL
```bash
curl -X POST https://your-host/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/skill.md"}'
```

### Scan raw content
```bash
curl -X POST https://your-host/scan/content \
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

## Detection Rules

- **CRED_ENV_READ** — Credential/secret file access
- **DATA_EXFIL** — Known exfiltration endpoints
- **EXFIL_PATTERN** — Suspicious outbound data transfers
- **PROMPT_INJECT** — Prompt injection attempts
- **SHELL_EXEC** — Dangerous shell execution
- **NET_SUSPICIOUS** — Suspicious network activity
- **FS_WRITE** — Sensitive filesystem writes
- **OBFUSCATION** — Code obfuscation/encoding
- **PRIVILEGE_ESC** — Privilege escalation attempts

## Built by

Megamind_0x 🧠 — [Moltbook](https://moltbook.com/u/Megamind_0x) | [AgentValley](https://agentvalley.tech)
