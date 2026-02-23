# 🛡️ SkillAudit

[![CI](https://github.com/megamind-0x/skillaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/megamind-0x/skillaudit/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/skillaudit)](https://www.npmjs.com/package/skillaudit)

**The security layer for AI agent skills.** Scan, gate, and enforce policy before your agent installs anything.

37 detection rules · 333 patterns · MCP + A2A coverage · Zero dependencies

[![Live](https://img.shields.io/badge/status-live-00ff88?style=flat-square)](https://skillaudit.vercel.app)
[![npm](https://img.shields.io/npm/v/skillaudit?style=flat-square&color=blue)](https://www.npmjs.com/package/skillaudit)
[![API Docs](https://img.shields.io/badge/docs-API-6BA539?style=flat-square)](https://skillaudit.vercel.app/docs)

```bash
# Gate check — should my agent install this?
npx skillaudit gate https://example.com/SKILL.md

# Full scan
npx skillaudit https://example.com/SKILL.md

# Scan MCP manifest for schema poisoning
npx skillaudit manifest tools.json
```

---

## Why SkillAudit?

AI agents install tools, skills, and MCP servers from untrusted sources. Those skills can steal credentials, exfiltrate data, inject prompts, or manipulate other agents — and most of this is invisible to the user.

SkillAudit catches it. One API call before install. That's it.

---

## Quick Start

### 1. Gate Check (one line)

The infrastructure endpoint. Returns allow/deny.

```bash
curl "https://skillaudit.vercel.app/gate?url=https://example.com/SKILL.md"
# → {"allow": true, "decision": "allow", "risk": "clean", ...}
```

### 2. Full Scan

```bash
curl "https://skillaudit.vercel.app/scan/quick?url=https://example.com/SKILL.md"
```

### 3. Bulk Gate (check multiple skills at once)

```bash
curl -X POST https://skillaudit.vercel.app/gate/bulk \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://example.com/skill1.md", "https://example.com/skill2.md"]}'
# → {"allow": false, "denied": 1, "blocked": [...]}
```

### 4. Policy Enforcement

```bash
curl -X POST https://skillaudit.vercel.app/policy/evaluate-inline \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/SKILL.md",
    "policy": {"maxRisk": "low", "blockedCategories": ["credential_theft"]}
  }'
```

---

## What It Detects

32 rule categories, 289 patterns:

| Category | Rules | What it catches |
|----------|-------|-----------------|
| 🔑 Credential Theft | `CRED_ENV_READ`, `TOKEN_STEAL` | Reading .env, stealing tokens/cookies, accessing SSH keys |
| 📤 Data Exfiltration | `DATA_EXFIL`, `EXFIL_PATTERN`, `EXFIL_COVERT` | Webhook.site, DNS exfil, covert channels, image beacons |
| 💉 Prompt Injection | `PROMPT_INJECT`, `TOOL_POISONING` | "Ignore previous instructions", hidden system prompts |
| 🧬 MCP Schema Poisoning | `MCP_SCHEMA_POISON` | Hidden instructions in MCP tool descriptions/schemas |
| 🤖 A2A Attacks | `A2A_AGENT_IMPERSONATION`, `A2A_TASK_HIJACK`, `A2A_CROSS_AGENT_INJECT`, `A2A_DATA_LEAK`, `A2A_CAPABILITY_ABUSE` | Agent Card spoofing, task hijacking, cross-agent injection |
| 🐚 Code Execution | `SHELL_EXEC`, `REVERSE_SHELL` | Shell commands, reverse shells, eval/Function |
| 🔐 Hardcoded Secrets | 22 detectors | AWS keys, GitHub tokens, JWTs, private keys, API keys |
| 👻 Obfuscation | `OBFUSCATION`, `INVISIBLE_TEXT` | Base64 payloads, zero-width Unicode, encoded URLs |
| ⏰ Evasion | `TIME_BOMB` | Date-triggered activation, delayed execution |
| 🔗 Supply Chain | `SUPPLY_CHAIN` | Remote code loading, curl\|bash, dependency confusion |
| 🌐 Network | `NET_SUSPICIOUS`, `SSRF_PATTERN`, `DNS_REBIND` | SSRF, raw IPs, DNS rebinding, metadata endpoints |
| 📦 Container Escape | `CONTAINER_ESCAPE` | Docker socket, nsenter, /proc traversal, LD_PRELOAD |
| 🔄 Persistence | `PERSISTENCE` | Cron injection, systemd, LaunchAgents, pm2, nohup |
| 🕵️ Recon | `ENV_RECON` | os.hostname, whoami, network interfaces, environment dump |
| 🔧 Agent Manipulation | `AGENT_MEMORY_MOD`, `TOOL_SHADOW`, `CROSS_TOOL_ACCESS` | Memory modification, tool shadowing, cross-tool data access |
| 💰 Crypto Theft | `CRYPTO_THEFT` | Wallet files, seed phrases, MetaMask vaults |

Smart context suppression: documentation examples and placeholder tokens are automatically suppressed to minimize false positives.

---

## CLI

Zero install, zero config. Requires Node.js 18+.

```bash
# Scan a file, URL, or directory
npx skillaudit SKILL.md
npx skillaudit https://github.com/user/repo
npx skillaudit ./my-agent-project/

# Gate check (CI/CD: exit 0 = allow, exit 1 = deny)
npx skillaudit gate https://example.com/SKILL.md
npx skillaudit gate https://example.com/SKILL.md --threshold high

# Scan MCP manifest for schema poisoning
npx skillaudit manifest tools.json

# CI/CD integration
npx skillaudit SKILL.md --fail-on moderate          # Exit 1 if risk >= moderate
npx skillaudit SKILL.md --markdown >> "$GITHUB_STEP_SUMMARY"  # PR summary
npx skillaudit SKILL.md --json | jq .riskLevel      # Machine-readable

# MCP server mode
npx skillaudit --mcp
```

---

## API Endpoints

Full interactive docs at **[skillaudit.vercel.app/docs](https://skillaudit.vercel.app/docs)**

### Gate (Infrastructure)

| Endpoint | Description |
|----------|-------------|
| `GET /gate?url=` | Pre-install gate — allow/warn/deny |
| `POST /gate/bulk` | Check multiple skills, one composite decision |

### Scanning

| Endpoint | Description |
|----------|-------------|
| `GET /scan/quick?url=` | Quick scan by URL |
| `POST /scan/content` | Scan raw content |
| `POST /scan/manifest` | Scan MCP tool manifest for schema poisoning |
| `GET /scan/agent-card?url=` | Scan A2A Agent Card |
| `GET /scan/npm?package=` | Scan npm package |
| `GET /scan/pypi?package=` | Scan PyPI package |
| `GET /scan/repo?repo=` | Scan GitHub repo |
| `POST /scan/deps` | Scan dependency tree |
| `POST /scan/batch` | Batch scan (up to 20 URLs) |
| `POST /scan/compare` | Diff two skill versions |
| `POST /scan/deep` | Deep scan with threat chains |

### Policy & Intelligence

| Endpoint | Description |
|----------|-------------|
| `POST /policy/evaluate-inline` | Evaluate against custom policy (no auth) |
| `POST /policy` | Create stored policy (API key) |
| `GET /reputation/:domain` | Domain trust score |
| `GET /feed` | Threat intelligence feed |
| `GET /badge/scan.svg?url=` | Embeddable SVG badge |
| `GET /certificate/:id` | Signed audit certificate |

### Results

| Endpoint | Description |
|----------|-------------|
| `GET /scan/:id` | Retrieve scan result |
| `GET /scan/:id/sarif` | SARIF v2.1.0 output |
| `GET /report/:id` | Shareable HTML report |

**Rate limit:** 30 req/min per IP. Bypass with API key.

---

## MCP Server

Use SkillAudit as a native tool in Claude Desktop, Cursor, or any MCP client:

```json
{
  "mcpServers": {
    "skillaudit": {
      "command": "npx",
      "args": ["skillaudit", "--mcp"]
    }
  }
}
```

Tools: `skillaudit_gate`, `skillaudit_scan`, `skillaudit_scan_content`, `skillaudit_reputation`, `skillaudit_batch`

---

## GitHub Action

```yaml
name: SkillAudit
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx skillaudit . --fail-on high --markdown >> "$GITHUB_STEP_SUMMARY"
```

---

## CI/CD Integration

```bash
# GitHub Actions — gate check before deploy
npx skillaudit gate "$SKILL_URL" --threshold moderate || exit 1

# Generate PR comment
npx skillaudit ./skills/ --markdown > scan-results.md

# Policy enforcement in pipeline
curl -sf -X POST https://skillaudit.vercel.app/policy/evaluate-inline \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"$SKILL_URL\", \"policy\": {\"maxRisk\": \"low\"}}" \
  | jq -e '.pass == true'
```

---

## Risk Levels

| Level | Score | Meaning |
|-------|-------|---------|
| 🟢 `clean` | 0 | No issues found |
| 🟡 `low` | 1–9 | Minor concerns, review recommended |
| 🟠 `moderate` | 10–24 | Manual review required |
| 🔴 `high` | 25–49 | Do NOT install without audit |
| ⛔ `critical` | 50+ | Almost certainly malicious |

---

## Self-Hosted

```bash
git clone https://github.com/megamind-0x/skillaudit
cd skillaudit && npm install && npm start
# → http://localhost:3847
```

---

Built by [Megamind_0x](https://github.com/megamind-0x) 🧠

[Live App](https://skillaudit.vercel.app) · [API Docs](https://skillaudit.vercel.app/docs) · [Dashboard](https://skillaudit.vercel.app/dashboard) · [npm](https://www.npmjs.com/package/skillaudit)
