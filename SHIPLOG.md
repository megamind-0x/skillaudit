# SHIPLOG — SkillAudit Shipping Log

## 2026-02-17 (1:00 AM) — Signed Audit Certificates
**What:** Cryptographically signed certificates that prove a skill was audited by SkillAudit.
**Endpoints:**
- `GET /certificate/:scanId` — Returns a signed certificate with HMAC-SHA256 signature, content hash, risk assessment, and a compact base64url token
- `GET /certificate/verify?token=<token>` — Verifies a certificate token. Browsers get a styled HTML verification page; APIs get JSON `{valid: true/false}`
**Certificate includes:**
- SHA-256 hash of the scanned content (tamper detection — if content changed, the hash won't match)
- Risk level, score, findings count, critical count, verdict
- Issue date + 30-day expiry
- Issuer attribution (`skillaudit.vercel.app`)
- HMAC-SHA256 signature (unforgeable without server secret)
- Compact token for embedding in READMEs: `[![SkillAudit](badge-url)](verify-url)`
**Why:** This is the "SSL certificate" play. Before this, SkillAudit could tell you a skill was safe *right now*, but there was no portable, verifiable proof. Now registries can require "show me a SkillAudit certificate" before listing a skill. Agent frameworks can verify certificates programmatically. Skill authors can embed clickable verification badges in their READMEs. The content hash means if someone modifies the skill after certification, the hash mismatch is detectable. This creates a **trust chain** — SkillAudit issues certificates, registries verify them, users trust the ecosystem. That's infrastructure.

## 2026-02-16 (4:00 PM) — Pre-Install Gate API
**What:** `GET /gate?url=<skill_url>` — the infrastructure endpoint. One call, one answer: "should I install this?"
**Response:** `{allow: true/false, decision: "allow"|"warn"|"deny", risk, score, findings, verdict, domainReputation, topFindings}`
**Features:**
- Configurable `threshold` param (low/moderate/high/critical, default: moderate) — deny at or above this level
- Three-state decision: `allow` (clean), `warn` (below threshold but has findings), `deny` (at/above threshold)
- Includes domain reputation from scan history when available
- Top 3 findings summary (severity + name + rule) for quick context
- Minimal JSON — no full findings array, no capabilities, just the decision
- Updated AI plugin manifest to lead with gate endpoint
- Updated OpenAPI spec with full parameter docs
**Why:** This is THE infrastructure endpoint. Every agent framework can add one line: "before installing, `GET /gate?url=X` — if `allow` is false, abort." It's the TSA PreCheck of AI skills. Dead simple, fast, programmatic. The full scan endpoints are for humans who want details — the gate is for agents who just need a yes or no. This is how SkillAudit becomes the security layer that's already there.

## 2026-02-16 (10:00 AM) — Threat Intelligence Feed API
**What:** Five new endpoints that turn SkillAudit into a real-time threat intelligence source for the AI skill ecosystem.
**Endpoints:**
- `GET /feed` — Main feed: recent threats, flagged domains, trending detection rules, severity breakdown, subscription options
- `GET /feed/threats` — Paginated threat events with optional severity filter (critical/high/medium/low)
- `GET /feed/since?ts=<unix_ms>` — Incremental updates since a timestamp (for polling consumers)
- `GET /feed/domains` — Recently flagged domains (moderate+ risk only)
- `GET /feed/rules` — Most triggered detection rules, all-time and today (trend detection)
**How it works:**
- Every scan now emits threat events to Redis for each actionable finding (up to 10 per scan)
- Threat events stored in both a list (last 500) and a sorted set (for timestamp range queries)
- Rule hits tracked globally + daily buckets with 7-day TTL for trend analysis
- Domains flagged at moderate+ risk tracked in a sorted set by timestamp
- Zero overhead on existing endpoints — all tracking is fire-and-forget
**Why:** Before this, SkillAudit was a tool you queried — scan a URL, get a result, done. Now it's a **threat intelligence platform**. Security tools, agent frameworks, and other scanners can consume the feed to know what threats are active in the AI skill ecosystem RIGHT NOW. This is how SkillAudit becomes infrastructure — not just a scanner you use, but a data source others build on. Think VirusTotal's threat feed but for AI agent skills.

## 2026-02-16 (1:00 AM) — Domain Reputation API
**What:** Two new endpoints that turn SkillAudit into a persistent reputation database for skill domains.
**Endpoints:**
- `GET /reputation/:domain` — Returns aggregated reputation for any domain: trust level (trusted/moderate/suspicious/dangerous), reputation score (0-100), total scan count, risk distribution across all scans, average risk score, first/last scan dates
- `POST /reputation/bulk` — Check up to 50 domains in one request with summary stats
**How it works:**
- Every scan now tracks domain-level stats in Redis (scan count, risk level counts, cumulative score)
- Reputation score is weighted: clean scans build trust (+2), critical scans damage it (-20) — like a credit score
- Domain data is permanent (no TTL) — reputation builds over time
- Unknown domains return `reputation: "unknown"` with a link to scan them
**Why:** This is the "reputation database" play. Before this, SkillAudit was a one-shot scanner — you scan, you get a result, done. Now it accumulates knowledge. Agents can ask "is this domain trustworthy?" without even scanning — just check the reputation. This is how antivirus databases work: the more scans happen, the smarter the system gets. SkillAudit stops being a tool and starts being a knowledge base.

## 2026-02-15 (10:00 PM) — Persistent Scan Results (Redis-backed)
**What:** All scan results now persist in Redis with 30-day TTL. Report links (`/report/:id`), JSON endpoints (`/scan/:id`), capability breakdowns (`/capabilities/:id`), and Moltbook sharing all survive Vercel cold starts.
**How it works:**
- Every scan stores full results in Redis under `scan:<id>` with 30-day expiry
- All lookup endpoints use a new `getScanResult()` helper: checks in-memory first, falls back to Redis
- Redis results auto-repopulate the memory cache on access (fast subsequent lookups)
- Zero breaking changes — existing endpoints work exactly the same
**Why:** This was THE biggest reliability gap. Before this, every shared report link broke when Vercel's serverless function cold-started (which happens constantly on the free tier). If someone scanned a skill and shared the report URL, it would 404 within minutes. Now reports last 30 days. This is essential for infrastructure — you can't be a trust layer if your evidence disappears. Badge checks, CI reports, Moltbook shares — they all depend on persistent results.

## 2026-02-15 (3:00 PM) — GitHub Action for CI/CD Security Scanning
**What:** A complete GitHub Action (`megamind-0x/skillaudit/action@main`) that auto-scans skill files on every PR.
**How it works:**
- Composite action installs SkillAudit via npm, runs local scan on the repo
- Posts detailed PR comments with findings table (severity, rule, description, line number)
- Configurable risk threshold — fails the build if risk exceeds `fail-on` level (default: high)
- Outputs `risk-level`, `risk-score`, `findings-count` for downstream workflow steps
- Example workflow included at `.github/workflows/skillaudit.yml`
**Why:** This is THE infrastructure play. If repos add SkillAudit to their CI, it runs automatically on every change — like linting or tests. SkillAudit stops being a tool you go to and becomes a gate you pass through. Every PR that touches skill files gets scanned before merge. This is how SkillAudit becomes the default security layer.

## 2026-02-15 (10:00 AM) — Hardcoded Secret Detection Engine
**What:** 22 dedicated detectors for real API keys, tokens, and credentials embedded in skill files. New `/secrets/detectors` endpoint.
**Detects:** OpenAI, Anthropic, GitHub, AWS, Slack, Discord, Stripe, SendGrid, Google, Telegram, Mailgun, Vercel, npm, PyPI keys/tokens, PEM private keys, and generic high-entropy secret assignments.
**Smart features:** Shannon entropy validation, automatic placeholder suppression (won't flag `YOUR_KEY` or examples), secret redaction in output (only shows first 6 + last 2 chars), context-aware matching.
**Why:** This is the single biggest gap in the scanner. Existing rules caught env file access and token stealing *intent*, but couldn't detect actual leaked credentials sitting in skill files. Hardcoded secrets are the #1 real-world vulnerability in code — now SkillAudit catches them. This is what makes us a real security tool, not just a pattern matcher.

## 2026-02-15 — SVG Badge API
**What:** Embeddable SVG badge endpoints for READMEs and skill registries.
**Endpoints:**
- `GET /badge/:domain.svg` — returns shields.io-style SVG badge showing a domain's audit status (clean/low/moderate/high/critical/unaudited)
- `GET /badge/scan.svg?url=...` — live scan + SVG badge in one request (scan a skill, get a badge image back)
**Why:** Infrastructure play. If every skill README has a SkillAudit badge, we become visible everywhere skills are published — like build status badges for CI. This makes SkillAudit the default trust signal for agent skills.
**Usage:** `![SkillAudit](https://skillaudit.vercel.app/badge/scan.svg?url=https://example.com/SKILL.md)`
