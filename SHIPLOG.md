# SHIPLOG — SkillAudit Shipping Log

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
