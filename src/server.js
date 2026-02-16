const express = require('express');
const path = require('path');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { scanContent } = require('./scanner');
const { SECRET_DETECTORS } = require('./secrets');
const { verifyPayment } = require('./verify-payment');
const app = express();
app.use(express.json({ limit: '2mb' }));

// --- x402 Payment Configuration ---
const SKILLAUDIT_WALLET_EVM = process.env.SKILLAUDIT_WALLET || '0x750F7CC2b66DA55e6d5a40c959875db4C38Bdc8c';
const SKILLAUDIT_WALLET_SOL = process.env.SKILLAUDIT_WALLET_SOL || '6oUWGzar1WQkz7nTHjuZ2oeB2gJfruvnkwREFESeCEHD';
const FACILITATOR_URL = process.env.X402_FACILITATOR_URL || 'https://www.x402.org/facilitator';

// USDC contract addresses
const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const USDC_SOL = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'; // USDC on Solana

const x402Routes = {
  'POST /scan/deep': {
    price: '0.05',
    description: 'Deep scan with full capability analysis',
  },
  'POST /scan/batch': {
    price: '0.10',
    description: 'Batch scan up to 20 URLs',
  },
  'POST /scan/compare': {
    price: '0.05',
    description: 'Compare two skill versions',
  },
};

// x402 middleware with DIY on-chain verification
app.use(async (req, res, next) => {
  const routeKey = `${req.method} ${req.path}`;
  const route = x402Routes[routeKey];
  if (!route) return next();

  // API key holders bypass payment
  if (API_KEYS.has(req.query?.key)) return next();

  // Check for payment proof: X-Payment-TX (our DIY) or PAYMENT-SIGNATURE (x402 standard)
  const paymentHeader = req.headers['x-payment-tx'] || req.headers['payment-signature'] || req.headers['x-payment'];
  if (paymentHeader) {
    try {
      const result = await verifyPayment(paymentHeader, SKILLAUDIT_WALLET_EVM, SKILLAUDIT_WALLET_SOL, parseFloat(route.price));
      if (result.valid) {
        req.paymentVerified = result;
        return next();
      }
      return res.status(402).json({
        error: 'Payment verification failed',
        reason: result.reason,
        hint: 'Send USDC to our wallet, then retry with header X-Payment-TX: base:<txHash> or solana:<txSig>',
      });
    } catch (err) {
      return res.status(500).json({ error: 'Payment verification error', message: err.message });
    }
  }

  // Return 402 with x402-compliant payment requirements (Base + Solana)
  const paymentRequired = {
    x402Version: 2,
    accepts: [
      {
        scheme: 'exact',
        network: 'eip155:8453', // Base mainnet
        maxAmountRequired: route.price,
        resource: routeKey,
        description: route.description,
        mimeType: 'application/json',
        payTo: SKILLAUDIT_WALLET_EVM,
        maxTimeoutSeconds: 60,
        asset: USDC_BASE,
      },
      {
        scheme: 'exact',
        network: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', // Solana mainnet
        maxAmountRequired: route.price,
        resource: routeKey,
        description: route.description,
        mimeType: 'application/json',
        payTo: SKILLAUDIT_WALLET_SOL,
        maxTimeoutSeconds: 60,
        asset: USDC_SOL,
      },
    ],
    facilitatorUrl: FACILITATOR_URL,
  };

  const encoded = Buffer.from(JSON.stringify(paymentRequired)).toString('base64');
  res.status(402)
    .header('PAYMENT-REQUIRED', encoded)
    .header('X-Payment-Required', encoded)
    .json({
      error: 'Payment Required',
      message: `This endpoint requires $${route.price} USDC. Pay on Base or Solana, then retry with the tx hash.`,
      price: `$${route.price} USDC`,
      howToPay: {
        step1: `Send ${route.price} USDC to one of the wallets below`,
        step2: 'Retry your request with header: X-Payment-TX: base:<txHash> or solana:<txSig>',
        wallets: {
          base: { address: SKILLAUDIT_WALLET_EVM, network: 'Base (Chain ID 8453)', asset: 'USDC' },
          solana: { address: SKILLAUDIT_WALLET_SOL, network: 'Solana Mainnet', asset: 'USDC' },
        },
      },
      x402: paymentRequired,
      docs: 'https://docs.x402.org',
    });
});

// --- API Keys ---
const API_KEYS = new Set((process.env.SKILLAUDIT_API_KEYS || 'sk-skillaudit-dev').split(','));

// --- Rate Limiting ---
const scanLimiter = rateLimit({
  windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false,
  skip: (req) => API_KEYS.has(req.query.key),
  message: { error: 'Too many requests. Max 30 per minute.', retryAfter: 60 }
});

// --- URL Cache (5 min TTL) ---
const urlCache = new Map();
const URL_CACHE_TTL = 5 * 60 * 1000;

function getCachedUrl(url) {
  const entry = urlCache.get(url);
  if (entry && Date.now() - entry.ts < URL_CACHE_TTL) return entry.data;
  urlCache.delete(url);
  return null;
}

function setCachedUrl(url, data) {
  urlCache.set(url, { data, ts: Date.now() });
  // Evict old entries
  if (urlCache.size > 200) {
    const now = Date.now();
    for (const [k, v] of urlCache) {
      if (now - v.ts > URL_CACHE_TTL) urlCache.delete(k);
    }
  }
}

// --- Redis persistence ---
const db = require('./redis');

// --- Scan History & Shared Results (in-memory + Redis) ---
const MAX_HISTORY = 100;
const scanHistory = [];
let totalScans = parseInt(process.env.SCAN_COUNT_BASE || '0', 10);
const sharedScans = new Map();
const badgedDomains = new Set();

// Load persisted scan count on startup
(async () => {
  const count = await db.getScanCount();
  if (count > totalScans) totalScans = count;
})();

function recordScan(url, result) {
  totalScans++;
  const id = crypto.randomBytes(6).toString('hex');
  const entry = { 
    id, 
    url, 
    timestamp: new Date().toISOString(), 
    riskLevel: result.riskLevel, 
    riskScore: result.riskScore,
    capabilityStats: result.capabilityStats,
    capabilities: result.capabilities,
    threatChains: result.threatChains 
  };
  scanHistory.unshift(entry);
  if (scanHistory.length > MAX_HISTORY) scanHistory.pop();
  sharedScans.set(id, { ...result, id, url });
  if (sharedScans.size > 500) {
    const oldest = sharedScans.keys().next().value;
    sharedScans.delete(oldest);
  }
  
  // Persist to Redis (fire-and-forget)
  db.incrScanCount();
  db.incrRisk(result.riskLevel || 'unknown');
  db.storeScanResult({ url, ...result });
  db.storeScanById(id, { ...result, id, url });
  if (result.threatChains) {
    result.threatChains.forEach(chain => db.incrThreatType(chain.name));
  }
  // Track domain reputation
  const domain = getDomain(url);
  if (domain) {
    db.trackDomainScan(domain, result.riskLevel, result.riskScore, result.summary?.total || 0, url);
  }
  // Threat intelligence feed: emit threat events for actionable findings
  const actionable = (result.findings || []).filter(f => !f.suppressed && f.severity !== 'info');
  if (actionable.length > 0) {
    const ts = new Date().toISOString();
    for (const f of actionable.slice(0, 10)) { // Cap at 10 events per scan
      db.storeThreatEvent({
        scanId: id,
        source: url,
        domain: domain || 'unknown',
        ruleId: f.ruleId,
        severity: f.severity,
        category: f.category,
        name: f.name,
        description: f.description,
        line: f.line,
        detectedAt: ts,
      });
      db.incrRuleHit(f.ruleId, f.severity);
    }
    // Track flagged domains (moderate+ risk only)
    if (['moderate', 'high', 'critical'].includes(result.riskLevel) && domain) {
      db.trackFlaggedDomain(domain, result.riskLevel, result.riskScore, url);
    }
  }
  return id;
}

// --- Badge System ---
const badges = new Map();

// --- Fetch URL with timeout ---
function fetchUrl(url) {
  const cached = getCachedUrl(url);
  if (cached) return Promise.resolve(cached);

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Request timeout (15s)')), 15000);
    const client = url.startsWith('https') ? https : http;
    client.get(url, { headers: { 'User-Agent': 'SkillAudit/0.7' }, timeout: 15000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        clearTimeout(timeout);
        return fetchUrl(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) { clearTimeout(timeout); return reject(new Error(`HTTP ${res.statusCode}`)); }
      let data = '';
      res.on('data', chunk => { data += chunk; if (data.length > 1024 * 512) { res.destroy(); clearTimeout(timeout); reject(new Error('Content too large')); } });
      res.on('end', () => { clearTimeout(timeout); setCachedUrl(url, data); resolve(data); });
    }).on('error', (e) => { clearTimeout(timeout); reject(e); }).on('timeout', () => { clearTimeout(timeout); reject(new Error('Timeout')); });
  });
}

function getDomain(url) {
  try { return new URL(url).hostname; } catch { return null; }
}

function fireCallback(callbackUrl, result) {
  try {
    const url = new URL(callbackUrl);
    const payload = JSON.stringify(result);
    const options = {
      hostname: url.hostname, port: url.port, path: url.pathname + url.search,
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), 'User-Agent': 'SkillAudit/0.7-webhook' },
      timeout: 10000,
    };
    const client = url.protocol === 'https:' ? https : http;
    const req = client.request(options);
    req.on('error', () => {});
    req.write(payload);
    req.end();
  } catch {}
}

// --- CORS middleware ---
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// --- Static files (SEO) ---
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1d' }));

// --- Pre-Install Gate (GET) - The infrastructure endpoint ---
// Designed for agents: one call, one answer. "Should I install this?"
app.get('/gate', scanLimiter, async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ allow: false, decision: 'error', reason: 'url query parameter is required', example: '/gate?url=https://example.com/SKILL.md' });

  const threshold = req.query.threshold || 'moderate'; // allow everything below this risk level
  const thresholdOrder = { clean: 0, low: 1, moderate: 2, high: 3, critical: 4 };
  const thresholdIdx = thresholdOrder[threshold] ?? 2;

  try {
    const content = await fetchUrl(url);
    const result = scanContent(content, url);
    const id = recordScan(url, result);

    const riskIdx = thresholdOrder[result.riskLevel] ?? 0;
    const decision = riskIdx === 0 ? 'allow' : riskIdx < thresholdIdx ? 'warn' : 'deny';
    const allow = decision !== 'deny';

    // Get domain reputation if available
    const domain = getDomain(url);
    let reputation = null;
    if (domain) {
      try { reputation = await db.getDomainReputation(domain); } catch {}
    }

    res.json({
      allow,
      decision, // 'allow' | 'warn' | 'deny'
      risk: result.riskLevel,
      score: result.riskScore,
      findings: result.summary.total,
      critical: result.summary.critical,
      high: result.summary.high,
      verdict: result.verdict,
      domain: domain || null,
      domainReputation: reputation ? reputation.reputation : 'unknown',
      domainScore: reputation ? reputation.reputationScore : null,
      scanId: id,
      reportUrl: `https://skillaudit.vercel.app/report/${id}`,
      threshold,
      // Top 3 findings for context (severity + name only)
      topFindings: result.findings.slice(0, 3).map(f => ({
        severity: f.severity,
        name: f.name,
        rule: f.ruleId,
      })),
    });
  } catch (err) {
    res.status(400).json({ allow: false, decision: 'error', reason: `Failed to fetch: ${err.message}` });
  }
});

// --- Quick Scan (GET) - Agent-friendly ---
app.get('/scan/quick', scanLimiter, async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ error: 'url query parameter is required', example: '/scan/quick?url=https://example.com/SKILL.md' });
  try {
    const content = await fetchUrl(url);
    const result = scanContent(content, url);
    const id = recordScan(url, result);
    result.id = id;
    result.shareUrl = `/scan/${id}`;
    result.reportUrl = `/report/${id}`;
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: `Failed to fetch: ${err.message}` });
  }
});

// --- Well-known: AI Plugin Manifest ---
app.get('/.well-known/ai-plugin.json', (req, res) => {
  res.json({
    schema_version: 'v1',
    name_for_human: 'SkillAudit',
    name_for_model: 'skillaudit',
    description_for_human: 'Security scanner for AI agent skills. Detects credential theft, data exfiltration, prompt injection, and more.',
    description_for_model: 'Security gate for AI agent skills. Before installing any skill, call GET /gate?url=<url> for an instant allow/warn/deny decision. For full scan details, use GET /scan/quick?url=<url> or POST /scan/url with {"url":"..."}. Returns risk level (clean/low/moderate/high/critical), findings, and verdict.',
    auth: { type: 'none' },
    api: {
      type: 'openapi',
      url: 'https://skillaudit.vercel.app/.well-known/openapi.json'
    },
    logo_url: 'https://skillaudit.vercel.app/logo.png',
    contact_email: 'megamind@skillaudit.vercel.app',
    legal_info_url: 'https://skillaudit.vercel.app'
  });
});

// --- Well-known: OpenAPI spec redirect ---
app.get('/.well-known/openapi.json', (req, res) => {
  res.redirect(301, '/openapi.json');
});

// --- robots.txt ---
app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send(`User-agent: *
Allow: /
Allow: /.well-known/ai-plugin.json
Allow: /.well-known/openapi.json
Allow: /openapi.json
Allow: /scan/quick

Sitemap: https://skillaudit.vercel.app/openapi.json
`);
});

// --- Landing page ---
app.get('/', (req, res) => {
  if (req.headers.accept && req.headers.accept.includes('application/json') && !req.headers.accept.includes('text/html')) {
    return res.json({
      name: 'SkillAudit', version: '0.7.0',
      description: 'Security scanner for AI agent skills — structural analysis, URL reputation, intent detection',
      docs: '/openapi.json',
      endpoints: {
        'GET /gate?url=': 'Pre-install gate — instant allow/warn/deny decision for agents (the infrastructure endpoint)',
        'POST /scan/url': 'Scan a skill by URL (supports callback)',
        'POST /scan/content': 'Scan raw skill content',
        'POST /scan/deep': 'Deep scan with capability analysis (x402: $0.05 USDC)',
        'POST /scan/batch': 'Batch scan multiple URLs (x402: $0.10 USDC)',
        'POST /scan/compare': 'Compare two skill versions (x402: $0.05 USDC)',
        'GET /scan/:id': 'Get shared scan result (JSON)',
        'GET /report/:id': 'View scan report (HTML)',
        'GET /rules': 'List detection rules',
        'GET /secrets/detectors': 'List hardcoded secret detectors (22 patterns)',
        'GET /history': 'Recent scan history',
        'GET /stats': 'Scan statistics',
        'POST /badge/request': 'Request a trust badge',
        'GET /badge/:domain': 'Check domain badge (JSON)',
        'GET /badge/:domain.svg': 'Embeddable SVG badge for READMEs',
        'GET /badge/scan.svg?url=': 'Live scan → SVG badge in one request',
        'POST /share/moltbook': 'Share scan result to Moltbook (with lobster math solving)',
        'GET /scan/repo?repo=owner/name': 'Auto-discover and scan all skill files in a GitHub repo',
        'GET /reputation/:domain': 'Domain reputation lookup (aggregated scan history)',
        'POST /reputation/bulk': 'Bulk domain reputation check (up to 50 domains)',
        'GET /feed': 'Threat intelligence feed — recent threats, flagged domains, trending rules',
        'GET /feed/threats': 'Recent threat events (filterable by severity)',
        'GET /feed/since?ts=': 'Incremental threat updates since a timestamp',
        'GET /feed/domains': 'Recently flagged domains',
        'GET /feed/rules': 'Trending detection rules (all-time + today)',
        'POST /watchlist': 'Add URL to watchlist for continuous monitoring (API key required)',
        'GET /watchlist': 'List watched URLs with risk status (API key required)',
        'POST /watchlist/check': 'Re-scan all watched URLs, detect risk changes (API key required)',
        'DELETE /watchlist/:id': 'Remove URL from watchlist (API key required)',
        'GET /watchlist/alerts': 'View all risk change alerts (API key required)',
        'GET /openapi.json': 'OpenAPI 3.0 spec',
        'GET /health': 'Health check',
      }
    });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '0.7.0', uptime: process.uptime() });
});

// --- Rules ---
app.get('/rules', (req, res) => {
  const rules = require('../rules/patterns.json').rules;
  res.json({
    count: rules.length,
    rules: rules.map(r => ({
      id: r.id, severity: r.severity, category: r.category,
      name: r.name, description: r.description, patternCount: r.patterns.length
    }))
  });
});

// --- Secret Detectors ---
app.get('/secrets/detectors', (req, res) => {
  res.json({
    count: SECRET_DETECTORS.length,
    description: 'Hardcoded secret detection — catches real API keys, tokens, and credentials embedded in skill files',
    detectors: SECRET_DETECTORS.map(d => ({
      id: d.id, severity: d.severity, category: d.category,
      name: d.name, description: d.description,
    }))
  });
});

// --- Scan URL ---
app.post('/scan/url', scanLimiter, async (req, res) => {
  const { url, callback } = req.body;
  if (!url) return res.status(400).json({ error: 'url is required' });
  try {
    const content = await fetchUrl(url);
    const result = scanContent(content, url);
    const id = recordScan(url, result);
    result.id = id;
    result.shareUrl = `/scan/${id}`;
    result.reportUrl = `/report/${id}`;
    if (callback) fireCallback(callback, result);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: `Failed to fetch: ${err.message}` });
  }
});

// --- Scan Content ---
app.post('/scan/content', scanLimiter, (req, res) => {
  const { content, source } = req.body;
  if (!content) return res.status(400).json({ error: 'content is required' });
  const result = scanContent(content, source || 'direct-input');
  const id = recordScan(source || 'direct-input', result);
  result.id = id;
  result.shareUrl = `/scan/${id}`;
  result.reportUrl = `/report/${id}`;
  res.json(result);
});

// --- Batch Scan ---
app.post('/scan/batch', scanLimiter, async (req, res) => {
  const { urls } = req.body;
  if (!urls || !Array.isArray(urls) || urls.length === 0) {
    return res.status(400).json({ error: 'urls array is required' });
  }
  if (urls.length > 20) {
    return res.status(400).json({ error: 'Maximum 20 URLs per batch' });
  }
  const results = await Promise.all(urls.map(async (url) => {
    try {
      const content = await fetchUrl(url);
      const result = scanContent(content, url);
      const id = recordScan(url, result);
      return { url, status: 'success', id, ...result, shareUrl: `/scan/${id}`, reportUrl: `/report/${id}` };
    } catch (err) {
      return { url, status: 'error', error: err.message };
    }
  }));

  const successful = results.filter(r => r.status === 'success');
  const failed = results.filter(r => r.status === 'error');
  const riskBreakdown = { clean: 0, low: 0, moderate: 0, high: 0, critical: 0 };
  successful.forEach(r => { riskBreakdown[r.riskLevel] = (riskBreakdown[r.riskLevel] || 0) + 1; });

  res.json({ total: urls.length, successful: successful.length, failed: failed.length, riskBreakdown, results });
});

// --- Compare ---
app.post('/scan/compare', scanLimiter, async (req, res) => {
  const { oldUrl, newUrl } = req.body;
  if (!oldUrl || !newUrl) return res.status(400).json({ error: 'oldUrl and newUrl are required' });
  try {
    const [oldContent, newContent] = await Promise.all([fetchUrl(oldUrl), fetchUrl(newUrl)]);
    const oldResult = scanContent(oldContent, oldUrl);
    const newResult = scanContent(newContent, newUrl);

    const oldRuleIds = new Set(oldResult.findings.map(f => `${f.ruleId}:${f.line}:${f.match}`));
    const newRuleIds = new Set(newResult.findings.map(f => `${f.ruleId}:${f.line}:${f.match}`));
    const newFindings = newResult.findings.filter(f => !oldRuleIds.has(`${f.ruleId}:${f.line}:${f.match}`));
    const resolvedFindings = oldResult.findings.filter(f => !newRuleIds.has(`${f.ruleId}:${f.line}:${f.match}`));
    const scoreDelta = newResult.riskScore - oldResult.riskScore;
    recordScan(newUrl, newResult);

    res.json({
      oldUrl, newUrl,
      oldVersion: { riskLevel: oldResult.riskLevel, riskScore: oldResult.riskScore, findingsCount: oldResult.summary.total },
      newVersion: { riskLevel: newResult.riskLevel, riskScore: newResult.riskScore, findingsCount: newResult.summary.total },
      scoreDelta, riskChanged: oldResult.riskLevel !== newResult.riskLevel,
      newFindings: { count: newFindings.length, items: newFindings },
      resolvedFindings: { count: resolvedFindings.length, items: resolvedFindings },
      verdict: scoreDelta > 0
        ? `🔴 Update INCREASES risk by ${scoreDelta} points. ${newFindings.length} new finding(s).`
        : scoreDelta < 0
          ? `✅ Update DECREASES risk by ${Math.abs(scoreDelta)} points. ${resolvedFindings.length} issue(s) resolved.`
          : '⚪ No change in risk score.',
    });
  } catch (err) {
    res.status(400).json({ error: `Failed to fetch: ${err.message}` });
  }
});

// --- Enhanced Deep Scan (v0.6.1) ---
app.post('/scan/deep', scanLimiter, async (req, res) => {
  const { url, content } = req.body;
  
  try {
    let textContent;
    let sourceUrl;
    
    if (url) {
      textContent = await fetchUrl(url);
      sourceUrl = url;
    } else if (content) {
      textContent = content;
      sourceUrl = 'inline';
    } else {
      return res.status(400).json({ error: 'Either url or content is required' });
    }
    
    const result = scanContent(textContent, sourceUrl);
    const scanId = recordScan(sourceUrl, result);
    
    // Enhanced response with full capability analysis
    res.json({
      ...result,
      scanId,
      enhancedAnalysis: true,
      capabilityBreakdown: result.capabilities,
      threatAnalysis: result.threatChains,
      permissionRequirements: result.permissions,
      riskAssessment: {
        traditionalRisk: result.riskLevel,
        capabilityRisk: result.capabilityStats.threatChains > 0 ? 'high' : 'low',
        combinedVerdict: result.verdict
      }
    });
  } catch (err) {
    res.status(400).json({ error: `Failed to process: ${err.message}` });
  }
});

// --- Get scan result (memory → Redis fallback) ---
async function getScanResult(id) {
  const mem = sharedScans.get(id);
  if (mem) return mem;
  // Fall back to Redis for persisted results
  const persisted = await db.getScanById(id);
  if (persisted) {
    // Re-populate memory cache
    sharedScans.set(id, persisted);
  }
  return persisted;
}

// --- Capability Breakdown (v0.6.1) ---
app.get('/capabilities/:id', async (req, res) => {
  const result = await getScanResult(req.params.id);
  if (!result) return res.status(404).json({ error: 'Scan not found' });
  
  res.json({
    scanId: req.params.id,
    source: result.source,
    scannedAt: result.scannedAt,
    capabilities: result.capabilities || {},
    threatChains: result.threatChains || [],
    permissions: result.permissions || {},
    capabilityStats: result.capabilityStats || {},
    analysisVersion: result.version
  });
});

// --- GitHub Repo Scanner Route (must be before /scan/:id) ---
app.get('/scan/repo', scanLimiter, async (req, res) => {
  const repoInput = req.query.repo;
  const branch = req.query.branch || 'main';

  if (!repoInput) {
    return res.status(400).json({
      error: 'repo query parameter is required',
      example: '/scan/repo?repo=owner/repo-name',
      hint: 'Pass a GitHub repository in owner/name format',
    });
  }

  let owner, repo;
  const match = repoInput.match(/(?:github\.com\/)?([^\/\s]+)\/([^\/\s?#]+)/);
  if (!match) {
    return res.status(400).json({ error: 'Invalid repo format. Use owner/repo (e.g. modelcontextprotocol/servers)' });
  }
  owner = match[1];
  repo = match[2].replace(/\.git$/, '');

  try {
    const skillFiles = await discoverSkillFiles(owner, repo, branch);

    if (skillFiles.length === 0) {
      return res.json({
        repo: `${owner}/${repo}`, branch, filesScanned: 0,
        message: 'No skill files found in this repository',
        hint: 'We look for SKILL.md, skill.json, plugin.json, mcp.json, ai-plugin.json, and files in skills/tools/plugins directories',
        riskLevel: 'unknown',
      });
    }

    const results = await Promise.all(skillFiles.map(async (filePath) => {
      const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${filePath}`;
      try {
        const content = await fetchUrl(rawUrl);
        const result = scanContent(content, rawUrl);
        const id = recordScan(rawUrl, result);
        return {
          file: filePath, url: rawUrl, status: 'scanned', id,
          riskLevel: result.riskLevel, riskScore: result.riskScore,
          findings: result.summary.total, critical: result.summary.critical,
          high: result.summary.high, reportUrl: `/report/${id}`,
        };
      } catch (err) {
        return { file: filePath, status: 'error', error: err.message };
      }
    }));

    const scanned = results.filter(r => r.status === 'scanned');
    const failed = results.filter(r => r.status === 'error');
    const riskOrder = ['clean', 'low', 'moderate', 'high', 'critical'];
    const worstRisk = scanned.reduce((worst, r) => {
      return riskOrder.indexOf(r.riskLevel) > riskOrder.indexOf(worst) ? r.riskLevel : worst;
    }, 'clean');

    const totalFindings = scanned.reduce((s, r) => s + r.findings, 0);
    const totalCritical = scanned.reduce((s, r) => s + r.critical, 0);
    const totalHigh = scanned.reduce((s, r) => s + r.high, 0);
    const totalScore = scanned.reduce((s, r) => s + r.riskScore, 0);

    res.json({
      repo: `${owner}/${repo}`, branch, repoUrl: `https://github.com/${owner}/${repo}`,
      filesDiscovered: skillFiles.length, filesScanned: scanned.length, filesFailed: failed.length,
      overallRisk: worstRisk, totalRiskScore: totalScore, totalFindings, totalCritical, totalHigh,
      verdict: totalFindings === 0
        ? `✅ Repository clean — ${scanned.length} skill file(s) scanned, no issues found.`
        : totalCritical > 0
          ? `🔴 CRITICAL issues found — ${totalCritical} critical, ${totalHigh} high across ${scanned.length} files. Manual audit required.`
          : totalHigh > 0
            ? `🔶 High risk findings — ${totalHigh} high severity issues across ${scanned.length} files. Review recommended.`
            : `⚠️ ${totalFindings} finding(s) across ${scanned.length} files. Minor concerns detected.`,
      files: results,
      badgeUrl: `https://skillaudit.vercel.app/badge/github.com/${owner}/${repo}.svg`,
    });
  } catch (err) {
    if (err.message.includes('HTTP 404')) {
      return res.status(404).json({
        error: `Repository not found: ${owner}/${repo}`,
        hint: 'Make sure the repo exists and is public. Try a different branch with ?branch=master',
      });
    }
    res.status(500).json({ error: `Failed to scan repo: ${err.message}` });
  }
});

// --- Shared Scan Result (JSON) ---
app.get('/scan/:id', async (req, res) => {
  const result = await getScanResult(req.params.id);
  if (!result) return res.status(404).json({ error: 'Scan not found' });
  res.json(result);
});

// --- Report Page (HTML) ---
app.get('/report/:id', async (req, res) => {
  const result = await getScanResult(req.params.id);
  if (!result) return res.status(404).send(reportNotFound());
  res.send(renderReport(result));
});

// --- History ---
app.get('/history', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 100);
  res.json({ count: scanHistory.length, total: totalScans, scans: scanHistory.slice(0, limit) });
});

// --- Stats ---
app.get('/stats', async (req, res) => {
  // Try Redis first for persisted stats
  const [redisCount, redisRisk, redisThreats, recentScans] = await Promise.all([
    db.getScanCount(),
    db.getRiskDistribution(),
    db.getThreatTypes(),
    db.getRecentScans(10),
  ]);

  const persistedTotal = Math.max(redisCount || 0, totalScans);
  
  // Merge in-memory stats for capabilities (not persisted yet)
  const capabilityStats = {};
  for (const s of scanHistory) {
    if (s.capabilities) {
      Object.keys(s.capabilities).forEach(cap => {
        capabilityStats[cap] = (capabilityStats[cap] || 0) + 1;
      });
    }
  }

  const riskDist = Object.keys(redisRisk).length > 0 ? redisRisk : 
    { clean: 0, low: 0, moderate: 0, high: 0, critical: 0 };
  
  const threatChainStats = redisThreats || {};
  
  res.json({
    totalScans: persistedTotal,
    recentScans: recentScans.length || scanHistory.length,
    riskDistribution: riskDist,
    recentScanList: recentScans,
    capabilityAnalysis: {
      mostCommonCapabilities: Object.entries(capabilityStats)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 10)
        .map(([cap, count]) => ({ capability: cap, count })),
      threatChains: Object.entries(threatChainStats)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 10)
        .map(([chain, count]) => ({ threatChain: chain, count })),
      totalWithCapabilities: Object.keys(capabilityStats).length,
      totalWithThreatChains: Object.keys(threatChainStats).length
    }
  });
});

// --- Badge System ---
app.post('/badge/request', scanLimiter, async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'url is required' });
  const domain = getDomain(url);
  if (!domain) return res.status(400).json({ error: 'Invalid URL' });
  try {
    const content = await fetchUrl(url);
    const result = scanContent(content, url);
    recordScan(url, result);
    const status = result.riskLevel === 'clean' || result.riskLevel === 'low' ? 'verified-safe' : 'flagged';
    badges.set(domain, { status, url, riskLevel: result.riskLevel, riskScore: result.riskScore, updatedAt: new Date().toISOString() });
    res.json({ domain, badge: status, scan: result });
  } catch (err) {
    res.status(400).json({ error: `Failed to fetch: ${err.message}` });
  }
});

// --- Live Badge: scan a URL and return SVG badge ---
app.get('/badge/scan.svg', scanLimiter, async (req, res) => {
  const url = req.query.url;
  if (!url) return res.type('image/svg+xml').send(renderBadgeSvg('SkillAudit', 'error'));
  try {
    const content = await fetchUrl(url);
    const result = scanContent(content, url);
    recordScan(url, result);
    const domain = getDomain(url);
    if (domain) badges.set(domain, { status: result.riskLevel === 'clean' || result.riskLevel === 'low' ? 'verified-safe' : 'flagged', url, riskLevel: result.riskLevel, riskScore: result.riskScore, updatedAt: new Date().toISOString() });
    res.type('image/svg+xml').header('Cache-Control', 'public, max-age=300').send(renderBadgeSvg('SkillAudit', result.riskLevel));
  } catch {
    res.type('image/svg+xml').send(renderBadgeSvg('SkillAudit', 'error'));
  }
});

app.get('/badge/:domain', (req, res) => {
  // If requesting .svg, return SVG badge image
  const domain = req.params.domain;
  if (domain.endsWith('.svg')) {
    const actualDomain = domain.slice(0, -4);
    const info = badges.get(actualDomain);
    const status = info ? info.riskLevel : 'unaudited';
    res.type('image/svg+xml').header('Cache-Control', 'public, max-age=300').send(renderBadgeSvg('SkillAudit', status));
    return;
  }
  const info = badges.get(domain);
  if (!info) return res.json({ domain, badge: 'unaudited' });
  res.json({ domain, ...info });
});

// --- Moltbook Integration ---
function postJson(url, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const payload = JSON.stringify(body);
    const opts = {
      hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search,
      method: 'POST', timeout: 15000,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), ...headers },
    };
    const client = u.protocol === 'https:' ? https : http;
    const req = client.request(opts, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, data }); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => reject(new Error('Timeout')));
    req.write(payload);
    req.end();
  });
}

function solveLobsterMath(challenge) {
  // Clean obfuscated text: strip special formatting chars, normalize
  const clean = challenge
    .replace(/[\]\[^\/\-~{}|<>()!@#$%&*_+=\\]/g, '')
    .replace(/[^a-zA-Z0-9.\s,?]/g, ' ')
    .replace(/\s+/g, ' ')
    .toLowerCase()
    .trim();

  // Word-to-number mapping
  const wordNums = {
    zero:0,one:1,two:2,three:3,four:4,five:5,six:6,seven:7,eight:8,nine:9,
    ten:10,eleven:11,twelve:12,thirteen:13,fourteen:14,fifteen:15,sixteen:16,
    seventeen:17,eighteen:18,nineteen:19,twenty:20,thirty:30,forty:40,fifty:50,
    sixty:60,seventy:70,eighty:80,ninety:90,hundred:100,thousand:1000,
  };

  function extractNumbers(text) {
    const nums = [];
    const digitRegex = /\b(\d+(?:\.\d+)?)\b/g;
    let m;
    while ((m = digitRegex.exec(text)) !== null) nums.push({ val: parseFloat(m[1]), idx: m.index });

    const words = text.split(/\s+/);
    let current = null;
    let currentIdx = 0;
    let pos = 0;
    for (let i = 0; i < words.length; i++) {
      const w = words[i];
      pos = text.indexOf(w, pos);
      if (wordNums[w] !== undefined) {
        const v = wordNums[w];
        if (v === 100) {
          current = (current || 1) * 100;
        } else if (v === 1000) {
          current = (current || 1) * 1000;
        } else {
          if (current === null) { current = v; currentIdx = pos; }
          else if (v < 10 && current >= 20) { current += v; }
          else if (v >= 20 && current < 10) { nums.push({ val: current, idx: currentIdx }); current = v; currentIdx = pos; }
          else { nums.push({ val: current, idx: currentIdx }); current = v; currentIdx = pos; }
        }
      } else {
        if (current !== null) { nums.push({ val: current, idx: currentIdx }); current = null; }
      }
      pos += w.length;
    }
    if (current !== null) nums.push({ val: current, idx: currentIdx });

    nums.sort((a, b) => a.idx - b.idx);
    // Deduplicate overlapping digit/word matches
    const deduped = [];
    for (const n of nums) {
      if (deduped.length === 0 || Math.abs(n.idx - deduped[deduped.length - 1].idx) > 2) {
        deduped.push(n);
      }
    }
    return deduped.map(n => n.val);
  }

  const numbers = extractNumbers(clean);
  if (numbers.length < 2) return numbers.length === 1 ? numbers[0].toFixed(2) : null;

  const text = clean;

  // Detect operation from context
  if (/multipli|times/.test(text)) return (numbers[0] * numbers[1]).toFixed(2);
  if (/doubled/.test(text)) return (numbers[0] * 2).toFixed(2);
  if (/tripled/.test(text)) return (numbers[0] * 3).toFixed(2);
  if (/divided/.test(text)) return (numbers[0] / numbers[1]).toFixed(2);
  if (/halved/.test(text)) return (numbers[0] / 2).toFixed(2);

  // Subtraction keywords
  if (/loses|decreases|slows|reduces|drops|minus|subtract|less than|slower|behind|difference|remaining|left/.test(text)) {
    return (numbers[0] - numbers[1]).toFixed(2);
  }

  // Addition keywords (including "total", "combined", "together", "and", "sum")
  if (/total|combined|together|sum|adds|plus|gains|increases|faster|boost|accelerat|additional|more than|and.*(?:what|how)/.test(text)) {
    return numbers.reduce((a, b) => a + b, 0).toFixed(2);
  }

  // Fallback: addition (lobster claw force problems are usually addition)
  return numbers.reduce((a, b) => a + b, 0).toFixed(2);
}

function generateMoltbookPost(result) {
  const source = result.source || result.url || 'unknown';
  let hostname;
  try { hostname = new URL(source).hostname; } catch { hostname = source; }

  const title = `SkillAudit Report: ${result.riskLevel.toUpperCase()} — ${hostname}`;

  let content = `**Risk Level:** ${result.riskLevel.toUpperCase()} (score: ${result.riskScore})\n\n`;
  content += `**Findings:** ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium, ${result.summary.low} low`;
  if (result.summary.suppressed > 0) content += ` (${result.summary.suppressed} suppressed as documentation)`;
  content += '\n\n';

  if (result.findings.length > 0) {
    content += '**Top findings:**\n';
    result.findings.slice(0, 3).forEach(f => {
      content += `- \`${f.ruleId}\` [${f.severity}] — ${f.name} (line ${f.line})\n`;
    });
    if (result.findings.length > 3) content += `- ... and ${result.findings.length - 3} more\n`;
    content += '\n';
  }

  content += `**Verdict:** ${result.verdict}\n\n`;
  content += `**Full report:** https://skillaudit.vercel.app/report/${result.id}\n\n`;
  content += `Scanned by SkillAudit 🛡️`;

  return { title, content };
}

app.post('/share/moltbook', scanLimiter, async (req, res) => {
  const { scanId, apiKey, submolt } = req.body;
  if (!scanId) return res.status(400).json({ error: 'scanId is required' });
  if (!apiKey) return res.status(400).json({ error: 'apiKey is required (your Moltbook API key)' });

  const result = await getScanResult(scanId);
  if (!result) return res.status(404).json({ error: 'Scan not found' });

  const { title, content } = generateMoltbookPost(result);
  const targetSubmolt = submolt || 'general';

  try {
    // Step 1: Create post on Moltbook
    const postRes = await postJson('https://www.moltbook.com/api/v1/posts', {
      title, content, submolt: targetSubmolt,
    }, { 'X-API-Key': apiKey });

    if (!postRes.data.success) {
      return res.status(400).json({
        error: 'Moltbook rejected the post',
        moltbook_error: postRes.data.error || postRes.data,
        hint: postRes.data.hint || null,
        retry_after_minutes: postRes.data.retry_after_minutes || null,
      });
    }

    // Step 2: Handle verification challenge if present
    if (postRes.data.verification_required && postRes.data.verification) {
      const v = postRes.data.verification;
      const answer = solveLobsterMath(v.challenge);

      if (!answer) {
        return res.status(500).json({
          error: 'Could not solve verification challenge',
          challenge: v.challenge,
          verification_code: v.code,
          hint: 'You can manually verify at POST /api/v1/verify on moltbook.com',
        });
      }

      // Step 3: Submit verification
      const verifyRes = await postJson('https://www.moltbook.com/api/v1/verify', {
        verification_code: v.code,
        answer,
      }, { 'X-API-Key': apiKey });

      if (!verifyRes.data.success) {
        return res.status(400).json({
          error: 'Verification failed',
          moltbook_error: verifyRes.data.error || verifyRes.data,
          challenge: v.challenge,
          our_answer: answer,
        });
      }

      return res.json({
        success: true,
        message: 'Posted to Moltbook! 🦞',
        post_id: postRes.data.post?.id,
        post_url: `https://moltbook.com/m/${targetSubmolt}/${postRes.data.post?.id}`,
        verified: true,
      });
    }

    // No verification needed (trusted agent)
    return res.json({
      success: true,
      message: 'Posted to Moltbook! 🦞',
      post_id: postRes.data.post?.id,
      post_url: `https://moltbook.com/m/${targetSubmolt}/${postRes.data.post?.id}`,
      verified: false,
    });
  } catch (err) {
    res.status(500).json({ error: `Moltbook API error: ${err.message}` });
  }
});

// --- GitHub Repository Scanner (MOVED - see above getScanResult) ---
// Skill file patterns to look for in repos
const SKILL_FILE_PATTERNS = [
  'SKILL.md', 'skill.md', 'skill.json', 'skill.yaml', 'skill.yml',
  'TOOL.md', 'tool.md', 'plugin.json', 'manifest.json',
  'ai-plugin.json', '.well-known/ai-plugin.json',
  'mcp.json', '.mcp.json', 'mcp.yaml', 'mcp.yml',
  'AGENTS.md', 'agents.md',
];

// File extensions that commonly contain skill definitions
const SKILL_EXTENSIONS = ['.skill.md', '.tool.md', '.skill.json', '.skill.yaml'];

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Request timeout (15s)')), 15000);
    const client = url.startsWith('https') ? https : http;
    client.get(url, {
      headers: { 'User-Agent': 'SkillAudit/0.8', 'Accept': 'application/json' },
      timeout: 15000,
    }, (res) => {
      if (res.statusCode !== 200) { clearTimeout(timeout); return reject(new Error(`HTTP ${res.statusCode}`)); }
      let data = '';
      res.on('data', chunk => { data += chunk; if (data.length > 1024 * 256) { res.destroy(); clearTimeout(timeout); reject(new Error('Response too large')); } });
      res.on('end', () => { clearTimeout(timeout); try { resolve(JSON.parse(data)); } catch (e) { reject(new Error('Invalid JSON')); } });
    }).on('error', (e) => { clearTimeout(timeout); reject(e); });
  });
}

async function discoverSkillFiles(owner, repo, branch) {
  // Use GitHub API to get the repo tree recursively
  const treeUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`;
  const tree = await fetchJson(treeUrl);

  if (!tree.tree) throw new Error('Could not read repository tree');

  const skillFiles = [];

  for (const item of tree.tree) {
    if (item.type !== 'blob') continue;
    const filename = item.path.split('/').pop().toLowerCase();
    const pathLower = item.path.toLowerCase();

    // Match known skill file names
    if (SKILL_FILE_PATTERNS.some(p => filename === p.toLowerCase())) {
      skillFiles.push(item.path);
      continue;
    }

    // Match skill extensions
    if (SKILL_EXTENSIONS.some(ext => pathLower.endsWith(ext))) {
      skillFiles.push(item.path);
      continue;
    }

    // Match README.md in src/ subdirectories (common for MCP server repos)
    if (filename === 'readme.md' && /^src\/[^\/]+\/readme\.md$/i.test(pathLower)) {
      skillFiles.push(item.path);
      continue;
    }

    // Match files in skill-related directories
    if (/\b(skills?|tools?|plugins?|mcp|servers?)\b/i.test(item.path) &&
        /\.(md|json|yaml|yml)$/i.test(item.path) &&
        item.size && item.size < 100000) {
      const dirPart = item.path.split('/').slice(0, -1).join('/').toLowerCase();
      if (/\b(skills?|tools?|plugins?|mcp|servers?)\b/.test(dirPart)) {
        skillFiles.push(item.path);
      }
    }
  }

  // Deduplicate and limit
  return [...new Set(skillFiles)].slice(0, 30);
}

// --- Domain Reputation API ---
app.get('/reputation/:domain', async (req, res) => {
  const domain = req.params.domain.toLowerCase();
  const rep = await db.getDomainReputation(domain);
  if (!rep) {
    return res.json({
      domain,
      reputation: 'unknown',
      reputationScore: null,
      scanCount: 0,
      message: 'No scan history for this domain. Scan a skill from this domain first.',
      scanUrl: `https://skillaudit.vercel.app/scan/quick?url=https://${domain}/SKILL.md`,
    });
  }
  res.json(rep);
});

app.post('/reputation/bulk', async (req, res) => {
  const { domains } = req.body;
  if (!domains || !Array.isArray(domains) || domains.length === 0) {
    return res.status(400).json({ error: 'domains array is required' });
  }
  if (domains.length > 50) {
    return res.status(400).json({ error: 'Maximum 50 domains per request' });
  }
  const results = await Promise.all(
    domains.map(async (d) => {
      const domain = String(d).toLowerCase();
      const rep = await db.getDomainReputation(domain);
      return rep || { domain, reputation: 'unknown', reputationScore: null, scanCount: 0 };
    })
  );
  const trusted = results.filter(r => r.reputation === 'trusted').length;
  const suspicious = results.filter(r => r.reputation === 'suspicious' || r.reputation === 'dangerous').length;
  const unknown = results.filter(r => r.reputation === 'unknown').length;
  res.json({
    total: domains.length,
    summary: { trusted, suspicious, unknown },
    results,
  });
});

// --- Threat Intelligence Feed API ---
app.get('/feed', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const severity = req.query.severity || null; // filter: critical, high, medium, low
  const [threats, flaggedDomains, ruleHits, totalScans_] = await Promise.all([
    db.getRecentThreats(limit, severity),
    db.getRecentFlaggedDomains(10),
    db.getRuleHits(),
    db.getScanCount(),
  ]);

  // Build trending rules (top 10 by hit count)
  const trendingRules = Object.entries(ruleHits)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 10)
    .map(([ruleId, count]) => ({ ruleId, hitCount: count }));

  // Severity breakdown of recent threats
  const sevBreakdown = { critical: 0, high: 0, medium: 0, low: 0 };
  threats.forEach(t => { if (sevBreakdown[t.severity] !== undefined) sevBreakdown[t.severity]++; });

  // Unique domains in recent threats
  const uniqueDomains = [...new Set(threats.map(t => t.domain).filter(Boolean))];

  res.json({
    feedVersion: '1.0',
    generatedAt: new Date().toISOString(),
    description: 'SkillAudit Threat Intelligence Feed — real-time security findings from AI skill scans',
    totalScansProcessed: totalScans_,
    recentThreats: {
      count: threats.length,
      severityBreakdown: sevBreakdown,
      uniqueDomains: uniqueDomains.length,
      items: threats,
    },
    flaggedDomains: {
      count: flaggedDomains.length,
      items: flaggedDomains,
    },
    trendingRules: {
      count: trendingRules.length,
      description: 'Most frequently triggered detection rules across all scans',
      items: trendingRules,
    },
    subscribe: {
      polling: 'GET /feed?severity=high&limit=50 — poll for updates',
      since: 'GET /feed/since?ts=<unix_ms> — get threats after a timestamp',
      webhook: 'POST /scan/url with callback parameter for per-scan notifications',
    },
  });
});

app.get('/feed/threats', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const severity = req.query.severity || null;
  const threats = await db.getRecentThreats(limit, severity);
  res.json({ count: threats.length, items: threats });
});

app.get('/feed/since', async (req, res) => {
  const ts = parseInt(req.query.ts);
  if (!ts) return res.status(400).json({ error: 'ts query parameter required (unix milliseconds)', example: '/feed/since?ts=1708070400000' });
  const threats = await db.getThreatsAfter(ts);
  res.json({ since: new Date(ts).toISOString(), count: threats.length, items: threats });
});

app.get('/feed/domains', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 30, 100);
  const domains = await db.getRecentFlaggedDomains(limit);
  res.json({ count: domains.length, items: domains });
});

app.get('/feed/rules', async (req, res) => {
  const [allTime, today] = await Promise.all([
    db.getRuleHits(),
    db.getDailyRuleHits(new Date().toISOString().slice(0, 10)),
  ]);
  const allTimeSorted = Object.entries(allTime).sort(([, a], [, b]) => b - a).map(([ruleId, count]) => ({ ruleId, hitCount: count }));
  const todaySorted = Object.entries(today).sort(([, a], [, b]) => b - a).map(([ruleId, count]) => ({ ruleId, hitCount: count }));
  res.json({
    allTime: { count: allTimeSorted.length, items: allTimeSorted },
    today: { count: todaySorted.length, items: todaySorted },
  });
});

// --- Watchlist / Monitoring API ---

// Add a URL to watchlist
app.post('/watchlist', scanLimiter, async (req, res) => {
  const apiKey = req.query.key || req.headers['x-api-key'];
  if (!apiKey || !API_KEYS.has(apiKey)) {
    return res.status(401).json({ error: 'API key required. Pass ?key=YOUR_KEY or X-API-Key header.', hint: 'Contact @Megamind_0x for an API key.' });
  }
  const { url, label, webhook } = req.body;
  if (!url) return res.status(400).json({ error: 'url is required' });

  // Check limit (max 50 per key)
  const existing = await db.getWatchlist(apiKey);
  if (existing.length >= 50) {
    return res.status(400).json({ error: 'Watchlist limit reached (50 URLs). Remove some first.' });
  }
  // Prevent duplicates
  if (existing.find(i => i.url === url)) {
    return res.status(409).json({ error: 'URL already on watchlist', existing: existing.find(i => i.url === url) });
  }

  // Do initial scan
  let initialResult = null;
  try {
    const content = await fetchUrl(url);
    initialResult = scanContent(content, url);
    const scanId = recordScan(url, initialResult);
    initialResult.id = scanId;
  } catch (err) {
    return res.status(400).json({ error: `Failed to fetch URL: ${err.message}` });
  }

  const id = crypto.randomBytes(6).toString('hex');
  const item = {
    id,
    url,
    label: label || getDomain(url) || url,
    webhook: webhook || null,
    addedAt: new Date().toISOString(),
    lastRisk: initialResult.riskLevel,
    lastScore: initialResult.riskScore,
    lastScanId: initialResult.id,
    lastScanAt: new Date().toISOString(),
    scanCount: 1,
    alerts: [],
  };

  await db.addWatchlistItem(apiKey, item);

  res.json({
    success: true,
    message: 'URL added to watchlist and initial scan complete.',
    item,
    initialScan: {
      riskLevel: initialResult.riskLevel,
      riskScore: initialResult.riskScore,
      findings: initialResult.summary.total,
      reportUrl: `/report/${initialResult.id}`,
    },
  });
});

// List watchlist
app.get('/watchlist', async (req, res) => {
  const apiKey = req.query.key || req.headers['x-api-key'];
  if (!apiKey || !API_KEYS.has(apiKey)) {
    return res.status(401).json({ error: 'API key required.' });
  }
  const items = await db.getWatchlist(apiKey);
  const hasAlerts = items.filter(i => i.alerts && i.alerts.length > 0);
  res.json({
    count: items.length,
    alertCount: hasAlerts.length,
    items: items.sort((a, b) => (b.lastScore || 0) - (a.lastScore || 0)),
  });
});

// Check/re-scan all watchlist URLs (or one by id)
app.post('/watchlist/check', scanLimiter, async (req, res) => {
  const apiKey = req.query.key || req.headers['x-api-key'];
  if (!apiKey || !API_KEYS.has(apiKey)) {
    return res.status(401).json({ error: 'API key required.' });
  }
  const { id: targetId } = req.body || {};
  let items = await db.getWatchlist(apiKey);
  if (targetId) {
    items = items.filter(i => i.id === targetId);
    if (items.length === 0) return res.status(404).json({ error: 'Watchlist item not found' });
  }

  const results = [];
  for (const item of items) {
    const prevRisk = item.lastRisk;
    const prevScore = item.lastScore;
    try {
      const content = await fetchUrl(item.url);
      const result = scanContent(content, item.url);
      const scanId = recordScan(item.url, result);

      const riskChanged = prevRisk !== result.riskLevel;
      const scoreDelta = result.riskScore - (prevScore || 0);

      // Update item
      item.lastRisk = result.riskLevel;
      item.lastScore = result.riskScore;
      item.lastScanId = scanId;
      item.lastScanAt = new Date().toISOString();
      item.scanCount = (item.scanCount || 0) + 1;

      // Record alert if risk changed
      if (riskChanged) {
        const alert = {
          type: scoreDelta > 0 ? 'risk_increased' : 'risk_decreased',
          from: prevRisk,
          to: result.riskLevel,
          scoreDelta,
          detectedAt: new Date().toISOString(),
          scanId,
        };
        item.alerts = [alert, ...(item.alerts || []).slice(0, 9)]; // Keep last 10 alerts

        // Fire webhook if configured
        if (item.webhook) {
          fireCallback(item.webhook, {
            event: 'risk_changed',
            watchlistId: item.id,
            url: item.url,
            label: item.label,
            ...alert,
            reportUrl: `https://skillaudit.vercel.app/report/${scanId}`,
          });
        }
      }

      await db.updateWatchlistItem(apiKey, item);

      results.push({
        id: item.id,
        url: item.url,
        label: item.label,
        status: 'scanned',
        riskLevel: result.riskLevel,
        riskScore: result.riskScore,
        previousRisk: prevRisk,
        riskChanged,
        scoreDelta,
        findings: result.summary.total,
        reportUrl: `/report/${scanId}`,
      });
    } catch (err) {
      results.push({ id: item.id, url: item.url, status: 'error', error: err.message });
    }
  }

  const changed = results.filter(r => r.riskChanged);
  const increased = changed.filter(r => r.scoreDelta > 0);
  const decreased = changed.filter(r => r.scoreDelta < 0);

  res.json({
    checkedAt: new Date().toISOString(),
    total: results.length,
    changed: changed.length,
    riskIncreased: increased.length,
    riskDecreased: decreased.length,
    verdict: changed.length === 0
      ? '✅ All clear — no risk changes detected.'
      : increased.length > 0
        ? `🔴 ${increased.length} URL(s) increased in risk! Review immediately.`
        : `✅ ${decreased.length} URL(s) decreased in risk. Looking better.`,
    results,
  });
});

// Remove from watchlist
app.delete('/watchlist/:id', async (req, res) => {
  const apiKey = req.query.key || req.headers['x-api-key'];
  if (!apiKey || !API_KEYS.has(apiKey)) {
    return res.status(401).json({ error: 'API key required.' });
  }
  const item = await db.getWatchlistItem(apiKey, req.params.id);
  if (!item) return res.status(404).json({ error: 'Watchlist item not found' });
  await db.removeWatchlistItem(apiKey, req.params.id);
  res.json({ success: true, message: `Removed ${item.url} from watchlist`, removed: item });
});

// Get watchlist alerts (all risk changes across watched URLs)
app.get('/watchlist/alerts', async (req, res) => {
  const apiKey = req.query.key || req.headers['x-api-key'];
  if (!apiKey || !API_KEYS.has(apiKey)) {
    return res.status(401).json({ error: 'API key required.' });
  }
  const items = await db.getWatchlist(apiKey);
  const allAlerts = [];
  for (const item of items) {
    if (item.alerts) {
      for (const alert of item.alerts) {
        allAlerts.push({ url: item.url, label: item.label, watchlistId: item.id, ...alert });
      }
    }
  }
  allAlerts.sort((a, b) => new Date(b.detectedAt) - new Date(a.detectedAt));
  res.json({ count: allAlerts.length, items: allAlerts });
});

// --- OpenAPI 3.0 Spec ---
app.get('/openapi.json', (req, res) => {
  res.json({
    openapi: '3.0.3',
    info: {
      title: 'SkillAudit API', version: '0.7.0',
      description: 'Security scanner for AI agent skills. Detects credential theft, data exfiltration, prompt injection, and more.',
      contact: { name: 'Megamind_0x', url: 'https://moltbook.com/u/Megamind_0x' },
    },
    servers: [{ url: 'https://skillaudit.vercel.app', description: 'Production' }],
    paths: {
      '/gate': { get: { summary: 'Pre-install gate — should I install this skill?', description: 'The infrastructure endpoint. Returns a simple allow/warn/deny decision with minimal JSON. Designed for agents to call before installing ANY skill. One call, one answer.', parameters: [{ name: 'url', in: 'query', required: true, schema: { type: 'string' }, description: 'URL of the skill to check' }, { name: 'threshold', in: 'query', required: false, schema: { type: 'string', enum: ['low', 'moderate', 'high', 'critical'], default: 'moderate' }, description: 'Risk threshold — deny at or above this level' }], responses: { '200': { description: 'Gate decision: {allow: bool, decision: "allow"|"warn"|"deny", risk, score, findings, verdict}' }, '400': { description: 'Missing URL or fetch error' } } } },
      '/scan/quick': { get: { summary: 'Quick scan by URL (GET)', description: 'Simplest way to scan — just pass a URL as query parameter. Perfect for agents.', parameters: [{ name: 'url', in: 'query', required: true, schema: { type: 'string' }, description: 'URL of the skill file to scan' }], responses: { '200': { description: 'Scan result with risk level, findings, and verdict' }, '400': { description: 'Missing or invalid URL' } } } },
      '/scan/url': { post: { summary: 'Scan a skill by URL', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['url'], properties: { url: { type: 'string' }, callback: { type: 'string' } } } } } }, responses: { '200': { description: 'Scan result' } } } },
      '/scan/content': { post: { summary: 'Scan raw skill content', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['content'], properties: { content: { type: 'string' }, source: { type: 'string' } } } } } }, responses: { '200': { description: 'Scan result' } } } },
      '/scan/deep': { post: { summary: 'Deep scan with capability analysis (x402: $0.05 USDC on Base/Solana)', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { url: { type: 'string' }, content: { type: 'string' } } } } } }, responses: { '200': { description: 'Deep scan result' }, '402': { description: 'Payment required — send USDC then retry with X-Payment-TX header' } } } },
      '/scan/batch': { post: { summary: 'Batch scan up to 20 URLs (x402: $0.10 USDC on Base/Solana)', responses: { '200': { description: 'Batch results' }, '402': { description: 'Payment required' } } } },
      '/scan/compare': { post: { summary: 'Compare two skill versions (x402: $0.05 USDC on Base/Solana)', responses: { '200': { description: 'Comparison result' }, '402': { description: 'Payment required' } } } },
      '/scan/repo': { get: { summary: 'Scan a GitHub repository for skill files', description: 'Auto-discovers SKILL.md, skill.json, plugin.json, mcp.json, and files in skills/tools/plugins directories. Scans them all and returns aggregated results.', parameters: [{ name: 'repo', in: 'query', required: true, schema: { type: 'string' }, description: 'GitHub repo in owner/name format', example: 'modelcontextprotocol/servers' }, { name: 'branch', in: 'query', required: false, schema: { type: 'string', default: 'main' }, description: 'Branch to scan' }], responses: { '200': { description: 'Repository scan results with per-file breakdown' }, '404': { description: 'Repository not found' } } } },
      '/scan/{id}': { get: { summary: 'Get scan result (JSON)', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { '200': { description: 'Scan result' } } } },
      '/report/{id}': { get: { summary: 'View scan report (HTML)', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { '200': { description: 'HTML report' } } } },
      '/rules': { get: { summary: 'List detection rules', responses: { '200': { description: 'Rule list' } } } },
      '/history': { get: { summary: 'Recent scan history', responses: { '200': { description: 'History' } } } },
      '/stats': { get: { summary: 'Scan statistics', responses: { '200': { description: 'Stats' } } } },
      '/badge/request': { post: { summary: 'Request trust badge', responses: { '200': { description: 'Badge result' } } } },
      '/badge/{domain}': { get: { summary: 'Check domain badge (JSON)', responses: { '200': { description: 'Badge info' } } } },
      '/badge/{domain}.svg': { get: { summary: 'Get SVG badge image for a domain', description: 'Returns an embeddable SVG badge showing the domain\'s scan status. Use in README files: ![SkillAudit](https://skillaudit.vercel.app/badge/example.com.svg)', responses: { '200': { description: 'SVG badge image', content: { 'image/svg+xml': {} } } } } },
      '/badge/scan.svg': { get: { summary: 'Live scan badge — scan a URL and return SVG badge', description: 'Scans the given URL and returns an SVG badge with the result. Use: ![](https://skillaudit.vercel.app/badge/scan.svg?url=https://...)', parameters: [{ name: 'url', in: 'query', required: true, schema: { type: 'string' } }], responses: { '200': { description: 'SVG badge image' } } } },
      '/capabilities/{id}': { get: { summary: 'Get capability breakdown for a scan', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { '200': { description: 'Capability analysis' } } } },
      '/share/moltbook': { post: { summary: 'Share scan to Moltbook', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['scanId', 'apiKey'], properties: { scanId: { type: 'string' }, apiKey: { type: 'string' }, submolt: { type: 'string', default: 'general' } } } } } }, responses: { '200': { description: 'Post result' } } } },
      '/reputation/{domain}': { get: { summary: 'Get domain reputation', description: 'Returns aggregated reputation score based on all past scans for this domain. Includes scan count, risk distribution, average risk score, and trust level (trusted/moderate/suspicious/dangerous).', parameters: [{ name: 'domain', in: 'path', required: true, schema: { type: 'string' }, description: 'Domain hostname (e.g. github.com)' }], responses: { '200': { description: 'Domain reputation data' } } } },
      '/reputation/bulk': { post: { summary: 'Bulk domain reputation lookup (up to 50)', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['domains'], properties: { domains: { type: 'array', items: { type: 'string' } } } } } } }, responses: { '200': { description: 'Bulk reputation results' } } } },
      '/feed': { get: { summary: 'Threat intelligence feed — recent threats, flagged domains, trending rules', description: 'Aggregated threat intelligence from all SkillAudit scans. Use for monitoring the AI skill threat landscape. Poll periodically or use /feed/since for incremental updates.', parameters: [{ name: 'limit', in: 'query', schema: { type: 'integer', default: 20 }, description: 'Number of recent threats (max 100)' }, { name: 'severity', in: 'query', schema: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] }, description: 'Filter by minimum severity' }], responses: { '200': { description: 'Threat intelligence feed' } } } },
      '/feed/threats': { get: { summary: 'Recent threat events', parameters: [{ name: 'limit', in: 'query', schema: { type: 'integer', default: 50 } }, { name: 'severity', in: 'query', schema: { type: 'string' } }], responses: { '200': { description: 'Threat events list' } } } },
      '/feed/since': { get: { summary: 'Get threats after a timestamp', parameters: [{ name: 'ts', in: 'query', required: true, schema: { type: 'integer' }, description: 'Unix timestamp in milliseconds' }], responses: { '200': { description: 'Threats since timestamp' } } } },
      '/feed/domains': { get: { summary: 'Recently flagged domains', responses: { '200': { description: 'Flagged domains list' } } } },
      '/feed/rules': { get: { summary: 'Trending detection rules — most triggered all-time and today', responses: { '200': { description: 'Rule hit statistics' } } } },
      '/watchlist': {
        post: { summary: 'Add URL to watchlist', description: 'Register a URL for continuous monitoring. Initial scan is performed immediately. Optional webhook for risk change notifications.', parameters: [{ name: 'key', in: 'query', required: true, schema: { type: 'string' } }], requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['url'], properties: { url: { type: 'string' }, label: { type: 'string' }, webhook: { type: 'string' } } } } } }, responses: { '200': { description: 'URL added with initial scan result' }, '401': { description: 'API key required' } } },
        get: { summary: 'List watched URLs', parameters: [{ name: 'key', in: 'query', required: true, schema: { type: 'string' } }], responses: { '200': { description: 'Watchlist items with current risk status' } } },
      },
      '/watchlist/check': { post: { summary: 'Re-scan watched URLs and detect risk changes', description: 'Re-scans all watched URLs (or one by id). Returns which URLs changed risk level and fires webhooks for changes.', parameters: [{ name: 'key', in: 'query', required: true, schema: { type: 'string' } }], requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { id: { type: 'string', description: 'Optional: check only one watchlist item' } } } } } }, responses: { '200': { description: 'Check results with risk change detection' } } } },
      '/watchlist/{id}': { delete: { summary: 'Remove URL from watchlist', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }, { name: 'key', in: 'query', required: true, schema: { type: 'string' } }], responses: { '200': { description: 'Removed' } } } },
      '/watchlist/alerts': { get: { summary: 'View all risk change alerts across watched URLs', parameters: [{ name: 'key', in: 'query', required: true, schema: { type: 'string' } }], responses: { '200': { description: 'Alert history' } } } },
      '/health': { get: { summary: 'Health check', responses: { '200': { description: 'OK' } } } },
    }
  });
});

// --- SVG Badge Renderer ---
function renderBadgeSvg(label, status) {
  const colors = {
    clean: '#4c1', low: '#97CA00', moderate: '#dfb317', high: '#fe7d37',
    critical: '#e05d44', unaudited: '#9f9f9f', error: '#e05d44',
    'verified-safe': '#4c1', flagged: '#fe7d37',
  };
  const labels = {
    clean: 'clean', low: 'low risk', moderate: 'moderate', high: 'high risk',
    critical: 'critical', unaudited: 'unaudited', error: 'error',
    'verified-safe': 'safe', flagged: 'flagged',
  };
  const color = colors[status] || '#9f9f9f';
  const text = labels[status] || status;
  const labelWidth = label.length * 6.5 + 10;
  const valueWidth = text.length * 6.5 + 10;
  const totalWidth = labelWidth + valueWidth;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="${label}: ${text}">
  <title>${label}: ${text}</title>
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="${totalWidth}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#555"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="20" fill="${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text aria-hidden="true" x="${labelWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${label}</text>
    <text x="${labelWidth / 2}" y="14">${label}</text>
    <text aria-hidden="true" x="${labelWidth + valueWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${text}</text>
    <text x="${labelWidth + valueWidth / 2}" y="14">${text}</text>
  </g>
</svg>`;
}

// --- Report HTML renderer ---
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function riskColor(level) {
  const colors = { clean: '#00ff88', low: '#88ff00', moderate: '#ffaa00', high: '#ff4444', critical: '#ff0044' };
  return colors[level] || '#888';
}

function riskBg(level) {
  const bgs = { clean: '#0a3d1a', low: '#2a3d0a', moderate: '#3d2a0a', high: '#3d1a0a', critical: '#3d0a0a' };
  return bgs[level] || '#1a1a3e';
}

function sevColor(sev) {
  const c = { critical: '#ff0044', high: '#ff4444', medium: '#ffaa00', low: '#88ff00', info: '#888' };
  return c[sev] || '#888';
}

function renderReport(result) {
  const findingsHtml = result.findings.length === 0
    ? '<p style="color:#00ff88;padding:1rem">No security issues found. ✅</p>'
    : result.findings.map(f => `
      <details class="finding" style="border-left:3px solid ${sevColor(f.severity)};margin-bottom:0.5rem;background:#111133;border-radius:0 6px 6px 0">
        <summary style="padding:0.6rem 1rem;cursor:pointer;display:flex;align-items:center;gap:0.5rem">
          <span style="background:${sevColor(f.severity)};color:#000;padding:0.1rem 0.5rem;border-radius:4px;font-size:0.7rem;font-weight:700;text-transform:uppercase">${esc(f.severity)}</span>
          <span style="color:#00ff88;font-weight:700">${esc(f.ruleId)}</span>
          <span>${esc(f.name)}</span>
          <span style="color:#555;margin-left:auto">line ${f.line}</span>
        </summary>
        <div style="padding:0.5rem 1rem 0.8rem;border-top:1px solid #1a1a3e">
          <p style="color:#aaa;font-size:0.85rem;margin-bottom:0.3rem">${esc(f.description)}</p>
          <code style="display:block;background:#0f0f23;padding:0.4rem 0.6rem;border-radius:4px;font-size:0.8rem;color:#e0e0e0;overflow-x:auto">${esc(f.lineContent)}</code>
          ${f.context ? `<span style="color:#555;font-size:0.75rem">Context: ${esc(f.context)}</span>` : ''}
        </div>
      </details>`).join('');

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SkillAudit Report — ${esc(result.source)}</title>
<meta property="og:title" content="SkillAudit Report: ${esc(result.riskLevel).toUpperCase()} risk">
<meta property="og:description" content="${esc(result.verdict)}">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0f0f23;color:#e0e0e0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,monospace;line-height:1.6;padding:1.5rem}
a{color:#00ff88;text-decoration:none}a:hover{text-decoration:underline}
.container{max-width:800px;margin:0 auto}
.header{text-align:center;padding:1.5rem 0}
.header h1{font-size:1.3rem;color:#888}
.header h1 span{color:#00ff88}
.risk-badge{display:inline-block;font-size:2rem;font-weight:900;padding:0.5rem 2rem;border-radius:12px;margin:1rem 0;text-transform:uppercase;background:${riskBg(result.riskLevel)};color:${riskColor(result.riskLevel)};border:2px solid ${riskColor(result.riskLevel)}}
.meta{color:#888;font-size:0.85rem;margin:0.5rem 0}
.verdict{padding:1rem;background:#111133;border-radius:8px;margin:1rem 0;font-size:1.05rem;text-align:center}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:0.5rem;margin:1rem 0}
.summary-item{text-align:center;padding:0.5rem;background:#111133;border-radius:6px}
.summary-item .num{font-size:1.5rem;font-weight:700}
.summary-item .label{font-size:0.7rem;color:#888;text-transform:uppercase}
details summary{list-style:none}details summary::-webkit-details-marker{display:none}
details summary::before{content:'▸ ';color:#555}details[open] summary::before{content:'▾ '}
.footer{text-align:center;padding:2rem 0;color:#555;font-size:0.8rem;border-top:1px solid #1a1a3e;margin-top:2rem}
</style></head><body><div class="container">
<div class="header">
  <h1>🛡️ Skill<span>Audit</span> Report</h1>
  <div class="risk-badge">${esc(result.riskLevel)}</div>
  <p class="meta">Source: <strong>${esc(result.source || result.url || 'unknown')}</strong></p>
  <p class="meta">Scanned: ${esc(result.scannedAt)} · Score: ${result.riskScore} · Engine v${esc(result.version)}</p>
</div>
<div class="verdict">${esc(result.verdict)}</div>
<div class="summary-grid">
  <div class="summary-item"><div class="num" style="color:#fff">${result.summary.total}</div><div class="label">Findings</div></div>
  <div class="summary-item"><div class="num" style="color:#ff0044">${result.summary.critical}</div><div class="label">Critical</div></div>
  <div class="summary-item"><div class="num" style="color:#ff4444">${result.summary.high}</div><div class="label">High</div></div>
  <div class="summary-item"><div class="num" style="color:#ffaa00">${result.summary.medium}</div><div class="label">Medium</div></div>
  <div class="summary-item"><div class="num" style="color:#88ff00">${result.summary.low}</div><div class="label">Low</div></div>
  <div class="summary-item"><div class="num" style="color:#888">${result.summary.suppressed}</div><div class="label">Suppressed</div></div>
</div>
<h2 style="color:#00ff88;font-size:1.1rem;margin:1.5rem 0 0.5rem;border-bottom:1px solid #2a2a5a;padding-bottom:0.5rem">Findings</h2>
${findingsHtml}
<div style="text-align:center;margin:1.5rem 0">
  <button onclick="openMoltbookModal()" style="background:#e01b24;color:#fff;border:none;border-radius:8px;padding:0.6rem 1.5rem;font-size:1rem;font-weight:700;cursor:pointer;font-family:monospace">Share to Moltbook 🦞</button>
</div>
<div id="moltbook-modal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);align-items:center;justify-content:center;z-index:9999">
  <div style="background:#1a1a3e;border:1px solid #2a2a5a;border-radius:12px;padding:1.5rem;max-width:420px;width:90%;font-family:monospace">
    <h3 style="color:#e01b24;margin-bottom:1rem">Share to Moltbook 🦞</h3>
    <label style="color:#888;font-size:0.8rem">Moltbook API Key</label>
    <input id="mb-key" type="password" placeholder="moltbook_sk_..." style="width:100%;background:#0f0f23;border:1px solid #3a3a6a;border-radius:6px;padding:0.5rem;color:#fff;font-family:monospace;margin:0.3rem 0 0.5rem">
    <p style="color:#555;font-size:0.7rem;margin-bottom:0.8rem">Your key is used only for this post and never stored.</p>
    <label style="color:#888;font-size:0.8rem">Submolt</label>
    <select id="mb-submolt" style="width:100%;background:#0f0f23;border:1px solid #3a3a6a;border-radius:6px;padding:0.5rem;color:#fff;font-family:monospace;margin:0.3rem 0 1rem">
      <option value="general">general</option>
      <option value="todayilearned">todayilearned</option>
      <option value="security">security</option>
    </select>
    <div style="display:flex;gap:0.5rem">
      <button id="mb-post" onclick="doPost()" style="flex:1;background:#e01b24;color:#fff;border:none;border-radius:8px;padding:0.6rem;font-weight:700;cursor:pointer;font-family:monospace">Post to Moltbook</button>
      <button onclick="document.getElementById('moltbook-modal').style.display='none'" style="background:#2a2a5a;color:#fff;border:none;border-radius:8px;padding:0.6rem 1rem;cursor:pointer;font-family:monospace">Cancel</button>
    </div>
    <div id="mb-result" style="margin-top:0.8rem;font-size:0.85rem"></div>
  </div>
</div>
<div class="footer">
  <a href="/">← Back to SkillAudit</a> · <a href="/scan/${esc(result.id)}">JSON API</a><br>
  Built by <a href="https://moltbook.com/u/Megamind_0x">Megamind_0x</a> 🧠
</div>
<script>
function openMoltbookModal(){document.getElementById('moltbook-modal').style.display='flex';document.getElementById('mb-key').focus()}
document.getElementById('moltbook-modal').addEventListener('click',function(e){if(e.target===this)this.style.display='none'});
async function doPost(){
  var key=document.getElementById('mb-key').value.trim(),submolt=document.getElementById('mb-submolt').value,btn=document.getElementById('mb-post'),r=document.getElementById('mb-result');
  if(!key){r.innerHTML='<span style="color:#ff4444">Please enter your API key</span>';return}
  btn.disabled=true;btn.textContent='Posting...';r.innerHTML='';
  try{var res=await fetch('/share/moltbook',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scanId:'${esc(result.id)}',apiKey:key,submolt:submolt})});
  var data=await res.json();
  if(data.success){r.innerHTML='<span style="color:#00ff88">✅ Posted!</span> <a href="'+data.post_url+'" target="_blank" style="color:#00ff88">'+data.post_url+'</a>'}
  else{r.innerHTML='<span style="color:#ff4444">'+(data.error||'Failed')+'</span>'+(data.hint?'<br><span style="color:#888">'+data.hint+'</span>':'')+(data.retry_after_minutes?'<br><span style="color:#888">Retry after '+data.retry_after_minutes+' min</span>':'')}}
  catch(e){r.innerHTML='<span style="color:#ff4444">Error: '+e.message+'</span>'}
  finally{btn.disabled=false;btn.textContent='Post to Moltbook'}
}
</script>
</div></body></html>`;
}

function reportNotFound() {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Report Not Found</title>
<style>body{background:#0f0f23;color:#e0e0e0;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh}
.box{text-align:center}a{color:#00ff88}</style></head><body><div class="box">
<h1>404</h1><p>Scan report not found or expired.</p><p><a href="/">← Back to SkillAudit</a></p></div></body></html>`;
}

const PORT = process.env.PORT || 3847;
app.listen(PORT, () => {
  console.log(`🛡️  SkillAudit v0.7.0 running on port ${PORT}`);
});
