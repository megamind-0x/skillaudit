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
  if (result.threatChains) {
    result.threatChains.forEach(chain => db.incrThreatType(chain.name));
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
    description_for_model: 'Scan AI agent skill files for security risks. Send a URL to /scan/quick?url=<url> (GET) for instant results, or POST to /scan/url with {"url":"..."} for full analysis. Returns risk level (clean/low/moderate/high/critical), findings, and verdict.',
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

// --- Capability Breakdown (v0.6.1) ---
app.get('/capabilities/:id', (req, res) => {
  const result = sharedScans.get(req.params.id);
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

// --- Shared Scan Result (JSON) ---
app.get('/scan/:id', (req, res) => {
  const result = sharedScans.get(req.params.id);
  if (!result) return res.status(404).json({ error: 'Scan not found' });
  res.json(result);
});

// --- Report Page (HTML) ---
app.get('/report/:id', (req, res) => {
  const result = sharedScans.get(req.params.id);
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

  const result = sharedScans.get(scanId);
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
      '/scan/quick': { get: { summary: 'Quick scan by URL (GET)', description: 'Simplest way to scan — just pass a URL as query parameter. Perfect for agents.', parameters: [{ name: 'url', in: 'query', required: true, schema: { type: 'string' }, description: 'URL of the skill file to scan' }], responses: { '200': { description: 'Scan result with risk level, findings, and verdict' }, '400': { description: 'Missing or invalid URL' } } } },
      '/scan/url': { post: { summary: 'Scan a skill by URL', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['url'], properties: { url: { type: 'string' }, callback: { type: 'string' } } } } } }, responses: { '200': { description: 'Scan result' } } } },
      '/scan/content': { post: { summary: 'Scan raw skill content', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['content'], properties: { content: { type: 'string' }, source: { type: 'string' } } } } } }, responses: { '200': { description: 'Scan result' } } } },
      '/scan/deep': { post: { summary: 'Deep scan with capability analysis (x402: $0.05 USDC on Base/Solana)', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { url: { type: 'string' }, content: { type: 'string' } } } } } }, responses: { '200': { description: 'Deep scan result' }, '402': { description: 'Payment required — send USDC then retry with X-Payment-TX header' } } } },
      '/scan/batch': { post: { summary: 'Batch scan up to 20 URLs (x402: $0.10 USDC on Base/Solana)', responses: { '200': { description: 'Batch results' }, '402': { description: 'Payment required' } } } },
      '/scan/compare': { post: { summary: 'Compare two skill versions (x402: $0.05 USDC on Base/Solana)', responses: { '200': { description: 'Comparison result' }, '402': { description: 'Payment required' } } } },
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
