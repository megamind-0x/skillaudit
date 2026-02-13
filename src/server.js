const express = require('express');
const path = require('path');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { scanContent } = require('./scanner');

const app = express();
app.use(express.json({ limit: '2mb' }));

// --- API Keys ---
const API_KEYS = new Set((process.env.SKILLAUDIT_API_KEYS || 'sk-skillaudit-dev').split(','));

// --- Rate Limiting ---
const scanLimiter = rateLimit({
  windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false,
  skip: (req) => API_KEYS.has(req.query.key),
  message: { error: 'Too many requests. Max 30 per minute.', retryAfter: 60 }
});

// --- Scan History & Shared Results (in-memory) ---
const MAX_HISTORY = 100;
const scanHistory = [];
let totalScans = 0;
const sharedScans = new Map(); // id -> full result

function recordScan(url, result) {
  totalScans++;
  const id = crypto.randomBytes(6).toString('hex');
  const entry = { id, url, timestamp: new Date().toISOString(), riskLevel: result.riskLevel, riskScore: result.riskScore };
  scanHistory.unshift(entry);
  if (scanHistory.length > MAX_HISTORY) scanHistory.pop();
  sharedScans.set(id, { ...result, id });
  if (sharedScans.size > 500) {
    const oldest = sharedScans.keys().next().value;
    sharedScans.delete(oldest);
  }
  return id;
}

// --- Badge System ---
const badges = new Map();

// --- Fetch URL ---
function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    client.get(url, { headers: { 'User-Agent': 'SkillAudit/0.3' }, timeout: 15000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchUrl(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
      let data = '';
      res.on('data', chunk => { data += chunk; if (data.length > 1024 * 512) { res.destroy(); reject(new Error('Content too large')); } });
      res.on('end', () => resolve(data));
    }).on('error', reject).on('timeout', () => reject(new Error('Timeout')));
  });
}

function getDomain(url) {
  try { return new URL(url).hostname; } catch { return null; }
}

// --- Fire webhook callback ---
function fireCallback(callbackUrl, result) {
  try {
    const url = new URL(callbackUrl);
    const payload = JSON.stringify(result);
    const options = {
      hostname: url.hostname, port: url.port, path: url.pathname + url.search,
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), 'User-Agent': 'SkillAudit/0.3-webhook' },
      timeout: 10000,
    };
    const client = url.protocol === 'https:' ? https : http;
    const req = client.request(options);
    req.on('error', () => {}); // fire-and-forget
    req.write(payload);
    req.end();
  } catch {}
}

// --- CORS ---
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// --- Static landing page ---
app.get('/', (req, res) => {
  if (req.headers.accept && req.headers.accept.includes('application/json') && !req.headers.accept.includes('text/html')) {
    return res.json({
      name: 'SkillAudit', version: '0.3.0',
      description: 'Security scanner for AI agent skills — structural analysis, URL reputation, intent detection',
      docs: '/openapi.json',
      endpoints: {
        'POST /scan/url': 'Scan a skill by URL (supports callback)',
        'POST /scan/content': 'Scan raw skill content',
        'POST /scan/batch': 'Batch scan multiple URLs',
        'POST /scan/compare': 'Compare two skill versions',
        'GET /scan/:id': 'Get shared scan result',
        'GET /rules': 'List detection rules',
        'GET /history': 'Recent scan history',
        'GET /stats': 'Scan statistics',
        'POST /badge/request': 'Request a trust badge',
        'GET /badge/:domain': 'Check domain badge',
        'GET /openapi.json': 'OpenAPI 3.0 spec',
        'GET /health': 'Health check',
      }
    });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '0.3.0', uptime: process.uptime() });
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

// --- Scan URL (with optional callback) ---
app.post('/scan/url', scanLimiter, async (req, res) => {
  const { url, callback } = req.body;
  if (!url) return res.status(400).json({ error: 'url is required' });
  try {
    const content = await fetchUrl(url);
    const result = scanContent(content, url);
    const id = recordScan(url, result);
    result.id = id;
    result.shareUrl = `/scan/${id}`;
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
      return { url, status: 'success', id, ...result, shareUrl: `/scan/${id}` };
    } catch (err) {
      return { url, status: 'error', error: err.message };
    }
  }));

  const successful = results.filter(r => r.status === 'success');
  const failed = results.filter(r => r.status === 'error');
  const riskBreakdown = { clean: 0, low: 0, moderate: 0, high: 0, critical: 0 };
  successful.forEach(r => { riskBreakdown[r.riskLevel] = (riskBreakdown[r.riskLevel] || 0) + 1; });

  res.json({
    total: urls.length,
    successful: successful.length,
    failed: failed.length,
    riskBreakdown,
    results
  });
});

// --- Compare two skill versions ---
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
      scoreDelta,
      riskChanged: oldResult.riskLevel !== newResult.riskLevel,
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

// --- Shared Scan Result ---
app.get('/scan/:id', (req, res) => {
  const result = sharedScans.get(req.params.id);
  if (!result) return res.status(404).json({ error: 'Scan not found' });
  res.json(result);
});

// --- History ---
app.get('/history', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 100);
  res.json({ count: scanHistory.length, total: totalScans, scans: scanHistory.slice(0, limit) });
});

// --- Stats ---
app.get('/stats', (req, res) => {
  const riskDist = { clean: 0, low: 0, moderate: 0, high: 0, critical: 0 };
  const domains = {};
  for (const s of scanHistory) {
    riskDist[s.riskLevel] = (riskDist[s.riskLevel] || 0) + 1;
    const d = getDomain(s.url);
    if (d) domains[d] = (domains[d] || 0) + 1;
  }
  const topDomains = Object.entries(domains).sort((a, b) => b[1] - a[1]).slice(0, 10)
    .map(([domain, count]) => ({ domain, count }));
  res.json({ totalScans, recentScans: scanHistory.length, riskDistribution: riskDist, topDomains });
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
    const status = result.riskLevel === 'clean' ? 'verified-safe' : 'flagged';
    badges.set(domain, { status, url, riskLevel: result.riskLevel, riskScore: result.riskScore, updatedAt: new Date().toISOString() });
    res.json({ domain, badge: status, scan: result });
  } catch (err) {
    res.status(400).json({ error: `Failed to fetch: ${err.message}` });
  }
});

app.get('/badge/:domain', (req, res) => {
  const info = badges.get(req.params.domain);
  if (!info) return res.json({ domain: req.params.domain, badge: 'unaudited' });
  res.json({ domain: req.params.domain, ...info });
});

// --- OpenAPI 3.0 Spec ---
app.get('/openapi.json', (req, res) => {
  res.json({
    openapi: '3.0.3',
    info: {
      title: 'SkillAudit API',
      version: '0.3.0',
      description: 'Security scanner for AI agent skills. Detects credential theft, data exfiltration, prompt injection, and more using structural analysis, URL reputation checking, and intent analysis.',
      contact: { name: 'Megamind_0x', url: 'https://moltbook.com/u/Megamind_0x' },
    },
    servers: [{ url: 'https://skillaudit.vercel.app', description: 'Production' }],
    paths: {
      '/scan/url': {
        post: {
          summary: 'Scan a skill by URL',
          description: 'Fetches the skill content from the given URL and runs security analysis. Supports optional webhook callback.',
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['url'], properties: { url: { type: 'string', description: 'URL of the skill to scan' }, callback: { type: 'string', description: 'Optional webhook URL to POST results to' } } } } } },
          responses: { '200': { description: 'Scan result' }, '400': { description: 'Invalid request or fetch error' } }
        }
      },
      '/scan/content': {
        post: {
          summary: 'Scan raw skill content',
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['content'], properties: { content: { type: 'string' }, source: { type: 'string' } } } } } },
          responses: { '200': { description: 'Scan result' } }
        }
      },
      '/scan/batch': {
        post: {
          summary: 'Batch scan multiple URLs',
          description: 'Scan up to 20 skill URLs in one request.',
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['urls'], properties: { urls: { type: 'array', items: { type: 'string' }, maxItems: 20 } } } } } },
          responses: { '200': { description: 'Batch scan results' } }
        }
      },
      '/scan/compare': {
        post: {
          summary: 'Compare two skill versions',
          description: 'Scan two versions of a skill and return the diff in findings.',
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['oldUrl', 'newUrl'], properties: { oldUrl: { type: 'string' }, newUrl: { type: 'string' } } } } } },
          responses: { '200': { description: 'Comparison result with new/resolved findings' } }
        }
      },
      '/scan/{id}': {
        get: {
          summary: 'Get shared scan result',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: { '200': { description: 'Scan result' }, '404': { description: 'Not found' } }
        }
      },
      '/rules': { get: { summary: 'List detection rules', responses: { '200': { description: 'Rule list' } } } },
      '/history': { get: { summary: 'Recent scan history', parameters: [{ name: 'limit', in: 'query', schema: { type: 'integer', maximum: 100 } }], responses: { '200': { description: 'Scan history' } } } },
      '/stats': { get: { summary: 'Scan statistics', responses: { '200': { description: 'Statistics' } } } },
      '/badge/request': {
        post: {
          summary: 'Request a trust badge',
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['url'], properties: { url: { type: 'string' } } } } } },
          responses: { '200': { description: 'Badge result' } }
        }
      },
      '/badge/{domain}': {
        get: {
          summary: 'Check domain badge',
          parameters: [{ name: 'domain', in: 'path', required: true, schema: { type: 'string' } }],
          responses: { '200': { description: 'Badge info' } }
        }
      },
      '/health': { get: { summary: 'Health check', responses: { '200': { description: 'OK' } } } },
    }
  });
});

const PORT = process.env.PORT || 3847;
app.listen(PORT, () => {
  console.log(`🛡️  SkillAudit v0.3.0 running on port ${PORT}`);
});
