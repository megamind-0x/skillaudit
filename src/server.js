const express = require('express');
const path = require('path');
const https = require('https');
const http = require('http');
const rateLimit = require('express-rate-limit');
const { scanContent } = require('./scanner');

const app = express();
app.use(express.json({ limit: '1mb' }));

// --- API Keys that bypass rate limits ---
const API_KEYS = new Set((process.env.SKILLAUDIT_API_KEYS || 'sk-skillaudit-dev').split(','));

// --- Rate Limiting ---
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => API_KEYS.has(req.query.key),
  message: { error: 'Too many requests. Max 30 per minute. Use ?key= for higher limits.', retryAfter: 60 }
});

// --- Scan History (in-memory) ---
const MAX_HISTORY = 100;
const scanHistory = [];
let totalScans = 0;

function recordScan(url, result) {
  totalScans++;
  scanHistory.unshift({
    url,
    timestamp: new Date().toISOString(),
    riskLevel: result.riskLevel,
    riskScore: result.riskScore
  });
  if (scanHistory.length > MAX_HISTORY) scanHistory.pop();
}

// --- Badge System (in-memory) ---
const badges = new Map(); // domain -> { status, url, updatedAt }

// --- Fetch URL ---
function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    client.get(url, { headers: { 'User-Agent': 'SkillAudit/0.2' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchUrl(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

function getDomain(url) {
  try { return new URL(url).hostname; } catch { return null; }
}

// --- Static landing page ---
app.get('/', (req, res) => {
  // If Accept header wants JSON, return API info
  if (req.headers.accept && req.headers.accept.includes('application/json') && !req.headers.accept.includes('text/html')) {
    return res.json({
      name: 'SkillAudit', version: '0.2.0',
      description: 'Security scanner for AI agent skills',
      endpoints: {
        'POST /scan/url': 'Scan a skill.md by URL',
        'POST /scan/content': 'Scan raw skill content',
        'GET /rules': 'List detection rules',
        'GET /history': 'Recent scan history',
        'GET /stats': 'Scan statistics',
        'POST /badge/request': 'Request a trust badge',
        'GET /badge/:domain': 'Check domain badge',
        'GET /health': 'Health check'
      }
    });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '0.2.0', uptime: process.uptime() });
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

// --- Scan endpoints ---
app.post('/scan/url', scanLimiter, async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'url is required' });
  try {
    const content = await fetchUrl(url);
    const result = scanContent(content, url);
    recordScan(url, result);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: `Failed to fetch: ${err.message}` });
  }
});

app.post('/scan/content', scanLimiter, (req, res) => {
  const { content, source } = req.body;
  if (!content) return res.status(400).json({ error: 'content is required' });
  const result = scanContent(content, source || 'direct-input');
  recordScan(source || 'direct-input', result);
  res.json(result);
});

// --- History ---
app.get('/history', (req, res) => {
  res.json({ count: scanHistory.length, total: totalScans, scans: scanHistory });
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

const PORT = process.env.PORT || 3847;
app.listen(PORT, () => {
  console.log(`🛡️  SkillAudit v0.2.0 running on port ${PORT}`);
});
