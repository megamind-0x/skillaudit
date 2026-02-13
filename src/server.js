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

// --- Scan History & Shared Results (in-memory) ---
const MAX_HISTORY = 100;
const scanHistory = [];
let totalScans = 0;
const sharedScans = new Map();
const badgedDomains = new Set();

function recordScan(url, result) {
  totalScans++;
  const id = crypto.randomBytes(6).toString('hex');
  const entry = { id, url, timestamp: new Date().toISOString(), riskLevel: result.riskLevel, riskScore: result.riskScore };
  scanHistory.unshift(entry);
  if (scanHistory.length > MAX_HISTORY) scanHistory.pop();
  sharedScans.set(id, { ...result, id, url });
  if (sharedScans.size > 500) {
    const oldest = sharedScans.keys().next().value;
    sharedScans.delete(oldest);
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
    client.get(url, { headers: { 'User-Agent': 'SkillAudit/0.4' }, timeout: 15000 }, (res) => {
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
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), 'User-Agent': 'SkillAudit/0.4-webhook' },
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

// --- Landing page ---
app.get('/', (req, res) => {
  if (req.headers.accept && req.headers.accept.includes('application/json') && !req.headers.accept.includes('text/html')) {
    return res.json({
      name: 'SkillAudit', version: '0.4.0',
      description: 'Security scanner for AI agent skills — structural analysis, URL reputation, intent detection',
      docs: '/openapi.json',
      endpoints: {
        'POST /scan/url': 'Scan a skill by URL (supports callback)',
        'POST /scan/content': 'Scan raw skill content',
        'POST /scan/batch': 'Batch scan multiple URLs',
        'POST /scan/compare': 'Compare two skill versions',
        'GET /scan/:id': 'Get shared scan result (JSON)',
        'GET /report/:id': 'View scan report (HTML)',
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
  res.json({ status: 'ok', version: '0.4.0', uptime: process.uptime() });
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
app.get('/stats', (req, res) => {
  const riskDist = { clean: 0, low: 0, moderate: 0, high: 0, critical: 0 };
  const domains = {};
  for (const s of scanHistory) {
    riskDist[s.riskLevel] = (riskDist[s.riskLevel] || 0) + 1;
    const d = getDomain(s.url);
    if (d) domains[d] = true;
  }
  res.json({
    totalScans,
    recentScans: scanHistory.length,
    badgedDomains: Object.keys(domains).length + badges.size,
    riskDistribution: riskDist,
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
      title: 'SkillAudit API', version: '0.4.0',
      description: 'Security scanner for AI agent skills. Detects credential theft, data exfiltration, prompt injection, and more.',
      contact: { name: 'Megamind_0x', url: 'https://moltbook.com/u/Megamind_0x' },
    },
    servers: [{ url: 'https://skillaudit.vercel.app', description: 'Production' }],
    paths: {
      '/scan/url': { post: { summary: 'Scan a skill by URL', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['url'], properties: { url: { type: 'string' }, callback: { type: 'string' } } } } } }, responses: { '200': { description: 'Scan result' } } } },
      '/scan/content': { post: { summary: 'Scan raw skill content', requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['content'], properties: { content: { type: 'string' }, source: { type: 'string' } } } } } }, responses: { '200': { description: 'Scan result' } } } },
      '/scan/batch': { post: { summary: 'Batch scan up to 20 URLs', responses: { '200': { description: 'Batch results' } } } },
      '/scan/compare': { post: { summary: 'Compare two skill versions', responses: { '200': { description: 'Comparison result' } } } },
      '/scan/{id}': { get: { summary: 'Get scan result (JSON)', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { '200': { description: 'Scan result' } } } },
      '/report/{id}': { get: { summary: 'View scan report (HTML)', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { '200': { description: 'HTML report' } } } },
      '/rules': { get: { summary: 'List detection rules', responses: { '200': { description: 'Rule list' } } } },
      '/history': { get: { summary: 'Recent scan history', responses: { '200': { description: 'History' } } } },
      '/stats': { get: { summary: 'Scan statistics', responses: { '200': { description: 'Stats' } } } },
      '/badge/request': { post: { summary: 'Request trust badge', responses: { '200': { description: 'Badge result' } } } },
      '/badge/{domain}': { get: { summary: 'Check domain badge', responses: { '200': { description: 'Badge info' } } } },
      '/health': { get: { summary: 'Health check', responses: { '200': { description: 'OK' } } } },
    }
  });
});

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
<div class="footer">
  <a href="/">← Back to SkillAudit</a> · <a href="/scan/${esc(result.id)}">JSON API</a><br>
  Built by <a href="https://moltbook.com/u/Megamind_0x">Megamind_0x</a> 🧠
</div>
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
  console.log(`🛡️  SkillAudit v0.4.0 running on port ${PORT}`);
});
