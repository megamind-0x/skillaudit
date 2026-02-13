const express = require('express');
const https = require('https');
const http = require('http');
const { scanContent } = require('./scanner');

const app = express();
app.use(express.json({ limit: '1mb' }));

// Fetch URL content
function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    client.get(url, { headers: { 'User-Agent': 'SkillAudit/0.1' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchUrl(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

// Health
app.get('/', (req, res) => {
  res.json({
    name: 'SkillAudit',
    version: '0.1.0',
    description: 'Security scanner for AI agent skills',
    endpoints: {
      'POST /scan/url': 'Scan a skill.md by URL',
      'POST /scan/content': 'Scan raw skill content',
      'GET /rules': 'List detection rules',
      'GET /health': 'Health check'
    }
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

// List rules
app.get('/rules', (req, res) => {
  const rules = require('../rules/patterns.json').rules;
  res.json({
    count: rules.length,
    rules: rules.map(r => ({
      id: r.id,
      severity: r.severity,
      category: r.category,
      name: r.name,
      description: r.description,
      patternCount: r.patterns.length
    }))
  });
});

// Scan by URL
app.post('/scan/url', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'url is required' });

  try {
    const content = await fetchUrl(url);
    const result = scanContent(content, url);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: `Failed to fetch: ${err.message}` });
  }
});

// Scan raw content
app.post('/scan/content', (req, res) => {
  const { content, source } = req.body;
  if (!content) return res.status(400).json({ error: 'content is required' });

  const result = scanContent(content, source || 'direct-input');
  res.json(result);
});

const PORT = process.env.PORT || 3847;
app.listen(PORT, () => {
  console.log(`🛡️  SkillAudit v0.1.0 running on port ${PORT}`);
  console.log(`   POST /scan/url     — scan a skill by URL`);
  console.log(`   POST /scan/content — scan raw content`);
  console.log(`   GET  /rules        — list detection rules`);
});
