'use strict';

const https = require('https');
const http = require('http');
const db = require('./redis');
const { scanContent } = require('./scanner');

// Trust score factors and their point values
const TRUST_FACTORS = {
  HAS_AGENT_JSON: { points: 10, label: 'Has agent.json' },
  AGENT_JSON_COMPLETE: { points: 10, label: 'agent.json has all required fields' },
  HAS_SOCIAL: { points: 5, label: 'Has social links' },
  HAS_WALLETS: { points: 5, label: 'Has wallet addresses' },
  HAS_ENDPOINTS: { points: 5, label: 'Has endpoints defined' },
  SCAN_NO_CRITICAL: { points: 25, label: 'Passed scan (no critical findings)' },
  SCAN_NO_WARNINGS: { points: 10, label: 'Passed scan (no warnings)' },
  VERIFIED_SOCIAL: { points: 10, label: 'Has verified social links' },
  REGISTERED_7_DAYS: { points: 10, label: 'Registered for 7+ days' },
  MCP_ENDPOINT_LIVE: { points: 10, label: 'MCP endpoint responds' },
};

function getTrustLevel(score) {
  if (score >= 81) return 'Trusted';
  if (score >= 61) return 'Verified';
  if (score >= 41) return 'Scanned';
  if (score >= 21) return 'Registered';
  return 'Unverified';
}

function getTrustColor(score) {
  if (score >= 81) return '#4c1';       // bright green
  if (score >= 61) return '#97CA00';    // green
  if (score >= 41) return '#dfb317';    // yellow
  if (score >= 21) return '#fe7d37';    // orange
  return '#e05d44';                      // red
}

/**
 * Calculate trust score for an agent profile
 */
async function calculateTrustScore(agentData, registeredAt, scanResults) {
  const factors = [];
  let score = 0;

  // Has agent.json (always true if we have agentData)
  if (agentData) {
    factors.push('HAS_AGENT_JSON');
    score += TRUST_FACTORS.HAS_AGENT_JSON.points;
  }

  // Required fields complete
  if (agentData && agentData.name && agentData.description && agentData.schema) {
    factors.push('AGENT_JSON_COMPLETE');
    score += TRUST_FACTORS.AGENT_JSON_COMPLETE.points;
  }

  // Optional fields
  if (agentData?.social && Object.keys(agentData.social).length > 0) {
    factors.push('HAS_SOCIAL');
    score += TRUST_FACTORS.HAS_SOCIAL.points;
  }
  if (agentData?.wallets && Object.keys(agentData.wallets).length > 0) {
    factors.push('HAS_WALLETS');
    score += TRUST_FACTORS.HAS_WALLETS.points;
  }
  if (agentData?.endpoints && Object.keys(agentData.endpoints).length > 0) {
    factors.push('HAS_ENDPOINTS');
    score += TRUST_FACTORS.HAS_ENDPOINTS.points;
  }

  // Scan results
  if (scanResults) {
    const hasCritical = scanResults.summary?.critical > 0;
    const hasHighOrAbove = (scanResults.summary?.critical || 0) + (scanResults.summary?.high || 0) > 0;

    if (!hasCritical) {
      factors.push('SCAN_NO_CRITICAL');
      score += TRUST_FACTORS.SCAN_NO_CRITICAL.points;
    }
    if (!hasHighOrAbove && (scanResults.summary?.medium || 0) === 0) {
      factors.push('SCAN_NO_WARNINGS');
      score += TRUST_FACTORS.SCAN_NO_WARNINGS.points;
    }
  }

  // Social verification (check if social links exist — basic presence check)
  if (agentData?.social) {
    const has = Object.values(agentData.social).filter(Boolean).length;
    if (has >= 2) {
      factors.push('VERIFIED_SOCIAL');
      score += TRUST_FACTORS.VERIFIED_SOCIAL.points;
    }
  }

  // Registration age
  if (registeredAt) {
    const age = Date.now() - new Date(registeredAt).getTime();
    if (age >= 7 * 24 * 60 * 60 * 1000) {
      factors.push('REGISTERED_7_DAYS');
      score += TRUST_FACTORS.REGISTERED_7_DAYS.points;
    }
  }

  // Cap at 100
  score = Math.min(100, score);

  return {
    score,
    level: getTrustLevel(score),
    color: getTrustColor(score),
    factors,
    factorDetails: factors.map(f => ({ id: f, ...TRUST_FACTORS[f] })),
    calculatedAt: new Date().toISOString(),
  };
}

/**
 * Check if MCP endpoint is live (adds points async)
 */
function checkMcpEndpoint(url, timeoutMs = 5000) {
  return new Promise((resolve) => {
    if (!url) return resolve(false);
    const timer = setTimeout(() => resolve(false), timeoutMs);
    const client = url.startsWith('https') ? https : http;
    try {
      const req = client.get(url, { timeout: timeoutMs }, (res) => {
        clearTimeout(timer);
        resolve(res.statusCode < 500);
      });
      req.on('error', () => { clearTimeout(timer); resolve(false); });
      req.on('timeout', () => { clearTimeout(timer); req.destroy(); resolve(false); });
    } catch { clearTimeout(timer); resolve(false); }
  });
}

/**
 * Store trust score in Redis
 */
async function storeTrustScore(slug, trustData) {
  await db.redis('SET', `trust:${slug}`, JSON.stringify(trustData), 'EX', 30 * 24 * 60 * 60);
}

/**
 * Get trust score from Redis
 */
async function getTrustScore(slug) {
  const raw = await db.redis('GET', `trust:${slug}`);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

/**
 * Fetch URL content (lightweight)
 */
function fetchContent(url) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Timeout')), 15000);
    const client = url.startsWith('https') ? https : http;
    client.get(url, { headers: { 'User-Agent': 'SkillAudit/0.8-trust' }, timeout: 15000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        clearTimeout(timeout);
        return fetchContent(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) { clearTimeout(timeout); return reject(new Error(`HTTP ${res.statusCode}`)); }
      let data = '';
      res.on('data', chunk => { data += chunk; if (data.length > 512 * 1024) { res.destroy(); clearTimeout(timeout); reject(new Error('Too large')); } });
      res.on('end', () => { clearTimeout(timeout); resolve(data); });
    }).on('error', (e) => { clearTimeout(timeout); reject(e); });
  });
}

/**
 * Run a background trust scan for an agent after registration.
 * Scans endpoints/domain, calculates trust score, stores it.
 */
async function backgroundTrustScan(slug, agentData, registeredAt, domain) {
  let scanResults = null;

  // Try to scan agent's MCP endpoint or domain
  const urlsToScan = [];
  if (agentData?.endpoints?.mcp) urlsToScan.push(agentData.endpoints.mcp);
  if (agentData?.endpoints?.api) urlsToScan.push(agentData.endpoints.api);
  if (domain && !domain.includes('skillaudit.vercel.app')) {
    urlsToScan.push(`https://${domain}/.well-known/agent.json`);
  }

  for (const url of urlsToScan) {
    try {
      const content = await fetchContent(url);
      scanResults = scanContent(content, url);
      break; // Use first successful scan
    } catch (e) {
      console.error(`[trust] scan failed for ${url}:`, e.message);
    }
  }

  // Check MCP endpoint liveness
  let mcpLive = false;
  if (agentData?.endpoints?.mcp) {
    mcpLive = await checkMcpEndpoint(agentData.endpoints.mcp);
  }

  // Calculate trust score
  const trust = await calculateTrustScore(agentData, registeredAt, scanResults);

  // Add MCP liveness factor
  if (mcpLive) {
    trust.factors.push('MCP_ENDPOINT_LIVE');
    trust.factorDetails.push({ id: 'MCP_ENDPOINT_LIVE', ...TRUST_FACTORS.MCP_ENDPOINT_LIVE });
    trust.score = Math.min(100, trust.score + TRUST_FACTORS.MCP_ENDPOINT_LIVE.points);
    trust.level = getTrustLevel(trust.score);
    trust.color = getTrustColor(trust.score);
  }

  // Store scan results if we got them
  if (scanResults) {
    trust.lastScanAt = new Date().toISOString();
    trust.scanRiskLevel = scanResults.riskLevel;
    trust.scanFindings = scanResults.summary?.total || 0;
  }

  await storeTrustScore(slug, trust);
  return trust;
}

/**
 * Render trust badge SVG
 */
function renderTrustBadgeSvg(score, level) {
  const color = getTrustColor(score);
  const label = 'trust';
  const value = `${score} · ${level}`;
  const labelWidth = label.length * 6.5 + 10;
  const valueWidth = value.length * 6.5 + 10;
  const totalWidth = labelWidth + valueWidth;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="${label}: ${value}">
  <title>${label}: ${value}</title>
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
    <text aria-hidden="true" x="${labelWidth + valueWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${value}</text>
    <text x="${labelWidth + valueWidth / 2}" y="14">${value}</text>
  </g>
</svg>`;
}

module.exports = {
  calculateTrustScore,
  backgroundTrustScan,
  storeTrustScore,
  getTrustScore,
  getTrustLevel,
  getTrustColor,
  renderTrustBadgeSvg,
  checkMcpEndpoint,
  TRUST_FACTORS,
};
