'use strict';

const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

async function redis(command, ...args) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) return null;
  try {
    const res = await fetch(`${UPSTASH_URL}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${UPSTASH_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify([command, ...args]),
    });
    const data = await res.json();
    if (data.error) { console.error('Redis error:', data.error); return null; }
    return data.result;
  } catch (e) {
    console.error('Redis fetch error:', e.message);
    return null;
  }
}

// Scan counter
async function incrScanCount() {
  const val = await redis('INCR', 'stats:totalScans');
  return val;
}

async function getScanCount() {
  const val = await redis('GET', 'stats:totalScans');
  return parseInt(val) || 0;
}

// Risk distribution
async function incrRisk(level) {
  return redis('HINCRBY', 'stats:riskDistribution', level, 1);
}

async function getRiskDistribution() {
  const val = await redis('HGETALL', 'stats:riskDistribution');
  if (!val || !Array.isArray(val)) return {};
  const obj = {};
  for (let i = 0; i < val.length; i += 2) obj[val[i]] = parseInt(val[i + 1]) || 0;
  return obj;
}

// Threat types
async function incrThreatType(type) {
  return redis('HINCRBY', 'stats:threatTypes', type, 1);
}

async function getThreatTypes() {
  const val = await redis('HGETALL', 'stats:threatTypes');
  if (!val || !Array.isArray(val)) return {};
  const obj = {};
  for (let i = 0; i < val.length; i += 2) obj[val[i]] = parseInt(val[i + 1]) || 0;
  return obj;
}

// Store scan result (keep last 100 in list + persist full result by ID)
async function storeScanResult(result) {
  const entry = JSON.stringify({
    url: result.url || 'unknown',
    risk_level: result.risk_level,
    risk_score: result.risk_score,
    findings_count: (result.findings || []).length,
    scanned_at: new Date().toISOString(),
  });
  await redis('LPUSH', 'scans:recent', entry);
  await redis('LTRIM', 'scans:recent', 0, 99);
}

// Persist full scan result by ID (TTL: 30 days)
async function storeScanById(id, result) {
  const payload = JSON.stringify(result);
  // SET with EX 2592000 = 30 days
  return redis('SET', `scan:${id}`, payload, 'EX', 2592000);
}

async function getScanById(id) {
  const val = await redis('GET', `scan:${id}`);
  if (!val) return null;
  try { return JSON.parse(val); } catch { return null; }
}

async function getRecentScans(count = 10) {
  const val = await redis('LRANGE', 'scans:recent', 0, count - 1);
  if (!val) return [];
  return val.map(v => { try { return JSON.parse(v); } catch { return null; } }).filter(Boolean);
}

// Domain reputation tracking
async function trackDomainScan(domain, riskLevel, riskScore, findingsCount, url) {
  if (!domain) return;
  const key = `domain:${domain}`;
  const ts = new Date().toISOString();
  // Increment scan count and risk level
  await redis('HINCRBY', key, 'scanCount', 1);
  await redis('HINCRBY', key, `risk:${riskLevel}`, 1);
  // Accumulate total score for averaging
  await redis('HINCRBY', key, 'totalRiskScore', riskScore);
  // Update last scan info (all fields in one HSET call)
  await redis('HSET', key, 'lastScanAt', ts, 'lastRiskLevel', riskLevel, 'lastRiskScore', String(riskScore), 'lastUrl', url || '');
  // Track first seen (only if not set)
  const firstSeen = await redis('HGET', key, 'firstSeenAt');
  if (!firstSeen) await redis('HSET', key, 'firstSeenAt', ts);
}

async function getDomainReputation(domain) {
  if (!domain) return null;
  const key = `domain:${domain}`;
  const val = await redis('HGETALL', key);
  if (!val || !Array.isArray(val) || val.length === 0) return null;
  const obj = {};
  for (let i = 0; i < val.length; i += 2) obj[val[i]] = val[i + 1];
  
  const scanCount = parseInt(obj.scanCount) || 0;
  const totalRiskScore = parseInt(obj.totalRiskScore) || 0;
  const avgRiskScore = scanCount > 0 ? Math.round((totalRiskScore / scanCount) * 100) / 100 : 0;
  
  // Build risk distribution
  const riskDist = {};
  for (const k of Object.keys(obj)) {
    if (k.startsWith('risk:')) riskDist[k.slice(5)] = parseInt(obj[k]) || 0;
  }
  
  // Calculate reputation: 100 = perfect, 0 = terrible
  // Weighted: critical=-20, high=-10, moderate=-5, low=-1, clean=+2
  const weights = { critical: -20, high: -10, moderate: -5, low: -1, clean: 2 };
  let repScore = 100;
  for (const [level, count] of Object.entries(riskDist)) {
    repScore += (weights[level] || 0) * count;
  }
  repScore = Math.max(0, Math.min(100, repScore));
  
  let reputation;
  if (repScore >= 90) reputation = 'trusted';
  else if (repScore >= 70) reputation = 'moderate';
  else if (repScore >= 40) reputation = 'suspicious';
  else reputation = 'dangerous';

  return {
    domain,
    reputation,
    reputationScore: repScore,
    scanCount,
    avgRiskScore,
    riskDistribution: riskDist,
    lastScan: {
      at: obj.lastScanAt || null,
      riskLevel: obj.lastRiskLevel || null,
      riskScore: parseInt(obj.lastRiskScore) || 0,
      url: obj.lastUrl || null,
    },
    firstSeenAt: obj.firstSeenAt || null,
  };
}

module.exports = {
  redis, incrScanCount, getScanCount,
  incrRisk, getRiskDistribution,
  incrThreatType, getThreatTypes,
  storeScanResult, storeScanById, getScanById, getRecentScans,
  trackDomainScan, getDomainReputation,
};
