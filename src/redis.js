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

// Store scan result (keep last 100)
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

async function getRecentScans(count = 10) {
  const val = await redis('LRANGE', 'scans:recent', 0, count - 1);
  if (!val) return [];
  return val.map(v => { try { return JSON.parse(v); } catch { return null; } }).filter(Boolean);
}

module.exports = {
  redis, incrScanCount, getScanCount,
  incrRisk, getRiskDistribution,
  incrThreatType, getThreatTypes,
  storeScanResult, getRecentScans,
};
