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

// --- Threat Intelligence Feed ---

// Store a threat event when a scan finds actionable findings
async function storeThreatEvent(event) {
  const payload = JSON.stringify(event);
  await redis('LPUSH', 'feed:threats', payload);
  await redis('LTRIM', 'feed:threats', 0, 499); // Keep last 500
  // Track in sorted set by timestamp for range queries
  await redis('ZADD', 'feed:threats:ts', Date.now(), payload);
  // Trim sorted set to last 500
  const count = await redis('ZCARD', 'feed:threats:ts');
  if (count && count > 500) {
    await redis('ZREMRANGEBYRANK', 'feed:threats:ts', 0, count - 501);
  }
}

async function getRecentThreats(count = 50, minSeverity = null) {
  const val = await redis('LRANGE', 'feed:threats', 0, count - 1);
  if (!val) return [];
  let events = val.map(v => { try { return JSON.parse(v); } catch { return null; } }).filter(Boolean);
  if (minSeverity) {
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const minLevel = severityOrder[minSeverity] || 0;
    events = events.filter(e => (severityOrder[e.severity] || 0) >= minLevel);
  }
  return events;
}

async function getThreatsAfter(timestampMs) {
  const val = await redis('ZRANGEBYSCORE', 'feed:threats:ts', timestampMs, '+inf');
  if (!val) return [];
  return val.map(v => { try { return JSON.parse(v); } catch { return null; } }).filter(Boolean);
}

// Track flagged domains in a sorted set (score = timestamp)
async function trackFlaggedDomain(domain, riskLevel, riskScore, url) {
  const payload = JSON.stringify({ domain, riskLevel, riskScore, url, flaggedAt: new Date().toISOString() });
  await redis('ZADD', 'feed:flagged_domains', Date.now(), payload);
  const count = await redis('ZCARD', 'feed:flagged_domains');
  if (count && count > 200) {
    await redis('ZREMRANGEBYRANK', 'feed:flagged_domains', 0, count - 201);
  }
}

async function getRecentFlaggedDomains(count = 30) {
  const val = await redis('ZREVRANGE', 'feed:flagged_domains', 0, count - 1);
  if (!val) return [];
  return val.map(v => { try { return JSON.parse(v); } catch { return null; } }).filter(Boolean);
}

// Track rule hit counts (for trending rules)
async function incrRuleHit(ruleId, severity) {
  await redis('HINCRBY', 'feed:rule_hits', ruleId, 1);
  // Also track in daily bucket for trend detection
  const day = new Date().toISOString().slice(0, 10);
  await redis('HINCRBY', `feed:rule_hits:${day}`, ruleId, 1);
  await redis('EXPIRE', `feed:rule_hits:${day}`, 604800); // 7-day TTL
}

async function getRuleHits() {
  const val = await redis('HGETALL', 'feed:rule_hits');
  if (!val || !Array.isArray(val)) return {};
  const obj = {};
  for (let i = 0; i < val.length; i += 2) obj[val[i]] = parseInt(val[i + 1]) || 0;
  return obj;
}

async function getDailyRuleHits(date) {
  const val = await redis('HGETALL', `feed:rule_hits:${date}`);
  if (!val || !Array.isArray(val)) return {};
  const obj = {};
  for (let i = 0; i < val.length; i += 2) obj[val[i]] = parseInt(val[i + 1]) || 0;
  return obj;
}

// --- Watchlist ---

async function addWatchlistItem(apiKey, item) {
  // item: { id, url, addedAt, lastRisk, lastScore, lastScanAt, scanCount, alerts }
  const key = `watchlist:${apiKey}`;
  await redis('HSET', key, item.id, JSON.stringify(item));
  // Also track in global index for stats
  await redis('SADD', 'watchlist:ids', `${apiKey}:${item.id}`);
}

async function getWatchlist(apiKey) {
  const key = `watchlist:${apiKey}`;
  const val = await redis('HGETALL', key);
  if (!val || !Array.isArray(val) || val.length === 0) return [];
  const items = [];
  for (let i = 0; i < val.length; i += 2) {
    try { items.push(JSON.parse(val[i + 1])); } catch {}
  }
  return items;
}

async function getWatchlistItem(apiKey, itemId) {
  const key = `watchlist:${apiKey}`;
  const val = await redis('HGET', key, itemId);
  if (!val) return null;
  try { return JSON.parse(val); } catch { return null; }
}

async function updateWatchlistItem(apiKey, item) {
  const key = `watchlist:${apiKey}`;
  return redis('HSET', key, item.id, JSON.stringify(item));
}

async function removeWatchlistItem(apiKey, itemId) {
  const key = `watchlist:${apiKey}`;
  await redis('HDEL', key, itemId);
  await redis('SREM', 'watchlist:ids', `${apiKey}:${itemId}`);
}

async function getWatchlistCount() {
  const val = await redis('SCARD', 'watchlist:ids');
  return parseInt(val) || 0;
}

// --- URL Scan History (drift detection) ---
// Tracks scan history per URL for trend analysis and drift detection

async function trackUrlScan(url, scanId, riskLevel, riskScore, findingsCount, criticalCount) {
  if (!url) return;
  const key = `url-history:${Buffer.from(url).toString('base64url').slice(0, 128)}`;
  const entry = JSON.stringify({
    scanId,
    riskLevel,
    riskScore,
    findings: findingsCount,
    critical: criticalCount,
    scannedAt: new Date().toISOString(),
  });
  // Store in sorted set by timestamp (score = Date.now())
  await redis('ZADD', key, Date.now(), entry);
  // Keep last 50 scans per URL
  const count = await redis('ZCARD', key);
  if (count && count > 50) {
    await redis('ZREMRANGEBYRANK', key, 0, count - 51);
  }
  // 90-day TTL on the whole key
  await redis('EXPIRE', key, 7776000);
}

async function getUrlHistory(url, limit = 20) {
  if (!url) return [];
  const key = `url-history:${Buffer.from(url).toString('base64url').slice(0, 128)}`;
  const val = await redis('ZREVRANGE', key, 0, limit - 1);
  if (!val) return [];
  return val.map(v => { try { return JSON.parse(v); } catch { return null; } }).filter(Boolean);
}

async function getLastUrlScan(url) {
  const history = await getUrlHistory(url, 1);
  return history.length > 0 ? history[0] : null;
}

// --- Content Hash Index ---
// Maps SHA-256 content hashes to scan IDs for instant lookup (VirusTotal model)

async function storeContentHash(contentHash, scanId, riskLevel, riskScore) {
  if (!contentHash) return;
  const payload = JSON.stringify({
    scanId,
    riskLevel,
    riskScore,
    scannedAt: new Date().toISOString(),
  });
  // Store with 30-day TTL (matches scan result TTL)
  await redis('SET', `hash:${contentHash}`, payload, 'EX', 2592000);
  // Track total unique hashes scanned
  await redis('PFADD', 'stats:uniqueHashes', contentHash);
}

async function getByContentHash(contentHash) {
  if (!contentHash) return null;
  const val = await redis('GET', `hash:${contentHash}`);
  if (!val) return null;
  try { return JSON.parse(val); } catch { return null; }
}

async function getUniqueHashCount() {
  const val = await redis('PFCOUNT', 'stats:uniqueHashes');
  return parseInt(val) || 0;
}

// --- Allowlist / Denylist ---

async function addListItem(apiKey, listType, item) {
  // listType: 'allow' or 'deny'
  const key = `${listType}list:${apiKey}`;
  await redis('HSET', key, item.id, JSON.stringify(item));
}

async function getList(apiKey, listType) {
  const key = `${listType}list:${apiKey}`;
  const val = await redis('HGETALL', key);
  if (!val || !Array.isArray(val) || val.length === 0) return [];
  const items = [];
  for (let i = 0; i < val.length; i += 2) {
    try { items.push(JSON.parse(val[i + 1])); } catch {}
  }
  return items;
}

async function getListItem(apiKey, listType, itemId) {
  const key = `${listType}list:${apiKey}`;
  const val = await redis('HGET', key, itemId);
  if (!val) return null;
  try { return JSON.parse(val); } catch { return null; }
}

async function removeListItem(apiKey, listType, itemId) {
  const key = `${listType}list:${apiKey}`;
  return redis('HDEL', key, itemId);
}

// --- Security Policies ---

async function storePolicy(apiKey, policy) {
  const key = `policies:${apiKey}`;
  await redis('HSET', key, policy.id, JSON.stringify(policy));
}

async function getPolicy(apiKey, policyId) {
  const key = `policies:${apiKey}`;
  const val = await redis('HGET', key, policyId);
  if (!val) return null;
  try { return JSON.parse(val); } catch { return null; }
}

async function listPolicies(apiKey) {
  const key = `policies:${apiKey}`;
  const val = await redis('HGETALL', key);
  if (!val || !Array.isArray(val) || val.length === 0) return [];
  const items = [];
  for (let i = 0; i < val.length; i += 2) {
    try { items.push(JSON.parse(val[i + 1])); } catch {}
  }
  return items;
}

async function removePolicy(apiKey, policyId) {
  const key = `policies:${apiKey}`;
  return redis('HDEL', key, policyId);
}

// --- API Keys (self-service) ---

async function storeApiKey(keyId, keyData) {
  // keyData: { key, label, createdAt, lastUsedAt, usageCount }
  // Store with no TTL — keys persist until revoked
  await redis('SET', `apikey:${keyId}`, JSON.stringify(keyData));
  // Index: key value → keyId (for lookups by the actual key string)
  await redis('SET', `apikey-lookup:${keyData.key}`, keyId);
  // Track all keys in a set
  await redis('SADD', 'apikeys:all', keyId);
}

async function getApiKeyById(keyId) {
  const val = await redis('GET', `apikey:${keyId}`);
  if (!val) return null;
  try { return JSON.parse(val); } catch { return null; }
}

async function getApiKeyByValue(keyValue) {
  const keyId = await redis('GET', `apikey-lookup:${keyValue}`);
  if (!keyId) return null;
  return getApiKeyById(keyId);
}

async function isValidApiKey(keyValue) {
  const exists = await redis('EXISTS', `apikey-lookup:${keyValue}`);
  return exists === 1;
}

async function trackApiKeyUsage(keyValue) {
  const keyId = await redis('GET', `apikey-lookup:${keyValue}`);
  if (!keyId) return;
  const raw = await redis('GET', `apikey:${keyId}`);
  if (!raw) return;
  try {
    const data = JSON.parse(raw);
    data.usageCount = (data.usageCount || 0) + 1;
    data.lastUsedAt = new Date().toISOString();
    await redis('SET', `apikey:${keyId}`, JSON.stringify(data));
  } catch {}
}

async function revokeApiKey(keyValue) {
  const keyId = await redis('GET', `apikey-lookup:${keyValue}`);
  if (!keyId) return false;
  await redis('DEL', `apikey:${keyId}`);
  await redis('DEL', `apikey-lookup:${keyValue}`);
  await redis('SREM', 'apikeys:all', keyId);
  return true;
}

async function getApiKeyCount() {
  const val = await redis('SCARD', 'apikeys:all');
  return parseInt(val) || 0;
}

module.exports = {
  redis, incrScanCount, getScanCount,
  incrRisk, getRiskDistribution,
  incrThreatType, getThreatTypes,
  storeScanResult, storeScanById, getScanById, getRecentScans,
  trackDomainScan, getDomainReputation,
  storeThreatEvent, getRecentThreats, getThreatsAfter,
  trackFlaggedDomain, getRecentFlaggedDomains,
  incrRuleHit, getRuleHits, getDailyRuleHits,
  addWatchlistItem, getWatchlist, getWatchlistItem, updateWatchlistItem, removeWatchlistItem, getWatchlistCount,
  trackUrlScan, getUrlHistory, getLastUrlScan,
  storeContentHash, getByContentHash, getUniqueHashCount,
  addWebhook, getWebhooks, getWebhook, removeWebhook, getAllWebhookKeys,
  addListItem, getList, getListItem, removeListItem,
  storePolicy, getPolicy, listPolicies, removePolicy,
  storeApiKey, getApiKeyById, getApiKeyByValue, isValidApiKey, trackApiKeyUsage, revokeApiKey, getApiKeyCount,
};

// --- Webhook Subscriptions ---

async function addWebhook(apiKey, webhook) {
  const key = `webhooks:${apiKey}`;
  await redis('HSET', key, webhook.id, JSON.stringify(webhook));
}

async function getWebhooks(apiKey) {
  const key = `webhooks:${apiKey}`;
  const val = await redis('HGETALL', key);
  if (!val || !Array.isArray(val) || val.length === 0) return [];
  const items = [];
  for (let i = 0; i < val.length; i += 2) {
    try { items.push(JSON.parse(val[i + 1])); } catch {}
  }
  return items;
}

async function getWebhook(apiKey, id) {
  const key = `webhooks:${apiKey}`;
  const val = await redis('HGET', key, id);
  if (!val) return null;
  try { return JSON.parse(val); } catch { return null; }
}

async function removeWebhook(apiKey, id) {
  const key = `webhooks:${apiKey}`;
  return redis('HDEL', key, id);
}

async function getAllWebhookKeys() {
  // Get all API keys that have webhooks registered
  const keys = await redis('KEYS', 'webhooks:*');
  return keys || [];
}
