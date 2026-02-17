#!/usr/bin/env node
/**
 * SkillAudit MCP Server — Model Context Protocol server for AI agent security scanning.
 * 
 * Run: npx skillaudit --mcp
 * Or:  node bin/mcp-server.js
 * 
 * Exposes SkillAudit as native MCP tools that any MCP-compatible agent can use.
 * Protocol: JSON-RPC 2.0 over stdio (MCP standard)
 */

const { scanContent } = require('../src/scanner');
const https = require('https');
const http = require('http');
const readline = require('readline');

const SERVER_INFO = {
  name: 'skillaudit',
  version: '0.8.1',
};

const TOOLS = [
  {
    name: 'skillaudit_gate',
    description: 'Pre-install security gate for AI agent skills. Returns allow/warn/deny decision. Call this BEFORE installing any skill, plugin, or MCP server.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'URL of the skill file to check (SKILL.md, plugin.json, etc.)' },
        threshold: { type: 'string', enum: ['low', 'moderate', 'high', 'critical'], description: 'Risk threshold for deny decision (default: moderate)', default: 'moderate' },
      },
      required: ['url'],
    },
  },
  {
    name: 'skillaudit_scan',
    description: 'Full security scan of a skill file. Returns detailed findings, risk score, capability analysis, and verdict.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'URL of the skill file to scan' },
        content: { type: 'string', description: 'Raw skill content to scan (use instead of url)' },
      },
    },
  },
  {
    name: 'skillaudit_scan_content',
    description: 'Scan raw skill content directly (no URL needed). Useful for scanning local files or generated content.',
    inputSchema: {
      type: 'object',
      properties: {
        content: { type: 'string', description: 'Raw skill/plugin content to scan' },
        source: { type: 'string', description: 'Label for the content source (optional)', default: 'mcp-input' },
      },
      required: ['content'],
    },
  },
  {
    name: 'skillaudit_reputation',
    description: 'Check the reputation of a domain based on historical scan data. Returns trust level and scan history.',
    inputSchema: {
      type: 'object',
      properties: {
        domain: { type: 'string', description: 'Domain to check (e.g., github.com, example.com)' },
      },
      required: ['domain'],
    },
  },
  {
    name: 'skillaudit_batch',
    description: 'Scan multiple skill URLs at once. Returns individual results and overall risk summary.',
    inputSchema: {
      type: 'object',
      properties: {
        urls: { type: 'array', items: { type: 'string' }, description: 'Array of skill URLs to scan (max 10)' },
      },
      required: ['urls'],
    },
  },
];

// --- URL fetching ---
function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Timeout (15s)')), 15000);
    const client = url.startsWith('https') ? https : http;
    client.get(url, { headers: { 'User-Agent': 'SkillAudit-MCP/0.8' }, timeout: 15000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        clearTimeout(timeout);
        return fetchUrl(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) { clearTimeout(timeout); return reject(new Error(`HTTP ${res.statusCode}`)); }
      let data = '';
      res.on('data', chunk => { data += chunk; if (data.length > 512 * 1024) { res.destroy(); clearTimeout(timeout); reject(new Error('Too large')); } });
      res.on('end', () => { clearTimeout(timeout); resolve(data); });
    }).on('error', e => { clearTimeout(timeout); reject(e); });
  });
}

// --- Tool handlers ---
async function handleGate({ url, threshold = 'moderate' }) {
  if (!url) return { error: 'url is required' };
  const content = await fetchUrl(url);
  const result = scanContent(content, url);
  const thresholdOrder = { clean: 0, low: 1, moderate: 2, high: 3, critical: 4 };
  const riskIdx = thresholdOrder[result.riskLevel] ?? 0;
  const thresholdIdx = thresholdOrder[threshold] ?? 2;
  const decision = riskIdx === 0 ? 'allow' : riskIdx < thresholdIdx ? 'warn' : 'deny';
  return {
    allow: decision !== 'deny',
    decision,
    risk: result.riskLevel,
    score: result.riskScore,
    findings: result.summary.total,
    critical: result.summary.critical,
    verdict: result.verdict,
    topFindings: result.findings.slice(0, 5).map(f => ({
      severity: f.severity, name: f.name, rule: f.ruleId, line: f.line,
    })),
  };
}

async function handleScan({ url, content }) {
  if (!url && !content) return { error: 'url or content is required' };
  let textContent, source;
  if (url) {
    textContent = await fetchUrl(url);
    source = url;
  } else {
    textContent = content;
    source = 'mcp-input';
  }
  const result = scanContent(textContent, source);
  return {
    source: result.source,
    riskLevel: result.riskLevel,
    riskScore: result.riskScore,
    summary: result.summary,
    verdict: result.verdict,
    findings: result.findings.slice(0, 20).map(f => ({
      severity: f.severity, name: f.name, rule: f.ruleId,
      description: f.description, line: f.line, match: f.match,
    })),
    capabilities: result.capabilityStats,
    threatChains: (result.threatChains || []).map(c => ({
      name: c.name, severity: c.severity, description: c.description,
    })),
  };
}

async function handleScanContent({ content, source = 'mcp-input' }) {
  if (!content) return { error: 'content is required' };
  const result = scanContent(content, source);
  return {
    source: result.source,
    riskLevel: result.riskLevel,
    riskScore: result.riskScore,
    summary: result.summary,
    verdict: result.verdict,
    findings: result.findings.slice(0, 20).map(f => ({
      severity: f.severity, name: f.name, rule: f.ruleId,
      description: f.description, line: f.line,
    })),
    capabilities: result.capabilityStats,
  };
}

async function handleReputation({ domain }) {
  if (!domain) return { error: 'domain is required' };
  // Use the API endpoint for reputation (requires the server to be running)
  // For standalone MCP, return basic info
  try {
    const res = await fetchUrl(`https://skillaudit.vercel.app/reputation/${encodeURIComponent(domain)}`);
    return JSON.parse(res);
  } catch {
    return { domain, reputation: 'unknown', message: 'Could not fetch reputation data. The SkillAudit API may be unavailable.' };
  }
}

async function handleBatch({ urls }) {
  if (!urls || !Array.isArray(urls) || urls.length === 0) return { error: 'urls array is required' };
  if (urls.length > 10) return { error: 'Maximum 10 URLs per batch in MCP mode' };
  
  const results = await Promise.all(urls.map(async (url) => {
    try {
      const content = await fetchUrl(url);
      const result = scanContent(content, url);
      return {
        url, status: 'success', riskLevel: result.riskLevel, riskScore: result.riskScore,
        findings: result.summary.total, critical: result.summary.critical, verdict: result.verdict,
      };
    } catch (err) {
      return { url, status: 'error', error: err.message };
    }
  }));

  const successful = results.filter(r => r.status === 'success');
  const riskBreakdown = { clean: 0, low: 0, moderate: 0, high: 0, critical: 0 };
  successful.forEach(r => { riskBreakdown[r.riskLevel] = (riskBreakdown[r.riskLevel] || 0) + 1; });

  return { total: urls.length, successful: successful.length, riskBreakdown, results };
}

const TOOL_HANDLERS = {
  skillaudit_gate: handleGate,
  skillaudit_scan: handleScan,
  skillaudit_scan_content: handleScanContent,
  skillaudit_reputation: handleReputation,
  skillaudit_batch: handleBatch,
};

// --- MCP JSON-RPC server over stdio ---
function sendResponse(response) {
  const msg = JSON.stringify(response);
  process.stdout.write(`Content-Length: ${Buffer.byteLength(msg)}\r\n\r\n${msg}`);
}

function sendNotification(method, params = {}) {
  const msg = JSON.stringify({ jsonrpc: '2.0', method, params });
  process.stdout.write(`Content-Length: ${Buffer.byteLength(msg)}\r\n\r\n${msg}`);
}

async function handleMessage(message) {
  const { id, method, params } = message;

  switch (method) {
    case 'initialize':
      return sendResponse({
        jsonrpc: '2.0', id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: SERVER_INFO,
        },
      });

    case 'notifications/initialized':
      // Client acknowledged init — no response needed
      return;

    case 'tools/list':
      return sendResponse({
        jsonrpc: '2.0', id,
        result: { tools: TOOLS },
      });

    case 'tools/call': {
      const toolName = params?.name;
      const handler = TOOL_HANDLERS[toolName];
      if (!handler) {
        return sendResponse({
          jsonrpc: '2.0', id,
          error: { code: -32601, message: `Unknown tool: ${toolName}` },
        });
      }
      try {
        const result = await handler(params.arguments || {});
        return sendResponse({
          jsonrpc: '2.0', id,
          result: {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
          },
        });
      } catch (err) {
        return sendResponse({
          jsonrpc: '2.0', id,
          result: {
            content: [{ type: 'text', text: JSON.stringify({ error: err.message }) }],
            isError: true,
          },
        });
      }
    }

    case 'ping':
      return sendResponse({ jsonrpc: '2.0', id, result: {} });

    default:
      if (id) {
        return sendResponse({
          jsonrpc: '2.0', id,
          error: { code: -32601, message: `Method not found: ${method}` },
        });
      }
  }
}

// --- Message parsing (Content-Length framing) ---
function startServer() {
  let buffer = '';

  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    buffer += chunk;

    while (true) {
      const headerEnd = buffer.indexOf('\r\n\r\n');
      if (headerEnd === -1) break;

      const header = buffer.slice(0, headerEnd);
      const match = header.match(/Content-Length:\s*(\d+)/i);
      if (!match) {
        // Try parsing as raw JSON (some clients skip Content-Length)
        try {
          const lines = buffer.split('\n').filter(l => l.trim());
          for (const line of lines) {
            const msg = JSON.parse(line.trim());
            handleMessage(msg);
          }
          buffer = '';
        } catch {
          buffer = buffer.slice(headerEnd + 4);
        }
        continue;
      }

      const contentLength = parseInt(match[1], 10);
      const bodyStart = headerEnd + 4;
      if (buffer.length < bodyStart + contentLength) break;

      const body = buffer.slice(bodyStart, bodyStart + contentLength);
      buffer = buffer.slice(bodyStart + contentLength);

      try {
        const message = JSON.parse(body);
        handleMessage(message);
      } catch (err) {
        process.stderr.write(`Parse error: ${err.message}\n`);
      }
    }
  });

  process.stdin.on('end', () => process.exit(0));
  process.stderr.write('SkillAudit MCP server started\n');
}

// Run if called directly or with --mcp flag
if (require.main === module || process.argv.includes('--mcp')) {
  startServer();
}

module.exports = { startServer, TOOLS };
