#!/usr/bin/env node

/**
 * SkillAudit MCP Server
 * 
 * Model Context Protocol server that exposes SkillAudit scanning tools.
 * Communicates via JSON-RPC over stdin/stdout (newline-delimited).
 * Zero external dependencies — Node.js built-ins only.
 */

const https = require('https');
const readline = require('readline');

const BASE_URL = 'https://skillaudit.vercel.app';

const SERVER_INFO = {
  name: 'skillaudit',
  version: '1.0.0',
};

const TOOLS = [
  {
    name: 'scan_url',
    description: 'Scan an AI agent skill file by URL for security threats. Returns risk level, findings, capabilities detected, and verdict.',
    inputSchema: {
      type: 'object',
      properties: {
        url: {
          type: 'string',
          description: 'URL of the skill file to scan (e.g. a SKILL.md or plugin manifest)',
        },
      },
      required: ['url'],
    },
  },
  {
    name: 'scan_content',
    description: 'Scan raw skill/plugin content for security threats. Paste the content directly instead of providing a URL.',
    inputSchema: {
      type: 'object',
      properties: {
        content: {
          type: 'string',
          description: 'Raw text content of the skill file to scan',
        },
        source: {
          type: 'string',
          description: 'Optional label for the source of this content',
        },
      },
      required: ['content'],
    },
  },
  {
    name: 'get_report',
    description: 'Get the full HTML report for a previous scan by its scan ID.',
    inputSchema: {
      type: 'object',
      properties: {
        scan_id: {
          type: 'string',
          description: 'The scan ID returned from a previous scan_url or scan_content call',
        },
      },
      required: ['scan_id'],
    },
  },
];

// --- HTTP helpers (zero deps) ---

function httpsGet(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(data);
        } else {
          reject(new Error(`HTTP ${res.statusCode}: ${data}`));
        }
      });
      res.on('error', reject);
    }).on('error', reject);
  });
}

function httpsPost(url, body) {
  const payload = JSON.stringify(body);
  const parsed = new URL(url);
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || 443,
        path: parsed.pathname + parsed.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(data);
          } else {
            reject(new Error(`HTTP ${res.statusCode}: ${data}`));
          }
        });
        res.on('error', reject);
      }
    );
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// --- Tool execution ---

async function executeTool(name, args) {
  switch (name) {
    case 'scan_url': {
      const url = args.url;
      if (!url) throw new Error('Missing required parameter: url');
      const encodedUrl = encodeURIComponent(url);
      const result = await httpsGet(`${BASE_URL}/scan/quick?url=${encodedUrl}`);
      return JSON.parse(result);
    }
    case 'scan_content': {
      const content = args.content;
      if (!content) throw new Error('Missing required parameter: content');
      const body = { content: content };
      if (args.source) body.source = args.source;
      const result = await httpsPost(`${BASE_URL}/scan/content`, body);
      return JSON.parse(result);
    }
    case 'get_report': {
      const scanId = args.scan_id;
      if (!scanId) throw new Error('Missing required parameter: scan_id');
      const html = await httpsGet(`${BASE_URL}/report/${encodeURIComponent(scanId)}`);
      return { scan_id: scanId, report_url: `${BASE_URL}/report/${scanId}`, html: html };
    }
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// --- JSON-RPC handling ---

function makeResponse(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function makeError(id, code, message, data) {
  const err = { jsonrpc: '2.0', id, error: { code, message } };
  if (data !== undefined) err.error.data = data;
  return err;
}

async function handleMessage(msg) {
  const { id, method, params } = msg;

  switch (method) {
    case 'initialize':
      return makeResponse(id, {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
      });

    case 'notifications/initialized':
      // Client acknowledgement — no response needed
      return null;

    case 'tools/list':
      return makeResponse(id, { tools: TOOLS });

    case 'tools/call': {
      const toolName = params?.name;
      const toolArgs = params?.arguments || {};
      try {
        const result = await executeTool(toolName, toolArgs);
        return makeResponse(id, {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        });
      } catch (err) {
        return makeResponse(id, {
          content: [
            {
              type: 'text',
              text: `Error: ${err.message}`,
            },
          ],
          isError: true,
        });
      }
    }

    default:
      // Unknown method
      if (id !== undefined) {
        return makeError(id, -32601, `Method not found: ${method}`);
      }
      // Notifications without id get no response
      return null;
  }
}

// --- Main loop ---

function main() {
  const rl = readline.createInterface({ input: process.stdin });
  let pending = 0;
  let stdinClosed = false;

  function maybeExit() {
    if (stdinClosed && pending === 0) process.exit(0);
  }

  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      const err = makeError(null, -32700, 'Parse error');
      process.stdout.write(JSON.stringify(err) + '\n');
      return;
    }

    pending++;
    handleMessage(msg)
      .then((response) => {
        if (response) {
          process.stdout.write(JSON.stringify(response) + '\n');
        }
      })
      .catch((err) => {
        const errResp = makeError(msg.id ?? null, -32603, err.message);
        process.stdout.write(JSON.stringify(errResp) + '\n');
      })
      .finally(() => {
        pending--;
        maybeExit();
      });
  });

  rl.on('close', () => {
    stdinClosed = true;
    maybeExit();
  });

  // Log to stderr (not stdout — stdout is for JSON-RPC only)
  process.stderr.write('SkillAudit MCP server started\n');
}

main();
