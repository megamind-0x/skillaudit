#!/usr/bin/env node
'use strict';

const https = require('https');
const http = require('http');

// ── Colors (ANSI) ──────────────────────────────────────────────────────────────
const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
};

// ── Helpers ────────────────────────────────────────────────────────────────────
function riskColor(level) {
  const map = { clean: c.green, low: c.cyan, moderate: c.yellow, high: c.red, critical: `${c.bold}${c.bgRed}${c.white}` };
  return map[level] || c.white;
}

function severityColor(sev) {
  const map = { critical: c.red, high: c.red, medium: c.yellow, low: c.cyan, info: c.dim };
  return map[sev] || c.white;
}

function riskBar(score) {
  const max = 100;
  const filled = Math.round((Math.min(score, max) / max) * 20);
  const empty = 20 - filled;
  const color = score >= 70 ? c.red : score >= 40 ? c.yellow : c.green;
  return `${color}${'█'.repeat(filled)}${c.dim}${'░'.repeat(empty)}${c.reset} ${score}/100`;
}

function fetch(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { headers: { 'User-Agent': 'skillaudit-cli/0.7.0' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetch(res.headers.location).then(resolve, reject);
      }
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 400) {
          reject(new Error(`HTTP ${res.statusCode}: ${data.slice(0, 200)}`));
        } else {
          resolve(data);
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(30000, () => { req.destroy(); reject(new Error('Request timed out (30s)')); });
  });
}

// ── Parse args ─────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const flags = new Set(args.filter(a => a.startsWith('--')));
const positional = args.filter(a => !a.startsWith('--'));

const jsonMode = flags.has('--json');
const verbose = flags.has('--verbose');
const help = flags.has('--help') || flags.has('-h');

if (help) {
  console.log(`
${c.bold}${c.cyan}🛡️  SkillAudit${c.reset} — Security scanner for AI agent skills

${c.bold}Usage:${c.reset}
  ${c.green}npx skillaudit${c.reset} <url>            Scan a skill file
  ${c.green}npx skillaudit${c.reset} <url> --json      Raw JSON output
  ${c.green}npx skillaudit${c.reset} <url> --verbose   Show all findings & permissions

${c.bold}Examples:${c.reset}
  npx skillaudit https://example.com/SKILL.md
  npx skillaudit https://raw.githubusercontent.com/user/repo/main/SKILL.md --verbose

${c.dim}https://skillaudit.vercel.app${c.reset}
`);
  process.exit(0);
}

const url = positional[0];

if (!url) {
  console.error(`${c.red}${c.bold}Error:${c.reset} No URL provided.\n`);
  console.error(`Usage: ${c.green}npx skillaudit${c.reset} <url>\n`);
  console.error(`Run ${c.cyan}npx skillaudit --help${c.reset} for more info.`);
  process.exit(1);
}

// Basic URL validation
try {
  const parsed = new URL(url);
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error();
} catch {
  console.error(`${c.red}${c.bold}Error:${c.reset} Invalid URL: ${url}`);
  process.exit(1);
}

// ── Main ───────────────────────────────────────────────────────────────────────
(async () => {
  const apiUrl = `https://skillaudit.vercel.app/scan/quick?url=${encodeURIComponent(url)}`;

  process.stdout.write(`${c.dim}Scanning...${c.reset}`);

  let raw;
  try {
    raw = await fetch(apiUrl);
  } catch (err) {
    process.stdout.write('\r');
    console.error(`${c.red}${c.bold}Error:${c.reset} ${err.message}`);
    process.exit(1);
  }

  process.stdout.write('\r            \r');

  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    console.error(`${c.red}${c.bold}Error:${c.reset} Invalid response from API.`);
    process.exit(1);
  }

  // Check for API-level errors
  if (data.error) {
    console.error(`${c.red}${c.bold}Error:${c.reset} ${data.error}`);
    process.exit(1);
  }

  // --json mode
  if (jsonMode) {
    console.log(JSON.stringify(data, null, 2));
    process.exit(0);
  }

  // ── Pretty output ──────────────────────────────────────────────────────────
  const risk = data.riskLevel || 'unknown';
  const score = data.riskScore ?? 0;
  const verdict = data.verdict || '';
  const findings = data.findings || [];
  const summary = data.summary || {};
  const perms = data.permissions || {};

  console.log();
  console.log(`${c.bold}🛡️  SkillAudit Report${c.reset}`);
  console.log(`${c.dim}${'─'.repeat(50)}${c.reset}`);
  console.log(`${c.bold}Source:${c.reset}  ${c.dim}${data.source || url}${c.reset}`);
  console.log(`${c.bold}Risk:${c.reset}    ${riskColor(risk)}${risk.toUpperCase()}${c.reset}`);
  console.log(`${c.bold}Score:${c.reset}   ${riskBar(score)}`);
  console.log(`${c.bold}Verdict:${c.reset} ${verdict}`);

  if (summary.total > 0) {
    console.log();
    console.log(`${c.bold}Findings:${c.reset} ${summary.total} total — ` +
      `${c.red}${summary.critical || 0} critical${c.reset}, ` +
      `${c.red}${summary.high || 0} high${c.reset}, ` +
      `${c.yellow}${summary.medium || 0} medium${c.reset}, ` +
      `${c.cyan}${summary.low || 0} low${c.reset}`);

    const show = verbose ? findings : findings.slice(0, 5);
    for (const f of show) {
      const sev = f.severity || 'info';
      const icon = sev === 'critical' || sev === 'high' ? '🔴' : sev === 'medium' ? '🟡' : '🔵';
      console.log(`  ${icon} ${severityColor(sev)}[${sev.toUpperCase()}]${c.reset} ${f.title || f.ruleId || 'Unknown'}`);
      if (f.description && verbose) {
        console.log(`     ${c.dim}${f.description}${c.reset}`);
      }
      if (f.line) {
        console.log(`     ${c.dim}Line ${f.line}${c.reset}`);
      }
    }
    if (!verbose && findings.length > 5) {
      console.log(`  ${c.dim}... and ${findings.length - 5} more (use --verbose)${c.reset}`);
    }
  }

  if (verbose && perms) {
    console.log();
    console.log(`${c.bold}Permissions:${c.reset}`);
    if (perms.summary) console.log(`  ${perms.summary}`);
    const permKeys = ['filesystem', 'network', 'credentials', 'code_execution', 'system_modification', 'agent_memory'];
    for (const key of permKeys) {
      const val = perms[key];
      if (val === undefined) continue;
      if (typeof val === 'object') {
        const parts = Object.entries(val).filter(([k]) => k !== 'summary').map(([k, v]) => `${k}: ${v ? '✗' : '✓'}`);
        console.log(`  ${c.dim}${key}:${c.reset} ${parts.join(', ')}`);
      } else {
        const icon = val ? '✗' : '✓';
        const color = val ? c.red : c.green;
        console.log(`  ${color}${icon}${c.reset} ${key}`);
      }
    }
  }

  if (data.shareUrl) {
    console.log();
    console.log(`${c.dim}Full report: https://skillaudit.vercel.app${data.shareUrl}${c.reset}`);
  }

  console.log();
})();
