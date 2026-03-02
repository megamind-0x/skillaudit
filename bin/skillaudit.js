#!/usr/bin/env node

'use strict';

const https = require('https');
const http = require('http');
const path = require('path');
const fs = require('fs');

const VERSION = require('../package.json').version;

// ── CLI args ──────────────────────────────────────────────
const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h') || args.length === 0) {
  console.log(`
  ╔═══════════════════════════════════════╗
  ║   SkillAudit v${VERSION.padEnd(25)}║
  ║   Security scanner for AI agent skills║
  ╚═══════════════════════════════════════╝

  Usage:
    skillaudit <url|file|dir>         Scan a skill (default command)
    skillaudit gate <url>             Pre-install gate check (allow/deny)
    skillaudit manifest <file>        Scan MCP tool manifest JSON
    skillaudit npm <package>          Scan an npm package
    skillaudit pypi <package>         Scan a PyPI package
    skillaudit cargo <crate>          Scan a Rust crate from crates.io
    skillaudit go <module>            Scan a Go module
    skillaudit github <owner/repo>    Scan a GitHub repository
    skillaudit --api <url>            Use hosted API instead of local scan
    skillaudit --mcp                  Start as MCP server (stdio, JSON-RPC)
    skillaudit --version              Show version

  Examples:
    skillaudit https://github.com/user/repo
    skillaudit ./my-skill/SKILL.md
    skillaudit gate https://example.com/SKILL.md
    skillaudit gate https://example.com/SKILL.md --threshold high
    skillaudit manifest tools.json
    skillaudit npm @modelcontextprotocol/sdk
    skillaudit pypi langchain
    skillaudit cargo rmcp
    skillaudit go github.com/anthropics/anthropic-sdk-go
    skillaudit github modelcontextprotocol/servers
    skillaudit SKILL.md --fail-on moderate
    skillaudit SKILL.md --json
    skillaudit SKILL.md --markdown

  Options:
    --json                      Output raw JSON
    --markdown                  Output as markdown (for CI/PR comments)
    --no-color                  Disable colors
    --api                       Use skillaudit.vercel.app API
    --fail-on <level>           Exit 1 if risk >= level (low|moderate|high|critical)
    --threshold <level>         Gate threshold (default: moderate)
`);
  process.exit(0);
}

if (args.includes('--version') || args.includes('-v')) {
  console.log(VERSION);
  process.exit(0);
}

if (args.includes('--mcp')) {
  require('./mcp-server').startServer();
  // MCP server runs indefinitely on stdio
  return;
}

const useApi = args.includes('--api');
const jsonOutput = args.includes('--json');
const markdownOutput = args.includes('--markdown');
const noColor = args.includes('--no-color') || !process.stdout.isTTY || markdownOutput;

// Parse --fail-on and --threshold
function getArgValue(flag) {
  const idx = args.indexOf(flag);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : null;
}
const failOn = getArgValue('--fail-on');
const threshold = getArgValue('--threshold') || 'moderate';

// Subcommand detection
const subcommands = ['gate', 'manifest', 'npm', 'pypi', 'cargo', 'go', 'github'];
const subcommand = subcommands.includes(args[0]) ? args[0] : null;
const positionalArgs = args.filter(a => !a.startsWith('-') && !subcommands.includes(a) && a !== failOn && a !== threshold && a !== getArgValue('--fail-on') && a !== getArgValue('--threshold'));
const target = subcommand ? args.find((a, i) => i > 0 && !a.startsWith('-') && a !== failOn && a !== threshold) : positionalArgs[0];

if (!target) {
  console.error('Error: No target specified. Run skillaudit --help for usage.');
  process.exit(1);
}

// ── Colors ────────────────────────────────────────────────
const c = noColor ? {
  reset: '', bold: '', dim: '', red: '', green: '', yellow: '', cyan: '', magenta: '', gray: ''
} : {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  cyan: '\x1b[36m', magenta: '\x1b[35m', gray: '\x1b[90m'
};

const RISK_COLORS = {
  clean: c.green, low: c.cyan, moderate: c.yellow, high: c.red, critical: `${c.bold}${c.red}`
};

const SEVERITY_ICONS = {
  info: 'ℹ', low: '⚡', medium: '⚠', high: '🔴', critical: '💀'
};

// ── Fetch URL content ─────────────────────────────────────
function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    // Convert GitHub repo URLs to raw content
    const rawUrl = githubToRaw(url);
    const mod = rawUrl.startsWith('https') ? https : http;
    
    const req = mod.get(rawUrl, { headers: { 'User-Agent': `SkillAudit-CLI/${VERSION}` } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchUrl(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`HTTP ${res.statusCode} fetching ${rawUrl}`));
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('Request timeout')); });
  });
}

function githubToRaw(url) {
  // github.com/user/repo → raw SKILL.md or README.md
  const ghMatch = url.match(/^https?:\/\/github\.com\/([^/]+)\/([^/]+)\/?$/);
  if (ghMatch) {
    return `https://raw.githubusercontent.com/${ghMatch[1]}/${ghMatch[2]}/main/SKILL.md`;
  }
  // github.com/user/repo/blob/branch/file → raw
  const blobMatch = url.match(/^https?:\/\/github\.com\/([^/]+)\/([^/]+)\/blob\/(.+)$/);
  if (blobMatch) {
    return `https://raw.githubusercontent.com/${blobMatch[1]}/${blobMatch[2]}/${blobMatch[3]}`;
  }
  return url;
}

// ── Read local files ──────────────────────────────────────
function readLocal(target) {
  const resolved = path.resolve(target);
  const stat = fs.statSync(resolved);
  
  if (stat.isFile()) {
    return fs.readFileSync(resolved, 'utf8');
  }
  
  if (stat.isDirectory()) {
    // Read common skill files
    const files = ['SKILL.md', 'skill.md', 'README.md', 'readme.md', 'AGENTS.md',
                   'setup.sh', 'install.sh', 'init.sh', 'run.sh',
                   'package.json', 'requirements.txt', 'Makefile'];
    let content = '';
    
    // Also grab any .md, .sh, .py, .js in root
    const allFiles = fs.readdirSync(resolved);
    const extras = allFiles.filter(f => /\.(md|sh|py|js|ts|yaml|yml|json)$/i.test(f));
    const toRead = [...new Set([...files, ...extras])];
    
    for (const f of toRead) {
      const fp = path.join(resolved, f);
      if (fs.existsSync(fp) && fs.statSync(fp).isFile()) {
        const text = fs.readFileSync(fp, 'utf8');
        content += `\n--- ${f} ---\n${text}\n`;
      }
    }
    
    if (!content) {
      throw new Error(`No scannable files found in ${resolved}`);
    }
    return content;
  }
  
  throw new Error(`${resolved} is not a file or directory`);
}

// ── API mode ──────────────────────────────────────────────
async function scanViaApi(target) {
  const url = `https://skillaudit.vercel.app/scan?url=${encodeURIComponent(target)}`;
  const data = await fetchUrl(url);
  return JSON.parse(data);
}

// ── Local scan ────────────────────────────────────────────
function scanLocal(content) {
  // Load scanner and capabilities
  const { scanContent } = require('../src/scanner');
  return scanContent(content);
}

// ── Display results ───────────────────────────────────────
function display(result) {
  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  const risk = (result.risk_level || result.riskLevel || 'unknown').toLowerCase();
  const riskColor = RISK_COLORS[risk] || c.yellow;
  const score = result.risk_score ?? result.riskScore ?? '?';
  const findings = result.findings || [];
  const caps = result.capabilities || {};

  console.log('');
  console.log(`${c.bold}  SkillAudit Scan Results${c.reset}`);
  console.log(`${c.gray}  ${'─'.repeat(40)}${c.reset}`);
  console.log(`  Risk Level:  ${riskColor}${c.bold}${risk.toUpperCase()}${c.reset}`);
  console.log(`  Risk Score:  ${riskColor}${score}/100${c.reset}`);
  console.log(`  Findings:    ${findings.length} issue${findings.length !== 1 ? 's' : ''}`);
  console.log('');

  if (findings.length > 0) {
    console.log(`${c.bold}  Findings${c.reset}`);
    console.log(`${c.gray}  ${'─'.repeat(40)}${c.reset}`);
    
    for (const f of findings) {
      const sev = (f.severity || 'medium').toLowerCase();
      const icon = SEVERITY_ICONS[sev] || '•';
      const sevColor = sev === 'critical' ? `${c.bold}${c.red}` : 
                        sev === 'high' ? c.red : 
                        sev === 'medium' ? c.yellow : c.cyan;
      
      console.log(`  ${icon} ${sevColor}[${sev.toUpperCase()}]${c.reset} ${c.bold}${f.rule || f.name || 'Unknown'}${c.reset}`);
      if (f.description) console.log(`    ${c.dim}${f.description}${c.reset}`);
      if (f.line) console.log(`    ${c.gray}Line ${f.line_number || '?'}: ${f.line.substring(0, 80)}${c.reset}`);
      console.log('');
    }
  }

  // Capabilities summary
  const capList = Object.entries(caps).filter(([_, v]) => v === true || (Array.isArray(v) && v.length > 0));
  if (capList.length > 0) {
    console.log(`${c.bold}  Capabilities Detected${c.reset}`);
    console.log(`${c.gray}  ${'─'.repeat(40)}${c.reset}`);
    for (const [cap] of capList) {
      const label = cap.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
      console.log(`  ${c.magenta}•${c.reset} ${label}`);
    }
    console.log('');
  }

  // Verdict
  if (risk === 'clean') {
    console.log(`  ${c.green}✓ No threats detected. Skill appears safe.${c.reset}`);
  } else if (risk === 'low') {
    console.log(`  ${c.cyan}✓ Minor observations. Likely safe for use.${c.reset}`);
  } else if (risk === 'moderate') {
    console.log(`  ${c.yellow}⚠ Review findings before using this skill.${c.reset}`);
  } else if (risk === 'high' || risk === 'critical') {
    console.log(`  ${c.red}✗ Significant risks detected. Use with caution.${c.reset}`);
  }
  
  console.log(`\n  ${c.gray}Scanned by SkillAudit v${VERSION} — https://skillaudit.vercel.app${c.reset}\n`);
}

// ── Markdown output (for CI/PR comments) ──────────────────
function displayMarkdown(result) {
  const risk = (result.risk_level || result.riskLevel || 'unknown').toLowerCase();
  const score = result.risk_score ?? result.riskScore ?? '?';
  const findings = result.findings || [];

  const riskEmoji = { clean: '✅', low: '🟢', moderate: '🟡', high: '🔴', critical: '💀' };
  const sevEmoji = { critical: '💀', high: '🔴', medium: '🟡', low: '🟢', info: 'ℹ️' };

  const lines = [];
  lines.push(`## ${riskEmoji[risk] || '❓'} SkillAudit: ${risk.toUpperCase()}`);
  lines.push('');
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Risk Level | **${risk.toUpperCase()}** |`);
  lines.push(`| Risk Score | ${score} |`);
  lines.push(`| Findings | ${findings.length} |`);
  lines.push('');

  if (findings.length > 0) {
    lines.push('### Findings');
    lines.push('');
    lines.push('| Severity | Rule | Description |');
    lines.push('|----------|------|-------------|');
    for (const f of findings.slice(0, 25)) {
      const sev = (f.severity || 'medium').toLowerCase();
      const name = f.rule || f.name || f.ruleId || 'Unknown';
      const desc = (f.description || '').replace(/\|/g, '\\|').substring(0, 100);
      lines.push(`| ${sevEmoji[sev] || '•'} ${sev} | ${name} | ${desc} |`);
    }
    if (findings.length > 25) lines.push(`| ... | +${findings.length - 25} more | |`);
    lines.push('');
  }

  // Verdict
  const verdict = result.verdict || '';
  if (verdict) lines.push(`> ${verdict}`);
  lines.push('');
  lines.push(`<sub>Scanned by [SkillAudit](https://skillaudit.vercel.app) v${VERSION}</sub>`);

  console.log(lines.join('\n'));
}

// ── Gate display ──────────────────────────────────────────
function displayGate(result, targetUrl) {
  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  if (markdownOutput) {
    const emoji = result.allow ? '✅' : '🚫';
    console.log(`${emoji} **Gate: ${result.decision.toUpperCase()}** — ${targetUrl}`);
    console.log(`Risk: ${result.riskLevel || result.risk}, Score: ${result.riskScore || result.score}, Findings: ${result.findings}`);
    if (result.verdict) console.log(`> ${result.verdict}`);
    return;
  }
  const allow = result.allow;
  const decision = result.decision || (allow ? 'allow' : 'deny');
  const risk = result.riskLevel || result.risk || 'unknown';
  const riskColor = RISK_COLORS[risk] || c.yellow;

  console.log('');
  console.log(`${c.bold}  SkillAudit Gate${c.reset}`);
  console.log(`${c.gray}  ${'─'.repeat(40)}${c.reset}`);
  console.log(`  Decision:  ${allow ? `${c.green}${c.bold}ALLOW` : `${c.red}${c.bold}DENY`}${c.reset}`);
  console.log(`  Risk:      ${riskColor}${risk.toUpperCase()}${c.reset}`);
  console.log(`  Findings:  ${result.findings || 0}`);
  if (result.verdict) console.log(`  Verdict:   ${result.verdict}`);
  console.log('');
}

// ── Manifest display ──────────────────────────────────────
function displayManifest(tools, results) {
  if (jsonOutput) {
    console.log(JSON.stringify(results, null, 2));
    return;
  }
  const { scanContent } = require('../src/scanner');

  // Use the same manifest-specific patterns from the server
  const MANIFEST_POISON_PATTERNS = [
    { pattern: /(?:ignore|disregard|override).*(?:previous|prior|other|above)/i, severity: 'critical', name: 'Instruction override' },
    { pattern: /(?:you must|you should|always|never).*(?:send|post|forward|include|attach)/i, severity: 'critical', name: 'Coercive instruction' },
    { pattern: /(?:do not|don'?t|never).*(?:tell|inform|show|reveal|display|mention).*(?:user|human|person)/i, severity: 'critical', name: 'Anti-disclosure' },
    { pattern: /(?:secretly|silently|quietly|covertly).*(?:send|post|log|record|forward)/i, severity: 'critical', name: 'Covert exfiltration' },
    { pattern: /(?:include|attach|append|add|send).*(?:all|every|entire|full).*(?:conversation|message|context|history)/i, severity: 'critical', name: 'Context harvesting' },
    { pattern: /(?:system\s*prompt|system\s*message|hidden\s*prompt)/i, severity: 'high', name: 'System prompt reference' },
    { pattern: /(?:when|if)\s+(?:the\s+)?(?:user|human)\s+(?:asks?|requests?).*(?:instead|actually|really)/i, severity: 'critical', name: 'User intent override' },
  ];

  let totalFindings = 0;
  let toolResults = [];

  for (const tool of tools) {
    const findings = [];
    const texts = [];
    if (tool.description) texts.push(tool.description);
    // Extract schema descriptions
    function extractDesc(schema) {
      if (!schema || typeof schema !== 'object') return;
      if (schema.description) texts.push(schema.description);
      if (schema.properties) Object.values(schema.properties).forEach(extractDesc);
    }
    if (tool.inputSchema) extractDesc(tool.inputSchema);

    for (const text of texts) {
      for (const mp of MANIFEST_POISON_PATTERNS) {
        if (mp.pattern.test(text)) {
          findings.push({ severity: mp.severity, name: mp.name });
        }
      }
      const r = scanContent(text);
      r.findings.filter(f => !f.suppressed).forEach(f => findings.push({ severity: f.severity, name: f.name }));
    }

    // Dedupe
    const seen = new Set();
    const deduped = findings.filter(f => { const k = f.name; if (seen.has(k)) return false; seen.add(k); return true; });
    totalFindings += deduped.length;
    toolResults.push({ name: tool.name || 'unnamed', findings: deduped });
  }

  if (markdownOutput) {
    console.log(`## 🛡️ SkillAudit Manifest Scan`);
    console.log(`${tools.length} tools scanned, ${totalFindings} findings\n`);
    for (const t of toolResults) {
      const icon = t.findings.length === 0 ? '✅' : '🔴';
      console.log(`${icon} **${t.name}**${t.findings.length > 0 ? ': ' + t.findings.map(f => f.name).join(', ') : ''}`);
    }
    return;
  }

  console.log('');
  console.log(`${c.bold}  SkillAudit Manifest Scan${c.reset}`);
  console.log(`${c.gray}  ${'─'.repeat(40)}${c.reset}`);
  console.log(`  Tools:     ${tools.length}`);
  console.log(`  Findings:  ${totalFindings}`);
  console.log('');

  for (const t of toolResults) {
    if (t.findings.length === 0) {
      console.log(`  ${c.green}✓${c.reset} ${t.name}`);
    } else {
      console.log(`  ${c.red}✗${c.reset} ${c.bold}${t.name}${c.reset}`);
      for (const f of t.findings) {
        const sevColor = f.severity === 'critical' ? `${c.bold}${c.red}` : f.severity === 'high' ? c.red : c.yellow;
        console.log(`    ${sevColor}[${f.severity.toUpperCase()}]${c.reset} ${f.name}`);
      }
    }
  }

  console.log(`\n  ${c.gray}Scanned by SkillAudit v${VERSION}${c.reset}\n`);
  return totalFindings;
}

// ── Package/repo scan display ─────────────────────────────
function displayPackageScan(result, type) {
  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  const name = result.package || result.crate || result.module || result.repo || 'unknown';
  const version = result.version || '';
  const risk = (result.overallRisk || 'unknown').toLowerCase();
  const riskColor = RISK_COLORS[risk] || c.yellow;
  const score = result.totalRiskScore ?? 0;
  const findings = result.totalFindings ?? 0;
  const critical = result.totalCritical ?? 0;
  const high = result.totalHigh ?? 0;
  const files = result.filesScanned ?? result.filesDiscovered ?? 0;
  const verdict = result.verdict || '';

  if (markdownOutput) {
    const riskEmoji = { clean: '✅', low: '🟢', moderate: '🟡', high: '🔴', critical: '💀' };
    console.log(`## ${riskEmoji[risk] || '❓'} SkillAudit ${type}: ${name}${version ? `@${version}` : ''}`);
    console.log('');
    console.log(`| Metric | Value |`);
    console.log(`|--------|-------|`);
    console.log(`| Risk | **${risk.toUpperCase()}** |`);
    console.log(`| Score | ${score} |`);
    console.log(`| Findings | ${findings} (${critical} critical, ${high} high) |`);
    console.log(`| Files Scanned | ${files} |`);
    console.log('');
    if (verdict) console.log(`> ${verdict}`);
    console.log('');

    // Warnings
    const warnings = result.packageWarnings || result.cargoWarnings || result.goWarnings || result.repoWarnings || [];
    if (warnings.length > 0) {
      console.log('### Warnings');
      for (const w of warnings) {
        const icon = w.severity === 'high' ? '🔴' : w.severity === 'medium' ? '🟡' : '🟢';
        console.log(`- ${icon} ${w.description || w.type}`);
      }
      console.log('');
    }

    // File results
    const fileResults = result.files || [];
    if (fileResults.length > 0) {
      console.log('### Files');
      for (const f of fileResults) {
        const fIcon = f.riskLevel === 'clean' ? '✅' : f.riskLevel === 'low' ? '🟢' : '🔴';
        console.log(`- ${fIcon} **${f.file}** — ${f.riskLevel} (${f.findings} findings)`);
      }
    }
    console.log(`\n<sub>Scanned by [SkillAudit](https://skillaudit.vercel.app) v${VERSION}</sub>`);
    return;
  }

  console.log('');
  console.log(`${c.bold}  SkillAudit ${type} Scan${c.reset}`);
  console.log(`${c.gray}  ${'─'.repeat(44)}${c.reset}`);
  console.log(`  Package:   ${c.bold}${name}${version ? `${c.gray}@${version}` : ''}${c.reset}`);
  console.log(`  Risk:      ${riskColor}${c.bold}${risk.toUpperCase()}${c.reset}`);
  console.log(`  Score:     ${riskColor}${score}/100${c.reset}`);
  console.log(`  Findings:  ${findings} total ${critical > 0 ? `${c.red}(${critical} critical)${c.reset} ` : ''}${high > 0 ? `${c.red}(${high} high)${c.reset}` : ''}`);
  console.log(`  Files:     ${files} scanned`);
  console.log('');

  // Warnings
  const warnings = result.packageWarnings || result.cargoWarnings || result.goWarnings || result.repoWarnings || [];
  if (warnings.length > 0) {
    console.log(`${c.bold}  Warnings${c.reset}`);
    console.log(`${c.gray}  ${'─'.repeat(44)}${c.reset}`);
    for (const w of warnings) {
      const sevColor = w.severity === 'high' ? c.red : w.severity === 'medium' ? c.yellow : c.cyan;
      const icon = w.severity === 'high' ? '🔴' : w.severity === 'medium' ? '⚠' : 'ℹ';
      console.log(`  ${icon} ${sevColor}[${(w.severity || 'medium').toUpperCase()}]${c.reset} ${w.description || w.type}`);
    }
    console.log('');
  }

  // File breakdown
  const fileResults = result.files || [];
  if (fileResults.length > 0) {
    console.log(`${c.bold}  Files${c.reset}`);
    console.log(`${c.gray}  ${'─'.repeat(44)}${c.reset}`);
    for (const f of fileResults) {
      const fRisk = (f.riskLevel || 'unknown').toLowerCase();
      const fColor = RISK_COLORS[fRisk] || c.gray;
      const icon = fRisk === 'clean' ? `${c.green}✓` : fRisk === 'low' ? `${c.cyan}~` : `${c.red}✗`;
      console.log(`  ${icon}${c.reset} ${f.file} ${fColor}${fRisk}${c.reset}${f.findings > 0 ? ` ${c.gray}(${f.findings} findings)${c.reset}` : ''}`);
    }
    console.log('');
  }

  // Verdict
  if (verdict) {
    console.log(`  ${verdict}`);
    console.log('');
  }

  console.log(`  ${c.gray}Scanned by SkillAudit v${VERSION} — https://skillaudit.vercel.app${c.reset}\n`);
}

// ── Fetch JSON from API ───────────────────────────────────
function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { headers: { 'User-Agent': `SkillAudit-CLI/${VERSION}`, Accept: 'application/json' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchJson(res.headers.location).then(resolve).catch(reject);
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch { reject(new Error(`Invalid JSON from ${url}`)); }
      });
    });
    req.on('error', reject);
    req.setTimeout(30000, () => { req.destroy(); reject(new Error('Request timeout')); });
  });
}

// ── Main ──────────────────────────────────────────────────
async function main() {
  const isUrl = /^https?:\/\//.test(target);
  const spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  let spinIdx = 0;
  
  const spin = setInterval(() => {
    if (!noColor) {
      process.stdout.write(`\r  ${c.cyan}${spinner[spinIdx++ % spinner.length]}${c.reset} Scanning...`);
    }
  }, 80);

  try {
    // ── Gate subcommand ──
    if (subcommand === 'gate') {
      if (!isUrl) throw new Error('gate requires a URL target');

      if (useApi) {
        // Use hosted API
        const data = await fetchUrl(`https://skillaudit.vercel.app/gate?url=${encodeURIComponent(target)}&threshold=${threshold}`);
        clearInterval(spin);
        if (!noColor) process.stdout.write('\r  \r');
        const result = JSON.parse(data);
        displayGate(result, target);
        process.exit(result.allow ? 0 : 1);
      }

      // Local gate
      let content;
      try { content = await fetchUrl(target); } catch (e) {
        if (target.match(/github\.com\/[^/]+\/[^/]+\/?$/)) {
          const readmeUrl = target.replace(/\/?$/, '').replace('github.com', 'raw.githubusercontent.com') + '/main/README.md';
          content = await fetchUrl(readmeUrl);
        } else { throw e; }
      }

      clearInterval(spin);
      if (!noColor) process.stdout.write('\r  \r');

      const { scanContent } = require('../src/scanner');
      const result = scanContent(content, target);
      const riskOrder = { clean: 0, low: 1, moderate: 2, high: 3, critical: 4 };
      const thresholdIdx = riskOrder[threshold] ?? 2;
      const riskIdx = riskOrder[result.riskLevel] ?? 0;
      const allow = riskIdx < thresholdIdx;
      const decision = riskIdx === 0 ? 'allow' : allow ? 'warn' : 'deny';

      const gateResult = {
        allow,
        decision,
        riskLevel: result.riskLevel,
        riskScore: result.riskScore,
        findings: result.summary.total,
        critical: result.summary.critical,
        verdict: result.verdict,
      };

      displayGate(gateResult, target);
      process.exit(allow ? 0 : 1);
    }

    // ── Manifest subcommand ──
    if (subcommand === 'manifest') {
      clearInterval(spin);
      if (!noColor) process.stdout.write('\r  \r');

      let content;
      if (isUrl) {
        content = await fetchUrl(target);
      } else {
        content = fs.readFileSync(path.resolve(target), 'utf8');
      }

      let parsed;
      try { parsed = JSON.parse(content); } catch { throw new Error('Manifest must be valid JSON'); }
      const tools = parsed.tools || (Array.isArray(parsed) ? parsed : null);
      if (!tools) throw new Error('JSON must contain a "tools" array or be an array of tools');

      const poisonCount = displayManifest(tools);
      const exitCode = (typeof poisonCount === 'number' && poisonCount > 0) ? 1 : 0;
      process.exit(exitCode);
    }

    // ── Package/repo subcommands (use hosted API) ──
    const packageCommands = { npm: 'npm', pypi: 'pypi', cargo: 'cargo', go: 'go', github: 'github' };
    if (packageCommands[subcommand]) {
      if (!target) throw new Error(`${subcommand} requires a target (e.g., skillaudit ${subcommand} ${subcommand === 'npm' ? 'express' : subcommand === 'pypi' ? 'langchain' : subcommand === 'cargo' ? 'rmcp' : subcommand === 'go' ? 'github.com/user/repo' : 'owner/repo'})`);

      const base = 'https://skillaudit.vercel.app';
      let apiUrl;
      let label;
      switch (subcommand) {
        case 'npm':
          apiUrl = `${base}/scan/npm?package=${encodeURIComponent(target)}`;
          label = 'npm';
          break;
        case 'pypi':
          apiUrl = `${base}/scan/pypi?package=${encodeURIComponent(target)}`;
          label = 'PyPI';
          break;
        case 'cargo':
          apiUrl = `${base}/scan/cargo?crate=${encodeURIComponent(target)}`;
          label = 'Cargo';
          break;
        case 'go':
          apiUrl = `${base}/scan/go?module=${encodeURIComponent(target)}`;
          label = 'Go';
          break;
        case 'github':
          apiUrl = `${base}/scan/github?repo=${encodeURIComponent(target)}`;
          label = 'GitHub';
          break;
      }

      const result = await fetchJson(apiUrl);
      clearInterval(spin);
      if (!noColor) process.stdout.write('\r  \r');

      if (result.error) {
        console.error(`\n  ${c.red}Error: ${result.error}${c.reset}`);
        if (result.hint) console.error(`  ${c.gray}${result.hint}${c.reset}`);
        console.error('');
        process.exit(2);
      }

      displayPackageScan(result, label);

      // Exit code based on risk
      const risk = (result.overallRisk || '').toLowerCase();
      if (failOn) {
        const riskOrder = { clean: 0, low: 1, moderate: 2, high: 3, critical: 4 };
        process.exit((riskOrder[risk] ?? 0) >= (riskOrder[failOn] ?? 2) ? 1 : 0);
      }
      process.exit(risk === 'high' || risk === 'critical' ? 1 : 0);
    }

    // ── Default: scan ──
    let result;

    if (useApi) {
      if (!isUrl) throw new Error('--api mode requires a URL target');
      result = await scanViaApi(target);
    } else if (isUrl) {
      let content;
      try { content = await fetchUrl(target); } catch (e) {
        if (target.match(/github\.com\/[^/]+\/[^/]+\/?$/)) {
          const readmeUrl = target.replace(/\/?$/, '').replace('github.com', 'raw.githubusercontent.com') + '/main/README.md';
          content = await fetchUrl(readmeUrl);
        } else { throw e; }
      }
      result = scanLocal(content);
    } else {
      const content = readLocal(target);
      result = scanLocal(content);
    }

    clearInterval(spin);
    if (!noColor) process.stdout.write('\r  \r');

    if (markdownOutput) {
      displayMarkdown(result);
    } else {
      display(result);
    }
    
    const risk = (result.risk_level || result.riskLevel || '').toLowerCase();

    // --fail-on: custom exit code threshold
    if (failOn) {
      const riskOrder = { clean: 0, low: 1, moderate: 2, high: 3, critical: 4 };
      const riskIdx = riskOrder[risk] ?? 0;
      const failIdx = riskOrder[failOn] ?? 2;
      process.exit(riskIdx >= failIdx ? 1 : 0);
    }

    process.exit(risk === 'high' || risk === 'critical' ? 1 : 0);
  } catch (err) {
    clearInterval(spin);
    if (!noColor) process.stdout.write('\r  \r');
    console.error(`\n  ${c.red}Error: ${err.message}${c.reset}\n`);
    process.exit(2);
  }
}

main();
