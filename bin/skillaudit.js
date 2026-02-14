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
    skillaudit <url>            Scan a skill from URL
    skillaudit <file>           Scan a local file or directory
    skillaudit --api <url>      Use hosted API instead of local scan
    skillaudit --version        Show version
    skillaudit --help           Show this help

  Examples:
    skillaudit https://github.com/user/repo
    skillaudit ./my-skill/
    skillaudit SKILL.md
    skillaudit --api https://github.com/user/repo

  Options:
    --json                      Output raw JSON
    --no-color                  Disable colors
    --api                       Use skillaudit.vercel.app API
`);
  process.exit(0);
}

if (args.includes('--version') || args.includes('-v')) {
  console.log(VERSION);
  process.exit(0);
}

const useApi = args.includes('--api');
const jsonOutput = args.includes('--json');
const noColor = args.includes('--no-color') || !process.stdout.isTTY;
const target = args.find(a => !a.startsWith('-'));

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
    let result;

    if (useApi) {
      if (!isUrl) throw new Error('--api mode requires a URL target');
      result = await scanViaApi(target);
    } else if (isUrl) {
      // Fetch then scan locally
      let content;
      try {
        content = await fetchUrl(target);
      } catch (e) {
        // If SKILL.md fails for GitHub repos, try README.md
        if (target.match(/github\.com\/[^/]+\/[^/]+\/?$/)) {
          const readmeUrl = target.replace(/\/?$/, '').replace('github.com', 'raw.githubusercontent.com') + '/main/README.md';
          content = await fetchUrl(readmeUrl);
        } else {
          throw e;
        }
      }
      result = scanLocal(content);
    } else {
      // Local file/dir
      const content = readLocal(target);
      result = scanLocal(content);
    }

    clearInterval(spin);
    if (!noColor) process.stdout.write('\r  \r');

    display(result);
    
    const risk = (result.risk_level || result.riskLevel || '').toLowerCase();
    process.exit(risk === 'high' || risk === 'critical' ? 1 : 0);
  } catch (err) {
    clearInterval(spin);
    if (!noColor) process.stdout.write('\r  \r');
    console.error(`\n  ${c.red}Error: ${err.message}${c.reset}\n`);
    process.exit(2);
  }
}

main();
