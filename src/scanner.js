const fs = require('fs');
const path = require('path');

const rules = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'rules', 'patterns.json'), 'utf8')
).rules;

// --- Known-safe domains ---
const SAFE_DOMAINS = new Set([
  'github.com', 'raw.githubusercontent.com', 'gist.github.com',
  'npmjs.com', 'registry.npmjs.org', 'unpkg.com',
  'moltbook.com', 'agentvalley.tech',
  'pypi.org', 'crates.io', 'rubygems.org',
  'stackoverflow.com', 'developer.mozilla.org',
  'google.com', 'googleapis.com', 'cloudflare.com',
  'vercel.app', 'netlify.app', 'heroku.com',
  'docker.io', 'hub.docker.com',
  'openai.com', 'anthropic.com', 'huggingface.co',
  'linkedin.com', 'twitter.com', 'x.com',
  'medium.com', 'dev.to', 'hashnode.dev',
  'wikipedia.org', 'wikimedia.org',
  'cdn.jsdelivr.net', 'cdnjs.cloudflare.com',
]);

const SUSPICIOUS_DOMAINS = new Set([
  'webhook.site', 'requestbin.com', 'pipedream.net',
  'ngrok.io', 'ngrok-free.app', 'burpcollaborator.net',
  'interact.sh', 'oastify.com', 'hookbin.com', 'postb.in',
  'rbndr.us', '1u.ms', 'nip.io', 'xip.io',
  'pastebin.com', 'transfer.sh', 'file.io',
]);

// Patterns that indicate a line is documentation/example
const DOC_PATTERNS = [
  /YOUR_API_KEY/i, /YOUR_.*_KEY/i, /YOUR_TOKEN/i,
  /xxx+/i, /REPLACE_WITH/i, /placeholder/i,
  /<your[_-]/i, /example/i,
  /^#+\s/, /^\s*[-*]\s.*:/, /```\s*$/,
];

// --- Dangerous intent patterns (natural language) ---
const INTENT_PATTERNS = [
  { pattern: /send\s+(the\s+)?(contents?|data|file|config|credentials?|secrets?|tokens?)\s+(of|from|to)\s/i, severity: 'high', name: 'Exfiltration intent', description: 'Instruction asks to send sensitive data externally' },
  { pattern: /upload\s+(the\s+)?(contents?|data|file|config|credentials?|secrets?)\s/i, severity: 'high', name: 'Upload intent', description: 'Instruction asks to upload sensitive data' },
  { pattern: /post\s+(the\s+)?(contents?|data|results?)\s+to\s+/i, severity: 'medium', name: 'POST data intent', description: 'Instruction asks to POST data to an endpoint' },
  { pattern: /read\s+.*\.(env|key|pem|secret|credentials)\b.*(?:send|post|upload|forward|transmit)/i, severity: 'critical', name: 'Read-and-exfiltrate intent', description: 'Instruction asks to read secrets then send them' },
  { pattern: /(?:forward|relay|copy)\s+.*(?:api.?key|token|password|secret|credential)\s+to\s/i, severity: 'critical', name: 'Credential forwarding intent', description: 'Instruction asks to forward credentials' },
  { pattern: /(?:delete|remove|wipe|destroy)\s+(all\s+)?(files?|data|logs?|history|memory)/i, severity: 'high', name: 'Destructive intent', description: 'Instruction asks to delete files or data' },
  { pattern: /install\s+.*(?:backdoor|rootkit|keylogger|trojan|malware)/i, severity: 'critical', name: 'Malware install intent', description: 'Instruction asks to install malicious software' },
  { pattern: /disable\s+.*(?:firewall|antivirus|security|logging|audit)/i, severity: 'critical', name: 'Security disable intent', description: 'Instruction asks to disable security measures' },
  { pattern: /connect\s+(?:back|reverse)\s+to/i, severity: 'high', name: 'Reverse connection intent', description: 'Instruction asks to connect back to attacker' },
  { pattern: /exfiltrate/i, severity: 'critical', name: 'Explicit exfiltration', description: 'Instruction explicitly mentions exfiltration' },
];

function isInstructionalContext(lines, lineIdx) {
  const line = lines[lineIdx];
  if (/YOUR_|XXX|REPLACE|<your|example\.com/i.test(line)) return true;
  for (let i = Math.max(0, lineIdx - 3); i <= Math.min(lines.length - 1, lineIdx + 3); i++) {
    if (/^#+\s|Example|Response:|Request:|Usage:/i.test(lines[i])) return true;
  }
  return false;
}

// --- Detect code block context ---
function buildCodeBlockMap(lines) {
  const map = new Array(lines.length).fill(false);
  let inBlock = false;
  let blockLang = '';
  const blockRanges = [];
  let blockStart = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/^```/.test(lines[i].trim())) {
      if (!inBlock) {
        inBlock = true;
        blockStart = i;
        blockLang = lines[i].trim().replace(/^```/, '').trim().toLowerCase();
      } else {
        inBlock = false;
        blockRanges.push({ start: blockStart, end: i, lang: blockLang });
        blockLang = '';
      }
    }
    map[i] = inBlock;
  }
  return { map, ranges: blockRanges };
}

function getCodeBlockLang(ranges, lineIdx) {
  for (const r of ranges) {
    if (lineIdx > r.start && lineIdx < r.end) return r.lang;
  }
  return null;
}

// --- Structural analysis: read → exfiltrate pattern ---
function detectStructuralPatterns(content, lines) {
  const findings = [];

  // Detect read-file + network-request in same flow
  const readPatterns = [
    /readFile/i, /fs\.read/i, /cat\s+/i, /open\s*\(/i,
    /read\s+.*file/i, /load\s+.*config/i, /read\s+.*\.env/i,
    /fs\.readFileSync/i, /readFileSync/i,
  ];
  const netPatterns = [
    /fetch\s*\(/i, /axios/i, /http\.request/i, /https\.request/i,
    /curl\s/i, /wget\s/i, /XMLHttpRequest/i, /\.post\s*\(/i,
    /send\s+.*to\s+http/i, /POST\s+.*http/i,
  ];

  let hasRead = false, hasNet = false;
  let readLines = [], netLines = [];

  for (let i = 0; i < lines.length; i++) {
    for (const p of readPatterns) {
      if (p.test(lines[i])) { hasRead = true; readLines.push(i + 1); break; }
    }
    for (const p of netPatterns) {
      if (p.test(lines[i])) { hasNet = true; netLines.push(i + 1); break; }
    }
  }

  if (hasRead && hasNet) {
    findings.push({
      ruleId: 'STRUCT_READ_EXFIL',
      severity: 'high',
      category: 'structural',
      name: 'Read → Network pattern detected',
      description: `Skill reads files (lines ${readLines.slice(0, 3).join(',')}) and makes network requests (lines ${netLines.slice(0, 3).join(',')}). Potential data exfiltration flow.`,
      line: readLines[0],
      lineContent: lines[readLines[0] - 1]?.trim().substring(0, 200) || '',
      match: 'structural',
      suppressed: false,
    });
  }

  return findings;
}

// --- URL reputation analysis ---
function analyzeUrls(content, lines) {
  const findings = [];
  const urlRegex = /https?:\/\/[^\s"'<>\])}]+/gi;

  for (let i = 0; i < lines.length; i++) {
    let match;
    while ((match = urlRegex.exec(lines[i])) !== null) {
      try {
        const hostname = new URL(match[0]).hostname.toLowerCase();
        // Check against suspicious domains
        for (const sd of SUSPICIOUS_DOMAINS) {
          if (hostname === sd || hostname.endsWith('.' + sd)) {
            findings.push({
              ruleId: 'URL_SUSPICIOUS',
              severity: 'high',
              category: 'url_reputation',
              name: 'Suspicious domain',
              description: `URL points to known suspicious domain: ${hostname}`,
              line: i + 1,
              lineContent: lines[i].trim().substring(0, 200),
              match: match[0].substring(0, 100),
              suppressed: false,
            });
          }
        }
        // Flag raw IP addresses
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
          findings.push({
            ruleId: 'URL_RAW_IP',
            severity: 'medium',
            category: 'url_reputation',
            name: 'Raw IP address URL',
            description: `URL uses raw IP address instead of domain: ${hostname}`,
            line: i + 1,
            lineContent: lines[i].trim().substring(0, 200),
            match: match[0].substring(0, 100),
            suppressed: false,
          });
        }
      } catch {}
    }
    urlRegex.lastIndex = 0;
  }

  return findings;
}

// --- Intent analysis (natural language) ---
function analyzeIntent(lines, codeBlockMap) {
  const findings = [];
  for (let i = 0; i < lines.length; i++) {
    // Only check prose (non-code) lines
    if (codeBlockMap[i]) continue;
    for (const ip of INTENT_PATTERNS) {
      if (ip.pattern.test(lines[i])) {
        findings.push({
          ruleId: 'INTENT_' + ip.name.toUpperCase().replace(/[^A-Z]/g, '_'),
          severity: ip.severity,
          category: 'intent_analysis',
          name: ip.name,
          description: ip.description,
          line: i + 1,
          lineContent: lines[i].trim().substring(0, 200),
          match: lines[i].match(ip.pattern)?.[0] || '',
          suppressed: false,
        });
      }
    }
  }
  return findings;
}

function scanContent(content, sourceUrl = null) {
  const findings = [];
  const lines = content.split('\n');
  const { map: codeBlockMap, ranges: codeBlockRanges } = buildCodeBlockMap(lines);

  // 1. Rule-based pattern matching (with context weighting)
  for (const rule of rules) {
    for (const patternStr of rule.patterns) {
      const regex = new RegExp(patternStr, 'gi');
      for (let i = 0; i < lines.length; i++) {
        const matches = lines[i].match(regex);
        if (matches) {
          const isDoc = isInstructionalContext(lines, i);
          const inCodeBlock = codeBlockMap[i];
          const blockLang = getCodeBlockLang(codeBlockRanges, i);

          // Context weighting: credential patterns in bash/shell blocks are riskier
          let adjustedSeverity = isDoc ? 'info' : rule.severity;
          if (!isDoc && inCodeBlock && ['bash', 'sh', 'shell', 'zsh'].includes(blockLang)) {
            // Bump medium → high, high → critical for executable code blocks
            if (adjustedSeverity === 'medium') adjustedSeverity = 'high';
            else if (adjustedSeverity === 'high') adjustedSeverity = 'critical';
          }

          findings.push({
            ruleId: rule.id,
            severity: adjustedSeverity,
            category: rule.category,
            name: rule.name,
            description: rule.description,
            line: i + 1,
            lineContent: lines[i].trim().substring(0, 200),
            match: matches[0],
            context: inCodeBlock ? `code:${blockLang || 'unknown'}` : 'prose',
            suppressed: isDoc,
          });
        }
      }
    }
  }

  // 2. Structural analysis
  findings.push(...detectStructuralPatterns(content, lines));

  // 3. URL reputation
  findings.push(...analyzeUrls(content, lines));

  // 4. Intent analysis
  findings.push(...analyzeIntent(lines, codeBlockMap));

  // Deduplicate by ruleId + line
  const seen = new Set();
  const deduped = findings.filter(f => {
    const key = `${f.ruleId}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const actionable = deduped.filter(f => !f.suppressed);
  const suppressed = deduped.filter(f => f.suppressed);

  const severityScore = { critical: 10, high: 7, medium: 4, low: 1, info: 0 };
  const totalScore = actionable.reduce((sum, f) => sum + (severityScore[f.severity] || 0), 0);

  let risk = 'clean';
  if (totalScore > 0) risk = 'low';
  if (totalScore >= 10) risk = 'moderate';
  if (totalScore >= 25) risk = 'high';
  if (totalScore >= 50) risk = 'critical';

  const critCount = actionable.filter(f => f.severity === 'critical').length;
  const highCount = actionable.filter(f => f.severity === 'high').length;
  const medCount = actionable.filter(f => f.severity === 'medium').length;

  return {
    source: sourceUrl || 'inline',
    scannedAt: new Date().toISOString(),
    version: '0.3.0',
    riskLevel: risk,
    riskScore: totalScore,
    summary: {
      total: actionable.length,
      critical: critCount,
      high: highCount,
      medium: medCount,
      low: actionable.length - critCount - highCount - medCount,
      suppressed: suppressed.length,
    },
    findings: actionable,
    verdict: totalScore === 0
      ? '✅ No issues detected. Skill appears safe.'
      : totalScore < 10
        ? '⚠️ Minor concerns found. Review recommended.'
        : totalScore < 25
          ? '🔶 Moderate risk. Manual review required before installing.'
          : '🔴 High risk. DO NOT install without thorough manual audit.',
  };
}

module.exports = { scanContent, SAFE_DOMAINS, SUSPICIOUS_DOMAINS };
