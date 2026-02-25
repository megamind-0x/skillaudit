const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { analyzeCapabilities } = require('./capabilities');
const { detectSecrets } = require('./secrets');

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

// --- Placeholder patterns: if a line contains any of these, it's documentation ---
const PLACEHOLDER_PATTERNS = [
  /YOUR_/i, /YOUR\s+/i, /xxx+/i, /REPLACE/i, /<your[_-]/i,
  /REPLACE_WITH/i, /placeholder/i, /example\.com/i,
  /your[_-]api[_-]?key/i, /your[_-]token/i, /your[_-]secret/i,
  /your[_-]access/i, /your[_-]jwt/i,
  /xxx_replace/i,
];

// --- Documentation context keywords (check ±5 lines) ---
const DOC_CONTEXT_WORDS = [
  /\bexample\b/i, /\busage\b/i, /\bstep\s+\d/i, /\bhow\s+to\b/i,
  /\btutorial\b/i, /\bsetup\b/i, /\bconfiguration\b/i, /\bgetting\s+started\b/i,
  /\breference\b/i, /\bquick\s+start\b/i, /\bapi\s+reference\b/i,
  /\bdocumentation\b/i, /\bguide\b/i, /\boverview\b/i,
  /\bsave\s+your\b/i, /\bstore\s+your\b/i, /\bset\s+your\b/i, /\badd\s+your\b/i,
  /\bget\s+your\b/i, /\bcreate\s+your\b/i, /\bgenerate\b/i,
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

// --- Detect if line has placeholder content ---
function hasPlaceholder(line) {
  return PLACEHOLDER_PATTERNS.some(p => p.test(line));
}

// --- Check if surrounding lines (±5) have doc context ---
function hasDocContext(lines, lineIdx, range = 5) {
  for (let i = Math.max(0, lineIdx - range); i <= Math.min(lines.length - 1, lineIdx + range); i++) {
    if (DOC_CONTEXT_WORDS.some(p => p.test(lines[i]))) return true;
  }
  return false;
}

// --- Check if line is in a markdown table ---
function isMarkdownTable(line) {
  return /^\s*\|/.test(line);
}

// --- Check if line is a markdown heading ---
function isMarkdownHeading(line) {
  return /^#+\s/.test(line);
}

function isInstructionalContext(lines, lineIdx) {
  const line = lines[lineIdx];

  // Strong suppression: line itself contains placeholder tokens
  if (hasPlaceholder(line)) return true;

  // Line is in a markdown table
  if (isMarkdownTable(line)) return true;

  // Line is a markdown heading
  if (isMarkdownHeading(line)) return true;

  // Check surrounding context for documentation keywords
  if (hasDocContext(lines, lineIdx)) return true;

  // Lines with backtick-wrapped references like `credentials.json` or `process.env.X`
  if (/`[^`]*`/.test(line) && hasDocContext(lines, lineIdx, 8)) return true;

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

// --- Check if a code block contains placeholder tokens ---
function codeBlockHasPlaceholder(lines, ranges, lineIdx) {
  for (const r of ranges) {
    if (lineIdx > r.start && lineIdx < r.end) {
      for (let i = r.start; i <= r.end; i++) {
        if (hasPlaceholder(lines[i])) return true;
      }
      return false;
    }
  }
  return false;
}

// --- Enhanced suppression logic ---
function shouldSuppress(lines, lineIdx, match, ruleId, codeBlockMap, codeBlockRanges) {
  const line = lines[lineIdx];

  // 1. Line contains placeholder tokens → ALWAYS suppress
  if (hasPlaceholder(line)) return true;

  // 2. Inside code block with placeholder tokens → suppress
  if (codeBlockMap[lineIdx] && codeBlockHasPlaceholder(lines, codeBlockRanges, lineIdx)) return true;

  // 3. Surrounding lines have doc context keywords → weight toward suppression
  if (hasDocContext(lines, lineIdx)) {
    // For credential/token rules in doc context, suppress
    if (['CRED_ENV_READ', 'TOKEN_STEAL', 'CRED_ENV_SAFE'].includes(ruleId)) return true;
    // For other rules in doc context with code blocks, suppress
    if (codeBlockMap[lineIdx]) return true;
  }

  // 4. Markdown table lines → suppress credential references
  if (isMarkdownTable(line) && ['CRED_ENV_READ', 'TOKEN_STEAL'].includes(ruleId)) return true;

  // 5. Authorization: Bearer in curl commands → suppress if placeholder nearby
  if (/Authorization:\s*Bearer/i.test(line)) {
    if (hasPlaceholder(line) || codeBlockMap[lineIdx]) return true;
  }

  // 6. credentials.json in "save your credentials" / "store your" context → suppress
  if (/credentials\.json/i.test(match)) {
    if (hasDocContext(lines, lineIdx, 8)) return true;
    // backtick-wrapped reference
    if (/`credentials\.json`/.test(line)) return true;
  }

  // 7. process.env references in documentation → suppress
  if (/process\.env\./i.test(match) && hasDocContext(lines, lineIdx, 8)) return true;

  // 8. General: if line is in code block and surrounding prose is documentation
  if (codeBlockMap[lineIdx] && hasDocContext(lines, lineIdx, 8)) return true;

  return false;
}

// --- Structural analysis: read → exfiltrate pattern ---
function detectStructuralPatterns(content, lines, codeBlockMap, codeBlockRanges) {
  const findings = [];

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

  let readLines = [], netLines = [];

  for (let i = 0; i < lines.length; i++) {
    // Skip lines in doc-context code blocks
    if (codeBlockMap[i] && hasDocContext(lines, codeBlockRanges, 8)) continue;

    for (const p of readPatterns) {
      if (p.test(lines[i])) { readLines.push(i + 1); break; }
    }
    for (const p of netPatterns) {
      if (p.test(lines[i])) { netLines.push(i + 1); break; }
    }
  }

  // Only flag if BOTH read and net happen outside documentation context
  // Filter out lines that are in documentation context
  const realReadLines = readLines.filter(ln => !isInstructionalContext(lines, ln - 1));
  const realNetLines = netLines.filter(ln => !isInstructionalContext(lines, ln - 1));

  if (realReadLines.length > 0 && realNetLines.length > 0) {
    findings.push({
      ruleId: 'STRUCT_READ_EXFIL',
      severity: 'high',
      category: 'structural',
      name: 'Read → Network pattern detected',
      description: `Skill reads files (lines ${realReadLines.slice(0, 3).join(',')}) and makes network requests (lines ${realNetLines.slice(0, 3).join(',')}). Potential data exfiltration flow.`,
      remediation: 'Separate file reading and network operations. If data must be sent externally, ensure it does not include sensitive files (.env, credentials, keys). Document all data flows explicitly and use allowlists for outbound destinations.',
      line: realReadLines[0],
      lineContent: lines[realReadLines[0] - 1]?.trim().substring(0, 200) || '',
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
        for (const sd of SUSPICIOUS_DOMAINS) {
          if (hostname === sd || hostname.endsWith('.' + sd)) {
            findings.push({
              ruleId: 'URL_SUSPICIOUS',
              severity: 'high',
              category: 'url_reputation',
              name: 'Suspicious domain',
              description: `URL points to known suspicious domain: ${hostname}`,
              remediation: 'Replace suspicious URLs (webhook.site, requestbin, ngrok, etc.) with legitimate service endpoints. These domains are commonly used for data exfiltration and testing. Use proper, documented API endpoints instead.',
              line: i + 1,
              lineContent: lines[i].trim().substring(0, 200),
              match: match[0].substring(0, 100),
              suppressed: false,
            });
          }
        }
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
          findings.push({
            ruleId: 'URL_RAW_IP',
            severity: 'medium',
            category: 'url_reputation',
            name: 'Raw IP address URL',
            description: `URL uses raw IP address instead of domain: ${hostname}`,
            remediation: 'Use proper domain names with HTTPS instead of raw IP addresses. Raw IPs can point to internal services, are harder to audit, and bypass domain-based security controls.',
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

// --- Invisible Unicode detection (raw bytes) ---
function detectInvisibleUnicode(content, lines) {
  const findings = [];
  // Actual zero-width and invisible characters (raw, not escaped)
  const invisibleChars = [
    { char: '\u200B', name: 'Zero-width space' },
    { char: '\u200C', name: 'Zero-width non-joiner' },
    { char: '\u200D', name: 'Zero-width joiner' },
    { char: '\u2060', name: 'Word joiner' },
    { char: '\u2061', name: 'Function application' },
    { char: '\u2062', name: 'Invisible times' },
    { char: '\u2063', name: 'Invisible separator' },
    { char: '\u2064', name: 'Invisible plus' },
    { char: '\uFEFF', name: 'Zero-width no-break space (BOM)' },
    { char: '\u00AD', name: 'Soft hyphen' },
    { char: '\u034F', name: 'Combining grapheme joiner' },
    { char: '\u061C', name: 'Arabic letter mark' },
    { char: '\u180E', name: 'Mongolian vowel separator' },
    { char: '\u2028', name: 'Line separator' },
    { char: '\u2029', name: 'Paragraph separator' },
    { char: '\u202A', name: 'LTR embedding' },
    { char: '\u202B', name: 'RTL embedding' },
    { char: '\u202C', name: 'Pop directional' },
    { char: '\u202D', name: 'LTR override' },
    { char: '\u202E', name: 'RTL override' },
  ];

  for (let i = 0; i < lines.length; i++) {
    for (const ic of invisibleChars) {
      if (lines[i].includes(ic.char)) {
        // Count occurrences
        const count = (lines[i].split(ic.char).length - 1);
        // BOM at line 0 position 0 is normal, skip single occurrence
        if (ic.char === '\uFEFF' && i === 0 && count === 1) continue;
        findings.push({
          ruleId: 'INVISIBLE_UNICODE_RAW',
          severity: 'high',
          category: 'obfuscation',
          name: `Invisible character: ${ic.name}`,
          description: `Line contains ${count} invisible ${ic.name} character(s) (U+${ic.char.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}). May hide malicious content from human review.`,
          line: i + 1,
          lineContent: lines[i].trim().substring(0, 200),
          match: `U+${ic.char.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')} x${count}`,
          suppressed: false,
        });
      }
    }
  }
  return findings;
}

// --- Intent analysis (natural language) ---
function analyzeIntent(lines, codeBlockMap) {
  const findings = [];
  for (let i = 0; i < lines.length; i++) {
    if (codeBlockMap[i]) continue;
    for (const ip of INTENT_PATTERNS) {
      if (ip.pattern.test(lines[i])) {
        findings.push({
          ruleId: 'INTENT_' + ip.name.toUpperCase().replace(/[^A-Z]/g, '_'),
          severity: ip.severity,
          category: 'intent_analysis',
          name: ip.name,
          description: ip.description,
          remediation: 'Rewrite the instruction to avoid directing the agent to send, upload, forward, or delete sensitive data. Skills should describe what they do, not instruct agents to handle sensitive data in specific ways.',
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

// --- Shared threat patterns for decoded/deobfuscated content ---
const DECODED_THREATS = [
  { pattern: /https?:\/\/\S+/i, name: 'Hidden URL', severity: 'high' },
  { pattern: /(?:curl|wget|fetch|axios|http\.request)\s/i, name: 'Hidden network call', severity: 'critical' },
  { pattern: /(?:eval|exec|system|spawn|Function)\s*\(/i, name: 'Hidden code execution', severity: 'critical' },
  { pattern: /(?:\.env|credentials|password|secret|token|api[_-]?key)/i, name: 'Hidden credential reference', severity: 'high' },
  { pattern: /(?:\/bin\/(?:ba)?sh|cmd\.exe|powershell)/i, name: 'Hidden shell reference', severity: 'critical' },
  { pattern: /(?:rm\s+-rf|del\s+\/[fqs]|format\s+c:)/i, name: 'Hidden destructive command', severity: 'critical' },
  { pattern: /(?:webhook\.site|ngrok|requestbin|pipedream)/i, name: 'Hidden exfiltration domain', severity: 'critical' },
  { pattern: /(?:ignore\s+previous|ignore\s+all|new\s+instructions)/i, name: 'Hidden prompt injection', severity: 'critical' },
  { pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+/i, name: 'Hidden SQL', severity: 'high' },
  { pattern: /<script[\s>]/i, name: 'Hidden script tag', severity: 'high' },
  { pattern: /(?:ssh|nc|ncat|socat)\s+/i, name: 'Hidden network tool', severity: 'high' },
  { pattern: /(?:PRIVATE KEY|BEGIN RSA|BEGIN EC)/i, name: 'Hidden private key', severity: 'critical' },
];

function scanDecodedContent(decoded, encoding, lineIdx, lineContent, codeBlockMap, findings) {
  for (const threat of DECODED_THREATS) {
    const threatMatch = decoded.match(threat.pattern);
    if (threatMatch) {
      findings.push({
        ruleId: `${encoding}_HIDDEN_` + threat.name.toUpperCase().replace(/[^A-Z]/g, '_'),
        severity: threat.severity,
        category: 'obfuscation',
        name: `Obfuscated payload (${encoding.toLowerCase()}): ${threat.name}`,
        description: `${encoding}-encoded content contains ${threat.name.toLowerCase()}. Decoded match: "${threatMatch[0].substring(0, 80)}"`,
        line: lineIdx + 1,
        lineContent: lineContent.trim().substring(0, 200),
        match: `${encoding.toLowerCase()}→"${decoded.substring(0, 100).replace(/\n/g, '\\n')}"`,
        context: codeBlockMap[lineIdx] ? `code:${encoding.toLowerCase()}-decoded` : `prose:${encoding.toLowerCase()}-decoded`,
        suppressed: false,
      });
    }
  }
}

// --- Base64 Payload Decoder ---
function decodeAndScanBase64(content, lines, codeBlockMap) {
  const findings = [];
  const b64Regex = /(?:['"`]|=\s*)([A-Za-z0-9+/]{40,}={0,2})(?:['"`]|$|\s)/g;

  for (let i = 0; i < lines.length; i++) {
    // For base64, only skip if line has explicit placeholder tokens
    // (Don't skip based on doc context — attackers hide payloads in config/docs sections)
    if (hasPlaceholder(lines[i])) continue;

    let match;
    b64Regex.lastIndex = 0;
    while ((match = b64Regex.exec(lines[i])) !== null) {
      const b64str = match[1];
      // Skip if it looks like a hash (hex-only) or a common non-payload pattern
      if (/^[A-Fa-f0-9]+$/.test(b64str)) continue;
      // Skip very common base64 strings that are just asset paths or CSS
      if (/^data:image|^iVBOR|^AAAA|^AQAB/.test(b64str)) continue;

      try {
        const decoded = Buffer.from(b64str, 'base64').toString('utf8');
        // Check if decoded content is printable text (not binary garbage)
        const printableRatio = decoded.replace(/[^\x20-\x7E\n\r\t]/g, '').length / decoded.length;
        if (printableRatio < 0.7) continue; // Likely binary data, not a text payload

        scanDecodedContent(decoded, 'BASE64', i, lines[i], codeBlockMap, findings);
      } catch {
        // Invalid base64, skip
      }
    }
  }
  return findings;
}

// --- Hex/Unicode/CharCode Escape Decoder ---
// Decodes \x41\x42, \u0041, String.fromCharCode(65,66), and octal \101 sequences
function decodeAndScanEscapes(content, lines, codeBlockMap) {
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    if (hasPlaceholder(lines[i])) continue;
    const line = lines[i];

    // 1. Hex escapes: \x41\x42\x43... (min 6 chars = 3 bytes)
    const hexSeqs = line.match(/(?:\\x[0-9a-fA-F]{2}){3,}/g);
    if (hexSeqs) {
      for (const seq of hexSeqs) {
        try {
          const decoded = seq.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
          const printable = decoded.replace(/[^\x20-\x7E]/g, '').length / decoded.length;
          if (printable >= 0.7) {
            scanDecodedContent(decoded, 'HEX', i, line, codeBlockMap, findings);
          }
        } catch {}
      }
    }

    // 2. Unicode escapes: \u0041\u0042... (min 3 chars)
    const uniSeqs = line.match(/(?:\\u[0-9a-fA-F]{4}){3,}/g);
    if (uniSeqs) {
      for (const seq of uniSeqs) {
        try {
          const decoded = seq.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
          const printable = decoded.replace(/[^\x20-\x7E]/g, '').length / decoded.length;
          if (printable >= 0.7) {
            scanDecodedContent(decoded, 'UNICODE', i, line, codeBlockMap, findings);
          }
        } catch {}
      }
    }

    // 3. String.fromCharCode(65, 66, 67, ...) — min 3 numbers
    const charCodeMatch = line.match(/String\.fromCharCode\s*\(\s*([\d,\s]+)\s*\)/gi);
    if (charCodeMatch) {
      for (const match of charCodeMatch) {
        try {
          const nums = match.match(/\d+/g);
          if (nums && nums.length >= 3) {
            const decoded = nums.map(n => String.fromCharCode(parseInt(n))).join('');
            const printable = decoded.replace(/[^\x20-\x7E]/g, '').length / decoded.length;
            if (printable >= 0.7) {
              scanDecodedContent(decoded, 'CHARCODE', i, line, codeBlockMap, findings);
            }
          }
        } catch {}
      }
    }

    // 4. Array of char codes: [99,117,114,108].map(c=>String.fromCharCode(c))
    const arrayCharMatch = line.match(/\[\s*(\d+(?:\s*,\s*\d+){2,})\s*\][\s.]*(?:map|forEach|reduce)/gi);
    if (arrayCharMatch) {
      for (const match of arrayCharMatch) {
        try {
          const nums = match.match(/\d+/g);
          if (nums && nums.length >= 3 && nums.every(n => parseInt(n) >= 32 && parseInt(n) <= 126)) {
            const decoded = nums.map(n => String.fromCharCode(parseInt(n))).join('');
            scanDecodedContent(decoded, 'CHARCODE_ARRAY', i, line, codeBlockMap, findings);
          }
        } catch {}
      }
    }
  }
  return findings;
}

function scanContent(content, sourceUrl = null) {
  const findings = [];
  const lines = content.split('\n');
  const { map: codeBlockMap, ranges: codeBlockRanges } = buildCodeBlockMap(lines);

  // 1. Rule-based pattern matching (with enhanced context suppression)
  for (const rule of rules) {
    for (const patternStr of rule.patterns) {
      const regex = new RegExp(patternStr, 'gi');
      for (let i = 0; i < lines.length; i++) {
        const matches = lines[i].match(regex);
        if (matches) {
          const inCodeBlock = codeBlockMap[i];
          const blockLang = getCodeBlockLang(codeBlockRanges, i);
          const suppressed = shouldSuppress(lines, i, matches[0], rule.id, codeBlockMap, codeBlockRanges);

          let adjustedSeverity = suppressed ? 'info' : rule.severity;
          if (!suppressed && inCodeBlock && ['bash', 'sh', 'shell', 'zsh'].includes(blockLang)) {
            if (adjustedSeverity === 'medium') adjustedSeverity = 'high';
            else if (adjustedSeverity === 'high') adjustedSeverity = 'critical';
          }

          findings.push({
            ruleId: rule.id,
            severity: adjustedSeverity,
            category: rule.category,
            name: rule.name,
            description: rule.description,
            remediation: rule.remediation || null,
            line: i + 1,
            lineContent: lines[i].trim().substring(0, 200),
            match: matches[0],
            context: inCodeBlock ? `code:${blockLang || 'unknown'}` : 'prose',
            suppressed,
          });
        }
      }
    }
  }

  // 2. Structural analysis
  findings.push(...detectStructuralPatterns(content, lines, codeBlockMap, codeBlockRanges));

  // 3. URL reputation
  findings.push(...analyzeUrls(content, lines));

  // 4. Intent analysis
  findings.push(...analyzeIntent(lines, codeBlockMap));

  // 5. Hardcoded secret detection
  findings.push(...detectSecrets(content, lines));

  // 5.5. Raw invisible Unicode detection
  findings.push(...detectInvisibleUnicode(content, lines));

  // 5.6. Base64 payload decoder — find, decode, and scan hidden content
  findings.push(...decodeAndScanBase64(content, lines, codeBlockMap));

  // 5.7. Hex/Unicode/CharCode escape decoder
  findings.push(...decodeAndScanEscapes(content, lines, codeBlockMap));

  // 6. Capability analysis (v0.6.1)
  const capabilityAnalysis = analyzeCapabilities(content);
  
  // Convert threat chains to findings
  capabilityAnalysis.threatChains.forEach(chain => {
    findings.push({
      ruleId: `THREAT_CHAIN_${chain.name}`,
      severity: chain.severity,
      category: chain.category,
      name: `Threat Chain: ${chain.name}`,
      description: chain.description,
      remediation: 'This skill combines multiple capabilities that together form a dangerous pattern (e.g., file reading + network access = potential exfiltration). Remove or isolate one of the capabilities. If both are needed, document exactly what data flows where and why.',
      line: chain.evidence[Object.keys(chain.evidence)[0]].lines[0], // Use first capability's first line
      lineContent: `Capability combination: ${chain.capabilities.join(' + ')}`,
      match: chain.capabilities.join(' + '),
      context: 'capability_analysis',
      suppressed: false,
      threatChain: true,
      capabilities: chain.capabilities,
      evidence: chain.evidence
    });
  });

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

  // Content hash for certificate verification
  const contentHash = crypto.createHash('sha256').update(content).digest('hex');

  return {
    source: sourceUrl || 'inline',
    scannedAt: new Date().toISOString(),
    version: '1.0.0',
    contentHash,
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
    capabilities: capabilityAnalysis.capabilities,
    threatChains: capabilityAnalysis.threatChains,
    permissions: capabilityAnalysis.permissions,
    capabilityStats: {
      totalCapabilities: capabilityAnalysis.capabilityCount,
      threatChains: capabilityAnalysis.threatChainCount,
      riskFactors: capabilityAnalysis.riskFactors
    },
    verdict: totalScore === 0 && capabilityAnalysis.threatChainCount === 0
      ? '✅ No issues detected. Skill appears safe.'
      : totalScore < 10 && capabilityAnalysis.threatChainCount === 0
        ? '⚠️ Minor concerns found. Review recommended.'
        : totalScore < 25 && capabilityAnalysis.threatChainCount <= 1
          ? '🔶 Moderate risk. Manual review required before installing.'
          : '🔴 High risk. DO NOT install without thorough manual audit.',
  };
}

module.exports = { scanContent, SAFE_DOMAINS, SUSPICIOUS_DOMAINS };
