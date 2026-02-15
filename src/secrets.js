// SkillAudit — Hardcoded Secret Detection Engine
// Detects real API keys, tokens, and credentials embedded in skill files
// NOT env var references — actual leaked secrets

'use strict';

// Each detector: { id, name, description, pattern, severity, validator? }
// validator is an optional function for extra checks (entropy, checksum, etc.)
const SECRET_DETECTORS = [
  // ── OpenAI ──
  {
    id: 'SECRET_OPENAI_KEY',
    name: 'OpenAI API key',
    description: 'Hardcoded OpenAI API key detected — immediate credential exposure risk',
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/g,
    severity: 'critical',
    category: 'hardcoded_secret',
  },
  // ── Anthropic ──
  {
    id: 'SECRET_ANTHROPIC_KEY',
    name: 'Anthropic API key',
    description: 'Hardcoded Anthropic API key detected',
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/g,
    severity: 'critical',
    category: 'hardcoded_secret',
  },
  // ── GitHub PAT ──
  {
    id: 'SECRET_GITHUB_TOKEN',
    name: 'GitHub personal access token',
    description: 'Hardcoded GitHub token — grants repository and account access',
    pattern: /\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})/g,
    severity: 'critical',
    category: 'hardcoded_secret',
  },
  // ── GitHub OAuth / App ──
  {
    id: 'SECRET_GITHUB_OAUTH',
    name: 'GitHub OAuth/App token',
    description: 'Hardcoded GitHub OAuth or App token',
    pattern: /\b(gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36})/g,
    severity: 'critical',
    category: 'hardcoded_secret',
  },
  // ── AWS Access Key ──
  {
    id: 'SECRET_AWS_KEY',
    name: 'AWS access key',
    description: 'Hardcoded AWS access key ID — grants cloud infrastructure access',
    pattern: /\b(AKIA[0-9A-Z]{16})/g,
    severity: 'critical',
    category: 'hardcoded_secret',
  },
  // ── AWS Secret Key (high entropy 40-char base64 near AKIA) ──
  {
    id: 'SECRET_AWS_SECRET',
    name: 'AWS secret access key',
    description: 'Hardcoded AWS secret key detected',
    pattern: /(?:aws_secret_access_key|secret_?key|aws_secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    severity: 'critical',
    category: 'hardcoded_secret',
  },
  // ── Slack tokens ──
  {
    id: 'SECRET_SLACK_TOKEN',
    name: 'Slack token',
    description: 'Hardcoded Slack bot/user/app token',
    pattern: /\b(xox[bpas]-[0-9A-Za-z-]{10,})/g,
    severity: 'critical',
    category: 'hardcoded_secret',
  },
  // ── Slack webhook ──
  {
    id: 'SECRET_SLACK_WEBHOOK',
    name: 'Slack webhook URL',
    description: 'Hardcoded Slack incoming webhook URL',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{20,}/g,
    severity: 'high',
    category: 'hardcoded_secret',
  },
  // ── Discord bot token ──
  {
    id: 'SECRET_DISCORD_TOKEN',
    name: 'Discord bot token',
    description: 'Hardcoded Discord bot token — grants full bot access',
    pattern: /\b[MN][A-Za-z\d]{23,}\.[A-Za-z\d-_]{6}\.[A-Za-z\d-_]{27,}/g,
    severity: 'critical',
    category: 'hardcoded_secret',
    validator: (match) => {
      // Discord tokens are base64-encoded user ID . timestamp . HMAC
      const parts = match.split('.');
      return parts.length === 3 && parts[0].length >= 18;
    },
  },
  // ── Discord webhook ──
  {
    id: 'SECRET_DISCORD_WEBHOOK',
    name: 'Discord webhook URL',
    description: 'Hardcoded Discord webhook — can post messages to channels',
    pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d{17,}\/[A-Za-z0-9_-]{60,}/g,
    severity: 'high',
    category: 'hardcoded_secret',
  },
  // ── Stripe ──
  {
    id: 'SECRET_STRIPE_KEY',
    name: 'Stripe API key',
    description: 'Hardcoded Stripe secret or publishable key',
    pattern: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}/g,
    severity: 'critical',
    category: 'hardcoded_secret',
  },
  // ── Twilio ──
  {
    id: 'SECRET_TWILIO_KEY',
    name: 'Twilio API key',
    description: 'Hardcoded Twilio account SID or auth token',
    pattern: /\bAC[a-f0-9]{32}/g,
    severity: 'high',
    category: 'hardcoded_secret',
  },
  // ── SendGrid ──
  {
    id: 'SECRET_SENDGRID_KEY',
    name: 'SendGrid API key',
    description: 'Hardcoded SendGrid API key',
    pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
    severity: 'critical',
    category: 'hardcoded_secret',
  },
  // ── Google API key ──
  {
    id: 'SECRET_GOOGLE_KEY',
    name: 'Google API key',
    description: 'Hardcoded Google API key',
    pattern: /\bAIza[0-9A-Za-z_-]{35}/g,
    severity: 'high',
    category: 'hardcoded_secret',
  },
  // ── Telegram bot token ──
  {
    id: 'SECRET_TELEGRAM_TOKEN',
    name: 'Telegram bot token',
    description: 'Hardcoded Telegram bot token — grants full bot control',
    pattern: /\b\d{8,10}:[A-Za-z0-9_-]{35}/g,
    severity: 'critical',
    category: 'hardcoded_secret',
  },
  // ── Mailgun ──
  {
    id: 'SECRET_MAILGUN_KEY',
    name: 'Mailgun API key',
    description: 'Hardcoded Mailgun API key',
    pattern: /\bkey-[0-9a-zA-Z]{32}/g,
    severity: 'high',
    category: 'hardcoded_secret',
  },
  // ── Heroku ──
  {
    id: 'SECRET_HEROKU_KEY',
    name: 'Heroku API key',
    description: 'Hardcoded Heroku API key',
    pattern: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
    severity: 'medium',
    category: 'hardcoded_secret',
    // UUIDs are common — only flag near "heroku" context
    contextRequired: /heroku/i,
  },
  // ── Generic high-entropy strings assigned to key/secret/token/password vars ──
  {
    id: 'SECRET_GENERIC_ASSIGNMENT',
    name: 'Hardcoded secret in variable assignment',
    description: 'Variable named key/secret/token/password assigned a high-entropy string literal',
    pattern: /(?:api[_-]?key|secret|token|password|auth[_-]?key|access[_-]?key)\s*[=:]\s*['"]([A-Za-z0-9+/=_-]{20,})['"/]/gi,
    severity: 'high',
    category: 'hardcoded_secret',
    validator: (match, fullMatch) => {
      // Extract the value portion and check entropy
      const valMatch = fullMatch.match(/['"]([A-Za-z0-9+/=_-]{20,})['"]/);
      if (!valMatch) return false;
      const val = valMatch[1];
      // Skip obvious placeholders
      if (/^(your|my|the|test|example|sample|demo|fake|dummy|placeholder|xxx|abc|123)/i.test(val)) return false;
      if (/^[A-Z_]+$/.test(val)) return false; // All caps = probably env var name
      return shannonEntropy(val) > 3.5;
    },
  },
  // ── Private keys (PEM) ──
  {
    id: 'SECRET_PRIVATE_KEY',
    name: 'Private key (PEM)',
    description: 'Embedded private key in PEM format — critical credential exposure',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'critical',
    category: 'hardcoded_secret',
  },
  // ── Vercel token ──
  {
    id: 'SECRET_VERCEL_TOKEN',
    name: 'Vercel token',
    description: 'Hardcoded Vercel deployment token',
    pattern: /\b(vercel_[A-Za-z0-9_-]{20,})/gi,
    severity: 'high',
    category: 'hardcoded_secret',
  },
  // ── npm token ──
  {
    id: 'SECRET_NPM_TOKEN',
    name: 'npm access token',
    description: 'Hardcoded npm registry token — can publish packages',
    pattern: /\bnpm_[A-Za-z0-9]{36}/g,
    severity: 'critical',
    category: 'hardcoded_secret',
  },
  // ── PyPI token ──
  {
    id: 'SECRET_PYPI_TOKEN',
    name: 'PyPI API token',
    description: 'Hardcoded PyPI token — can publish Python packages',
    pattern: /\bpypi-[A-Za-z0-9_-]{50,}/g,
    severity: 'critical',
    category: 'hardcoded_secret',
  },
];

// Shannon entropy calculator
function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Placeholder patterns — if line contains these, suppress the finding
const PLACEHOLDER_SKIP = [
  /YOUR_/i, /YOUR\s+/i, /xxx+/i, /REPLACE/i, /<your[_-]/i,
  /placeholder/i, /example/i, /sample/i, /demo/i, /fake/i, /dummy/i,
  /test[_-]?key/i, /sk-your/i, /sk-xxx/i, /insert[_-]/i,
];

/**
 * Scan content for hardcoded secrets
 * @param {string} content - The file content to scan
 * @param {string[]} lines - Pre-split lines
 * @returns {Array} findings
 */
function detectSecrets(content, lines) {
  const findings = [];

  for (const detector of SECRET_DETECTORS) {
    // Reset regex state
    detector.pattern.lastIndex = 0;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      detector.pattern.lastIndex = 0;
      let match;
      
      while ((match = detector.pattern.exec(line)) !== null) {
        const matchText = match[0];
        
        // Skip if line contains placeholder indicators
        if (PLACEHOLDER_SKIP.some(p => p.test(line))) continue;
        
        // Skip if contextRequired and context not present nearby
        if (detector.contextRequired) {
          const nearby = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 4)).join(' ');
          if (!detector.contextRequired.test(nearby)) continue;
        }
        
        // Run optional validator
        if (detector.validator && !detector.validator(matchText, line)) continue;
        
        // Redact the secret for display (show first 4 chars + last 2)
        const redacted = matchText.length > 10
          ? matchText.slice(0, 6) + '•'.repeat(Math.min(matchText.length - 8, 20)) + matchText.slice(-2)
          : matchText.slice(0, 3) + '•••';
        
        findings.push({
          ruleId: detector.id,
          severity: detector.severity,
          category: detector.category,
          name: detector.name,
          description: detector.description,
          line: i + 1,
          lineContent: line.trim().substring(0, 200),
          match: redacted,
          context: 'hardcoded_secret',
          suppressed: false,
        });
      }
    }
  }

  // Deduplicate by ruleId + line
  const seen = new Set();
  return findings.filter(f => {
    const key = `${f.ruleId}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

module.exports = { detectSecrets, SECRET_DETECTORS, shannonEntropy };
