const fs = require('fs');
const path = require('path');

const rules = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'rules', 'patterns.json'), 'utf8')
).rules;

// Patterns that indicate a line is documentation/example, not actual code
const DOC_PATTERNS = [
  /YOUR_API_KEY/i,
  /YOUR_.*_KEY/i,
  /YOUR_TOKEN/i,
  /xxx+/i,
  /REPLACE_WITH/i,
  /placeholder/i,
  /<your[_-]/i,
  /example/i,
  /^#+\s/,           // markdown headers
  /^\s*[-*]\s.*:/,   // bullet list descriptions
  /```\s*$/,         // code fence boundaries
];

function isDocLine(line) {
  return DOC_PATTERNS.some(p => p.test(line));
}

// Context: check if a line is inside a markdown code example that's clearly instructional
function isInstructionalContext(lines, lineIdx) {
  const line = lines[lineIdx];
  // If line contains placeholder tokens, it's docs
  if (/YOUR_|XXX|REPLACE|<your|example\.com/i.test(line)) return true;
  // Check surrounding lines for doc context
  for (let i = Math.max(0, lineIdx - 3); i <= Math.min(lines.length - 1, lineIdx + 3); i++) {
    if (/^#+\s|Example|Response:|Request:|Usage:/i.test(lines[i])) return true;
  }
  return false;
}

function scanContent(content, sourceUrl = null) {
  const findings = [];
  const lines = content.split('\n');

  for (const rule of rules) {
    for (const patternStr of rule.patterns) {
      const regex = new RegExp(patternStr, 'gi');
      for (let i = 0; i < lines.length; i++) {
        const matches = lines[i].match(regex);
        if (matches) {
          // Skip if this is clearly a documentation/example line
          const isDoc = isInstructionalContext(lines, i);
          
          findings.push({
            ruleId: rule.id,
            severity: isDoc ? 'info' : rule.severity,
            category: rule.category,
            name: rule.name,
            description: rule.description,
            line: i + 1,
            lineContent: lines[i].trim().substring(0, 200),
            match: matches[0],
            suppressed: isDoc
          });
        }
      }
    }
  }

  // Deduplicate by ruleId + line
  const seen = new Set();
  const deduped = findings.filter(f => {
    const key = `${f.ruleId}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Score
  // Filter out suppressed findings for scoring
  const actionable = deduped.filter(f => !f.suppressed);
  const suppressed = deduped.filter(f => f.suppressed);

  const severityScore = { critical: 10, high: 7, medium: 4, low: 1, info: 0 };
  const totalScore = actionable.reduce((sum, f) => sum + (severityScore[f.severity] || 0), 0);

  // Risk level
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
    riskLevel: risk,
    riskScore: totalScore,
    summary: {
      total: actionable.length,
      critical: critCount,
      high: highCount,
      medium: medCount,
      low: actionable.length - critCount - highCount - medCount,
      suppressed: suppressed.length
    },
    findings: actionable,
    verdict: totalScore === 0
      ? '✅ No issues detected. Skill appears safe.'
      : totalScore < 10
        ? '⚠️ Minor concerns found. Review recommended.'
        : totalScore < 25
          ? '🔶 Moderate risk. Manual review required before installing.'
          : '🔴 High risk. DO NOT install without thorough manual audit.'
  };
}

module.exports = { scanContent };
