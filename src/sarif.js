/**
 * SARIF (Static Analysis Results Interchange Format) v2.1.0 output
 * 
 * Converts SkillAudit scan results to SARIF — the industry standard
 * for security scanner output. Supported by GitHub Code Scanning,
 * VS Code SARIF Viewer, Azure DevOps, and every major security tool.
 * 
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

const SARIF_VERSION = '2.1.0';
const SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json';

// Map SkillAudit severity → SARIF level
function toSarifLevel(severity) {
  switch (severity) {
    case 'critical': return 'error';
    case 'high': return 'error';
    case 'medium': return 'warning';
    case 'low': return 'note';
    case 'info': return 'note';
    default: return 'none';
  }
}

// Map SkillAudit severity → SARIF security-severity (CVSS-like 0-10 scale)
function toSecuritySeverity(severity) {
  switch (severity) {
    case 'critical': return '9.5';
    case 'high': return '7.5';
    case 'medium': return '5.0';
    case 'low': return '2.5';
    case 'info': return '0.0';
    default: return '0.0';
  }
}

// Map SkillAudit category → SARIF tag
function categoryToTags(category) {
  const tags = ['security', 'ai-skill'];
  switch (category) {
    case 'credential_theft': tags.push('credentials', 'secret-detection'); break;
    case 'data_exfiltration': tags.push('exfiltration', 'data-leak'); break;
    case 'prompt_injection': tags.push('injection', 'prompt-injection'); break;
    case 'url_reputation': tags.push('url-reputation', 'suspicious-domain'); break;
    case 'intent_analysis': tags.push('intent-detection', 'behavioral'); break;
    case 'structural': tags.push('structural-analysis', 'data-flow'); break;
    case 'capability_analysis': tags.push('capability', 'threat-chain'); break;
    case 'secret_detection': tags.push('credentials', 'hardcoded-secret'); break;
    default: if (category) tags.push(category);
  }
  return tags;
}

/**
 * Convert a SkillAudit scan result to SARIF format.
 * 
 * @param {Object} result - SkillAudit scan result
 * @param {Object} [options] - Options
 * @param {boolean} [options.includeSupressed] - Include suppressed findings as 'note' level
 * @returns {Object} SARIF v2.1.0 document
 */
function toSarif(result, options = {}) {
  const source = result.source || result.url || 'unknown';
  const includeSupressed = options.includeSuppressed || false;

  // Collect unique rules from findings
  const ruleMap = new Map();
  const allFindings = includeSupressed 
    ? [...(result.findings || []), ...(result.suppressedFindings || [])]
    : (result.findings || []);
  
  for (const f of allFindings) {
    if (!ruleMap.has(f.ruleId)) {
      ruleMap.set(f.ruleId, {
        id: f.ruleId,
        name: f.name,
        shortDescription: { text: f.name },
        fullDescription: { text: f.description },
        helpUri: `https://skillaudit.vercel.app/rules`,
        defaultConfiguration: {
          level: toSarifLevel(f.severity),
        },
        properties: {
          tags: categoryToTags(f.category),
          'security-severity': toSecuritySeverity(f.severity),
          category: f.category || 'unknown',
        },
      });
    }
  }

  // Build results array
  const results = allFindings.map((f, idx) => {
    const sarifResult = {
      ruleId: f.ruleId,
      ruleIndex: [...ruleMap.keys()].indexOf(f.ruleId),
      level: f.suppressed ? 'note' : toSarifLevel(f.severity),
      message: {
        text: f.description + (f.match ? ` (matched: \`${f.match}\`)` : ''),
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: source,
              uriBaseId: '%SRCROOT%',
            },
            region: {
              startLine: f.line || 1,
              startColumn: 1,
              snippet: {
                text: f.lineContent || '',
              },
            },
          },
        },
      ],
      properties: {
        severity: f.severity,
        category: f.category,
        context: f.context || null,
        suppressed: f.suppressed || false,
      },
    };

    // Add suppression info for suppressed findings
    if (f.suppressed) {
      sarifResult.suppressions = [
        {
          kind: 'inSource',
          justification: 'Detected as documentation/instructional context by SkillAudit heuristics',
        },
      ];
    }

    // Add threat chain info
    if (f.threatChain) {
      sarifResult.properties.threatChain = true;
      sarifResult.properties.capabilities = f.capabilities;
    }

    return sarifResult;
  });

  // Build the SARIF document
  const sarif = {
    version: SARIF_VERSION,
    $schema: SARIF_SCHEMA,
    runs: [
      {
        tool: {
          driver: {
            name: 'SkillAudit',
            version: result.version || '0.8.1',
            informationUri: 'https://skillaudit.vercel.app',
            semanticVersion: result.version || '0.8.1',
            rules: [...ruleMap.values()],
            properties: {
              description: 'Security scanner for AI agent skills — detects credential theft, data exfiltration, prompt injection, and more.',
            },
          },
        },
        results,
        artifacts: [
          {
            location: {
              uri: source,
              uriBaseId: '%SRCROOT%',
            },
            hashes: result.contentHash
              ? { 'sha-256': result.contentHash }
              : undefined,
            properties: {
              scannedAt: result.scannedAt,
            },
          },
        ],
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: result.scannedAt,
            endTimeUtc: result.scannedAt,
            properties: {
              riskLevel: result.riskLevel,
              riskScore: result.riskScore,
              verdict: result.verdict,
              scanId: result.id,
              reportUrl: result.id ? `https://skillaudit.vercel.app/report/${result.id}` : undefined,
            },
          },
        ],
        properties: {
          riskLevel: result.riskLevel,
          riskScore: result.riskScore,
          summary: result.summary,
          capabilityStats: result.capabilityStats,
        },
      },
    ],
  };

  return sarif;
}

module.exports = { toSarif };
