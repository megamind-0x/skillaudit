/**
 * CycloneDX SBOM (Software Bill of Materials) v1.5 output
 * 
 * Generates a CycloneDX BOM from SkillAudit scan results — listing
 * detected capabilities, external references, security vulnerabilities,
 * and component metadata for AI agent skills.
 * 
 * CycloneDX is the OWASP standard for SBOMs, required by:
 * - US Executive Order 14028 (government software supply chain)
 * - EU Cyber Resilience Act
 * - NIST SSDF (Secure Software Development Framework)
 * 
 * Spec: https://cyclonedx.org/docs/1.5/json/
 */

const crypto = require('crypto');

// Map SkillAudit severity to CycloneDX vulnerability rating
const SEVERITY_MAP = {
  critical: { score: 9.5, severity: 'critical', method: 'other' },
  high: { score: 7.5, severity: 'high', method: 'other' },
  medium: { score: 4.5, severity: 'medium', method: 'other' },
  low: { score: 2.0, severity: 'low', method: 'other' },
  info: { score: 0.0, severity: 'info', method: 'other' },
};

// Map SkillAudit categories to CWE IDs
const CATEGORY_CWE = {
  credential_theft: { id: 522, name: 'Insufficiently Protected Credentials' },
  data_exfiltration: { id: 200, name: 'Exposure of Sensitive Information' },
  prompt_injection: { id: 74, name: 'Improper Neutralization of Special Elements in Output' },
  code_execution: { id: 94, name: 'Improper Control of Generation of Code' },
  network: { id: 918, name: 'Server-Side Request Forgery' },
  filesystem: { id: 22, name: 'Improper Limitation of a Pathname' },
  obfuscation: { id: 506, name: 'Embedded Malicious Code' },
  privilege_escalation: { id: 269, name: 'Improper Privilege Management' },
  crypto_theft: { id: 522, name: 'Insufficiently Protected Credentials' },
  agent_manipulation: { id: 74, name: 'Improper Neutralization of Special Elements in Output' },
  evasion: { id: 506, name: 'Embedded Malicious Code' },
  supply_chain: { id: 829, name: 'Inclusion of Functionality from Untrusted Control Sphere' },
  reconnaissance: { id: 200, name: 'Exposure of Sensitive Information' },
  persistence: { id: 506, name: 'Embedded Malicious Code' },
  url_reputation: { id: 601, name: 'URL Redirection to Untrusted Site' },
  intent_analysis: { id: 74, name: 'Improper Neutralization of Special Elements in Output' },
  structural: { id: 200, name: 'Exposure of Sensitive Information' },
  denial_of_service: { id: 400, name: 'Uncontrolled Resource Consumption' },
  secret_detection: { id: 798, name: 'Use of Hard-coded Credentials' },
};

function toSbom(scanResult, options = {}) {
  const source = scanResult.source || scanResult.url || 'unknown';
  const timestamp = scanResult.scannedAt || new Date().toISOString();
  const serialNumber = `urn:uuid:${crypto.randomUUID ? crypto.randomUUID() : generateUUID()}`;

  // Build the main component (the scanned skill)
  let componentName = 'unknown-skill';
  let componentVersion = '0.0.0';
  let componentPurl = null;
  let externalRefs = [];

  // Extract component info from source URL
  try {
    const url = new URL(source);
    componentName = url.pathname.split('/').filter(Boolean).pop() || url.hostname;
    
    // Build PURL (Package URL) based on source type
    if (source.includes('npm:')) {
      const pkg = source.replace(/^npm:/, '').split('/')[0];
      componentPurl = `pkg:npm/${encodeURIComponent(pkg)}`;
    } else if (source.includes('pypi:')) {
      const pkg = source.replace(/^pypi:/, '').split('/')[0];
      componentPurl = `pkg:pypi/${encodeURIComponent(pkg)}`;
    } else if (source.startsWith('http')) {
      externalRefs.push({ type: 'distribution', url: source });
    }
  } catch {
    componentName = source.split('/').pop() || source;
  }

  // Build capabilities as services/features
  const capabilities = scanResult.capabilities || {};
  const services = Object.entries(capabilities).map(([name, cap]) => ({
    'bom-ref': `cap-${name}`,
    name: name,
    description: cap.description || `Detected capability: ${name}`,
    endpoints: cap.evidence ? cap.evidence.map(e => e.match || '').filter(Boolean).slice(0, 5) : [],
  }));

  // Build vulnerabilities from findings
  const vulnerabilities = (scanResult.findings || [])
    .filter(f => !f.suppressed)
    .map((f, idx) => {
      const sevInfo = SEVERITY_MAP[f.severity] || SEVERITY_MAP.medium;
      const cwe = CATEGORY_CWE[f.category];
      
      return {
        'bom-ref': `vuln-${idx}`,
        id: f.ruleId,
        source: {
          name: 'SkillAudit',
          url: 'https://skillaudit.vercel.app',
        },
        ratings: [{
          score: sevInfo.score,
          severity: sevInfo.severity,
          method: 'other',
          vector: `skillaudit/${f.ruleId}/${f.severity}`,
        }],
        cwes: cwe ? [cwe.id] : [],
        description: f.description,
        detail: f.remediation || undefined,
        recommendation: f.remediation || undefined,
        advisories: scanResult.id ? [{
          title: `SkillAudit Report ${scanResult.id}`,
          url: `https://skillaudit.vercel.app/report/${scanResult.id}`,
        }] : [],
        affects: [{
          ref: 'main-component',
          versions: [{ version: componentVersion, status: 'affected' }],
        }],
        properties: [
          { name: 'skillaudit:line', value: String(f.line || 0) },
          { name: 'skillaudit:category', value: f.category || 'unknown' },
          { name: 'skillaudit:context', value: f.context || 'unknown' },
          ...(f.match ? [{ name: 'skillaudit:match', value: f.match.substring(0, 200) }] : []),
        ],
      };
    });

  // Build threat chains as compositions
  const compositions = [];
  if (scanResult.threatChains && scanResult.threatChains.length > 0) {
    compositions.push({
      aggregate: 'incomplete',
      assemblies: scanResult.threatChains.map(tc => tc.name),
    });
  }

  // Assemble CycloneDX BOM
  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber,
    version: 1,
    metadata: {
      timestamp,
      tools: {
        components: [{
          type: 'application',
          name: 'SkillAudit',
          version: scanResult.version || '1.0.0',
          description: 'Security scanner for AI agent skills — structural analysis, capability detection, threat chain analysis',
          externalReferences: [
            { type: 'website', url: 'https://skillaudit.vercel.app' },
            { type: 'vcs', url: 'https://github.com/megamind-0x/skillaudit' },
          ],
        }],
      },
      component: {
        'bom-ref': 'main-component',
        type: 'data',
        name: componentName,
        version: componentVersion,
        description: `AI agent skill scanned by SkillAudit`,
        hashes: scanResult.contentHash ? [{
          alg: 'SHA-256',
          content: scanResult.contentHash,
        }] : [],
        externalReferences: externalRefs.length > 0 ? externalRefs : undefined,
        purl: componentPurl || undefined,
        properties: [
          { name: 'skillaudit:riskLevel', value: scanResult.riskLevel || 'unknown' },
          { name: 'skillaudit:riskScore', value: String(scanResult.riskScore || 0) },
          { name: 'skillaudit:verdict', value: scanResult.verdict || '' },
          ...(scanResult.id ? [{ name: 'skillaudit:scanId', value: scanResult.id }] : []),
          ...(scanResult.capabilityStats ? [
            { name: 'skillaudit:capabilityCount', value: String(scanResult.capabilityStats.totalCapabilities || 0) },
            { name: 'skillaudit:threatChainCount', value: String(scanResult.capabilityStats.threatChains || 0) },
          ] : []),
        ],
      },
      properties: [
        { name: 'skillaudit:engineVersion', value: scanResult.version || '1.0.0' },
        { name: 'skillaudit:scanTimestamp', value: timestamp },
      ],
    },
    components: [],
    services: services.length > 0 ? services : undefined,
    vulnerabilities: vulnerabilities.length > 0 ? vulnerabilities : undefined,
    compositions: compositions.length > 0 ? compositions : undefined,
  };

  // Add permission requirements as properties if available
  if (scanResult.permissions) {
    const perms = Object.entries(scanResult.permissions)
      .filter(([, v]) => v === true || (Array.isArray(v) && v.length > 0));
    if (perms.length > 0) {
      bom.metadata.properties.push({
        name: 'skillaudit:requiredPermissions',
        value: perms.map(([k]) => k).join(', '),
      });
    }
  }

  return bom;
}

// Fallback UUID generator for older Node versions
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
  });
}

module.exports = { toSbom };
