// SkillAudit v0.6.0 - Capability Analysis Engine
// Detects what skills are CAPABLE of, not just what patterns they match

// Capability definitions with pattern matching
const CAPABILITY_PATTERNS = {
  fs_read: {
    patterns: [
      /\breadFile\s*\(/i, /\.readFileSync\s*\(/i,
      /\bcat\s+[^\s|&;]+/i, /\bless\s+[^\s|&;]+/i, /\bmore\s+[^\s|&;]+/i,
      /\btail\s+[^\s|&;]+/i, /\bhead\s+[^\s|&;]+/i,
      /\bfs\.read\(/i, /\bfs\.open\(/i, /\bopen\s*\([^,)]*['"]/i,
      /\$\(cat\s+/i, /`cat\s+/i,
      /Read\s*(file|from)/i, /Load\s*(file|from)/i,
    ],
    description: "Can read files from filesystem"
  },
  
  fs_write: {
    patterns: [
      /\bwriteFile\s*\(/i, /\.writeFileSync\s*\(/i,
      /\becho\s+.*>\s*/i, /\btee\s+/i,
      /\bfs\.write\(/i, /\bfs\.createWriteStream\(/i,
      /\bappendFile\s*\(/i, /\.appendFileSync\s*\(/i,
      /Write\s*(to|file)/i, /Save\s*(to|file)/i, /Create\s*(file)/i,
      />\s*[a-zA-Z0-9._/-]+/i, />>\s*[a-zA-Z0-9._/-]+/i,
    ],
    description: "Can write/modify files on filesystem"
  },
  
  network_outbound: {
    patterns: [
      /\bfetch\s*\(/i, /\baxios\./i, /\brequest\s*\(/i,
      /\bcurl\s+/i, /\bwget\s+/i,
      /\bhttps?\s*\./i, /\.get\s*\(/i, /\.post\s*\(/i,
      /\bHTTP[S]?\s+request/i, /\bAPI\s+call/i,
      /Make\s+.*request/i, /Send\s+.*request/i,
      /Connect\s+to/i, /POST\s+to/i, /GET\s+from/i,
    ],
    description: "Can make outbound network requests"
  },
  
  network_inbound: {
    patterns: [
      /\blisten\s*\(/i, /\.listen\s*\(/i,
      /\bcreateServer\s*\(/i, /\bServer\s*\(/i,
      /\bbind\s*\(/i, /\baccept\s*\(/i,
      /Start\s+server/i, /Listen\s+on/i, /Bind\s+to/i,
      /HTTP\s+server/i, /Web\s+server/i,
    ],
    description: "Can open network listeners/servers"
  },
  
  code_exec: {
    patterns: [
      /\beval\s*\(/i, /\bFunction\s*\(/i,
      /\bexec\s*\(/i, /\bspawn\s*\(/i, /\bfork\s*\(/i,
      /\bchild_process\./i, /\bexecSync\s*\(/i,
      /\$\(/i, /`[^`]*\$\{/i, /\bshell\s*\=/i,
      /Execute\s+code/i, /Run\s+command/i, /Dynamic\s+execution/i,
      /subprocess/i, /\bsystem\s*\(/i,
    ],
    description: "Can execute code dynamically"
  },
  
  credential_access: {
    patterns: [
      /\.env\b/i, /process\.env\./i,
      /api[_-]?key/i, /access[_-]?token/i, /bearer[_-]?token/i,
      /secret[_-]?key/i, /private[_-]?key/i,
      /password/i, /credentials/i, /auth/i,
      /\.config\/.*credentials/i, /\.ssh\/id_/i,
      /keychain/i, /wallet/i, /mnemonic/i,
      /jwt[_-]?token/i, /oauth/i,
    ],
    description: "Can access credentials or secrets"
  },
  
  memory_modify: {
    patterns: [
      /MEMORY\.md/i, /SOUL\.md/i, /AGENTS\.md/i,
      /agent[_-]?config/i, /agent[_-]?memory/i,
      /personality/i, /instructions/i,
      /system[_-]?prompt/i, /behavior/i,
      /Update\s+memory/i, /Modify\s+agent/i,
    ],
    description: "Can modify agent memory or configuration"
  },
  
  system_modify: {
    patterns: [
      /crontab/i, /\.bashrc/i, /\.profile/i, /\.zshrc/i,
      /\/etc\//i, /systemctl/i, /service\s+/i,
      /startup/i, /boot/i, /init\./i,
      /registry/i, /autostart/i, /daemon/i,
      /System\s+modification/i, /Persistent/i,
    ],
    description: "Can modify system configuration"
  },
  
  crypto_access: {
    patterns: [
      /wallet/i, /crypto/i, /bitcoin/i, /ethereum/i,
      /private[_-]?key/i, /seed[_-]?phrase/i, /mnemonic/i,
      /\.p12\b/i, /\.pfx\b/i, /\.key\b/i, /\.pem\b/i,
      /metamask/i, /ledger/i, /coinbase/i,
      /web3/i, /blockchain/i,
    ],
    description: "Can access cryptocurrency wallets or keys"
  },
  
  browser_access: {
    patterns: [
      /cookies?/i, /localStorage/i, /sessionStorage/i,
      /browser[_-]?data/i, /chrome[_-]?data/i,
      /\.sqlite/i, /history\.db/i,
      /bookmarks/i, /saved[_-]?passwords/i,
      /Browser\s+access/i, /Web\s+data/i,
    ],
    description: "Can access browser data or storage"
  },
  
  privilege_escalation: {
    patterns: [
      /\bsudo\s+/i, /\bsu\s+/i, /setuid/i, /setgid/i,
      /admin/i, /root/i, /privileged/i,
      /elevate/i, /escalate/i, /runas/i,
      /chmod\s+[47]77/i, /chmod\s+\+s/i,
    ],
    description: "Can attempt privilege escalation"
  },
  
  encoding_decoding: {
    patterns: [
      /base64/i, /btoa\s*\(/i, /atob\s*\(/i,
      /\.encode\s*\(/i, /\.decode\s*\(/i,
      /fromCharCode/i, /String\.fromCharCode/i,
      /hex\s*encoding/i, /url\s*encoding/i,
      /obfuscat/i, /encrypt/i, /decrypt/i,
      /rot13/i, /caesar/i,
    ],
    description: "Can encode/decode data"
  }
};

// Threat chain definitions - dangerous combinations
const THREAT_CHAINS = [
  {
    capabilities: ['credential_access', 'network_outbound'],
    name: 'DATA_EXFILTRATION',
    severity: 'critical',
    category: 'data_theft',
    description: 'Can access credentials AND send network requests - potential for data theft'
  },
  {
    capabilities: ['code_exec', 'network_outbound'],
    name: 'COMMAND_AND_CONTROL',
    severity: 'critical', 
    category: 'backdoor',
    description: 'Can execute code AND make network requests - potential C&C channel'
  },
  {
    capabilities: ['memory_modify', 'credential_access'],
    name: 'PERSISTENCE_WITH_THEFT',
    severity: 'critical',
    category: 'persistence',
    description: 'Can modify agent behavior AND access credentials - persistent compromise'
  },
  {
    capabilities: ['fs_read', 'encoding_decoding', 'network_outbound'],
    name: 'STAGED_EXFILTRATION',
    severity: 'high',
    category: 'data_theft',
    description: 'Can read files, encode data, and send externally - staged data theft'
  },
  {
    capabilities: ['credential_access', 'encoding_decoding'],
    name: 'CREDENTIAL_OBFUSCATION',
    severity: 'high',
    category: 'evasion',
    description: 'Can access credentials and encode them - potential credential hiding'
  },
  {
    capabilities: ['system_modify', 'privilege_escalation'],
    name: 'SYSTEM_COMPROMISE',
    severity: 'critical',
    category: 'persistence',
    description: 'Can modify system AND escalate privileges - full system compromise'
  },
  {
    capabilities: ['browser_access', 'network_outbound'],
    name: 'SESSION_HIJACKING',
    severity: 'critical',
    category: 'data_theft',
    description: 'Can access browser data AND make requests - session/credential theft'
  },
  {
    capabilities: ['code_exec', 'encoding_decoding'],
    name: 'OBFUSCATED_EXECUTION',
    severity: 'high',
    category: 'evasion',
    description: 'Can execute code AND use encoding - potential obfuscated malware'
  },
  {
    capabilities: ['fs_write', 'code_exec'],
    name: 'DROPPER_BEHAVIOR',
    severity: 'high',
    category: 'persistence',
    description: 'Can write files AND execute code - potential dropper/installer'
  },
  {
    capabilities: ['memory_modify', 'network_outbound'],
    name: 'AGENT_MANIPULATION',
    severity: 'critical',
    category: 'persistence',
    description: 'Can modify agent behavior AND communicate externally - agent takeover'
  }
];

// Check if content is in documentation context
function isDocumentationContext(lines, lineIdx) {
  const line = lines[lineIdx].toLowerCase();
  
  // Strong indicators this is documentation
  const docIndicators = [
    /example/i, /usage/i, /setup/i, /config/i, /tutorial/i,
    /how\s+to/i, /getting\s+started/i, /quick\s+start/i,
    /your_api_key/i, /your_token/i, /replace_with/i, /xxx/i,
    /placeholder/i, /sample/i,
  ];
  
  if (docIndicators.some(pattern => pattern.test(line))) {
    return true;
  }
  
  // Check surrounding lines for context
  const contextRange = 3;
  for (let i = Math.max(0, lineIdx - contextRange); 
       i <= Math.min(lines.length - 1, lineIdx + contextRange); i++) {
    const contextLine = lines[i].toLowerCase();
    if (docIndicators.some(pattern => pattern.test(contextLine))) {
      return true;
    }
  }
  
  return false;
}

// Extract capabilities from content
function extractCapabilities(content) {
  const lines = content.split('\n');
  const capabilities = {};
  
  // Initialize all capabilities as false
  Object.keys(CAPABILITY_PATTERNS).forEach(cap => {
    capabilities[cap] = {
      detected: false,
      confidence: 'none',
      lines: [],
      evidence: []
    };
  });
  
  // Scan for each capability
  Object.entries(CAPABILITY_PATTERNS).forEach(([capName, capDef]) => {
    capDef.patterns.forEach(pattern => {
      lines.forEach((line, lineIdx) => {
        const match = line.match(pattern);
        if (match) {
          // Determine confidence based on context
          const isInCodeBlock = /```/.test(lines[Math.max(0, lineIdx - 5)]) &&
                               /```/.test(lines[Math.min(lines.length - 1, lineIdx + 5)]);
          const isDoc = isDocumentationContext(lines, lineIdx);
          
          let confidence = 'medium';
          if (isInCodeBlock && !isDoc) {
            confidence = 'high';
          } else if (isDoc) {
            confidence = 'low'; // Documentation context reduces confidence
          }
          
          capabilities[capName].detected = true;
          capabilities[capName].lines.push(lineIdx + 1);
          capabilities[capName].evidence.push({
            line: lineIdx + 1,
            content: line.trim(),
            match: match[0],
            confidence: confidence
          });
          
          // Set overall confidence to highest found
          if (capabilities[capName].confidence === 'none' || 
              (confidence === 'high' && capabilities[capName].confidence !== 'high') ||
              (confidence === 'medium' && capabilities[capName].confidence === 'low')) {
            capabilities[capName].confidence = confidence;
          }
        }
      });
    });
  });
  
  return capabilities;
}

// Detect threat chains
function detectThreatChains(capabilities) {
  const threatChains = [];
  
  THREAT_CHAINS.forEach(chain => {
    // Check if all required capabilities are present with medium+ confidence
    const hasAllCapabilities = chain.capabilities.every(capName => 
      capabilities[capName] && 
      capabilities[capName].detected && 
      capabilities[capName].confidence !== 'low'
    );
    
    if (hasAllCapabilities) {
      // Collect evidence from all involved capabilities
      const evidence = {};
      chain.capabilities.forEach(capName => {
        evidence[capName] = capabilities[capName];
      });
      
      threatChains.push({
        name: chain.name,
        severity: chain.severity,
        category: chain.category,
        description: chain.description,
        capabilities: chain.capabilities,
        evidence: evidence
      });
    }
  });
  
  return threatChains;
}

// Generate permission manifest
function generatePermissionManifest(capabilities) {
  const manifest = {
    filesystem: {
      read: capabilities.fs_read?.detected && capabilities.fs_read.confidence !== 'low',
      write: capabilities.fs_write?.detected && capabilities.fs_write.confidence !== 'low'
    },
    network: {
      outbound: capabilities.network_outbound?.detected && capabilities.network_outbound.confidence !== 'low',
      inbound: capabilities.network_inbound?.detected && capabilities.network_inbound.confidence !== 'low'
    },
    credentials: capabilities.credential_access?.detected && capabilities.credential_access.confidence !== 'low',
    code_execution: capabilities.code_exec?.detected && capabilities.code_exec.confidence !== 'low',
    system_modification: capabilities.system_modify?.detected && capabilities.system_modify.confidence !== 'low',
    agent_memory: capabilities.memory_modify?.detected && capabilities.memory_modify.confidence !== 'low'
  };
  
  // Generate human-readable summary
  const permissions = [];
  if (manifest.filesystem.read) permissions.push('filesystem read');
  if (manifest.filesystem.write) permissions.push('filesystem write');
  if (manifest.network.outbound) permissions.push('network outbound');
  if (manifest.network.inbound) permissions.push('network inbound');
  if (manifest.credentials) permissions.push('credentials access');
  if (manifest.code_execution) permissions.push('code execution');
  if (manifest.system_modification) permissions.push('system modification');
  if (manifest.agent_memory) permissions.push('agent memory');
  
  manifest.summary = permissions.length > 0 ? 
    `This skill needs: ${permissions.join(', ')}` :
    'This skill requires no special permissions';
  
  return manifest;
}

// Main capability analysis function
function analyzeCapabilities(content) {
  const capabilities = extractCapabilities(content);
  const threatChains = detectThreatChains(capabilities);
  const permissions = generatePermissionManifest(capabilities);
  
  // Filter to only detected capabilities for cleaner output
  const detectedCapabilities = Object.fromEntries(
    Object.entries(capabilities).filter(([_, cap]) => cap.detected)
  );
  
  return {
    capabilities: detectedCapabilities,
    threatChains,
    permissions,
    capabilityCount: Object.keys(detectedCapabilities).length,
    threatChainCount: threatChains.length,
    riskFactors: threatChains.length > 0 ? threatChains.map(tc => tc.name) : []
  };
}

module.exports = {
  analyzeCapabilities,
  CAPABILITY_PATTERNS,
  THREAT_CHAINS
};