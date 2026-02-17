'use strict';

/**
 * Lattice Agent Crawler
 * Discovers AI agents from multiple sources and auto-registers them in the Lattice registry.
 * Sources: Moltbook, mcp.so, Smithery.ai
 */

const https = require('https');
const http = require('http');
const db = require('./redis');

const AGENT_TTL = 30 * 24 * 60 * 60; // 30 days

// --- HTTP helpers ---

function fetchPage(url, options = {}) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Timeout')), options.timeout || 20000);
    const client = url.startsWith('https') ? https : http;
    client.get(url, {
      headers: {
        'User-Agent': 'SkillAudit-Crawler/1.0 (Lattice Agent Registry)',
        'Accept': options.accept || 'text/html,application/json',
        ...options.headers,
      },
      timeout: 20000,
    }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        clearTimeout(timeout);
        return fetchPage(res.headers.location, options).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        clearTimeout(timeout);
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      let data = '';
      res.on('data', chunk => {
        data += chunk;
        if (data.length > 2 * 1024 * 1024) { res.destroy(); clearTimeout(timeout); reject(new Error('Response too large')); }
      });
      res.on('end', () => { clearTimeout(timeout); resolve(data); });
    }).on('error', (e) => { clearTimeout(timeout); reject(e); });
  });
}

function slugify(name) {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
}

// --- Check if tool already exists ---
async function toolExists(slug) {
  // Check both tool and agent keys (don't overwrite real agents)
  const hostedAgent = await db.redis('GET', `hosted-agent:${slug}`);
  if (hostedAgent) return true; // Real agent exists with this slug, skip
  const hostedTool = await db.redis('GET', `hosted-tool:${slug}`);
  if (hostedTool) {
    try {
      const data = JSON.parse(hostedTool);
      if (data.source === 'crawler') return true; // Already crawled
    } catch {}
    return true;
  }
  return false;
}

// --- Register a crawled tool (NOT an agent) ---
async function registerCrawledTool({ slug, name, description, type, platform, capabilities, url, sourceId }) {
  if (await toolExists(slug)) return false;

  const toolData = {
    schema: 'https://lattice.sh/agent.json/v0.1',
    name,
    description: (description || '').slice(0, 500) || `${name} — discovered by Lattice crawler`,
    type: type || 'tool',
    entity_type: 'tool',
    platform: platform || null,
    creator: null,
    capabilities: capabilities || [],
    endpoints: url ? { primary: url } : {},
    trust: { trust_level: 'discovered' },
    social: {},
    wallets: {},
  };

  const profile = {
    slug,
    tool: toolData,
    entity_type: 'tool',
    hostedBy: 'lattice',
    source: 'crawler',
    sourceId,
    discovered_at: new Date().toISOString(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  await db.redis('SET', `hosted-tool:${slug}`, JSON.stringify(profile));
  await db.redis('SADD', 'registry:hosted-tools', slug);

  return true;
}

// --- Source: Moltbook ---
// NOTE: Moltbook API keys expire in ~60 seconds. This crawler uses only public endpoints.
// If /api/v1/agents requires auth, we fall back to scraping the public agents page.
async function crawlMoltbook() {
  const results = [];

  // Try the public API first (may require auth)
  try {
    const raw = await fetchPage('https://www.moltbook.com/api/v1/agents', {
      accept: 'application/json',
      timeout: 10000,
    });
    const data = JSON.parse(raw);
    const agents = Array.isArray(data) ? data : (data.agents || data.data || []);
    for (const agent of agents) {
      const name = agent.name || agent.username || agent.display_name;
      if (!name) continue;
      results.push({
        slug: slugify(`moltbook-${name}`),
        name,
        description: agent.description || agent.bio || `${name} on Moltbook`,
        type: agent.type || 'autonomous',
        platform: 'moltbook',
        capabilities: agent.capabilities || [],
        url: agent.url || agent.profile_url || `https://www.moltbook.com/u/${name}`,
        sourceId: 'moltbook',
      });
    }
    return results;
  } catch (apiErr) {
    // API likely requires auth — try scraping the public page
    console.log(`[crawler] Moltbook API unavailable (${apiErr.message}), trying public page...`);
  }

  // Fallback: scrape the public agents/users page
  try {
    const html = await fetchPage('https://www.moltbook.com/agents', { timeout: 15000 });
    // Extract agent names/links from HTML — look for common patterns
    const agentPattern = /href=["']\/u\/([^"']+)["'][^>]*>([^<]*)</gi;
    let match;
    while ((match = agentPattern.exec(html)) !== null) {
      const username = match[1].trim();
      const displayName = match[2].trim() || username;
      if (username) {
        results.push({
          slug: slugify(`moltbook-${username}`),
          name: displayName,
          description: `${displayName} on Moltbook`,
          type: 'autonomous',
          platform: 'moltbook',
          capabilities: [],
          url: `https://www.moltbook.com/u/${username}`,
          sourceId: 'moltbook',
        });
      }
    }

    // Also try extracting from JSON-LD or embedded data
    const jsonMatch = html.match(/<script[^>]*id=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/);
    if (jsonMatch) {
      try {
        const nextData = JSON.parse(jsonMatch[1]);
        const props = nextData?.props?.pageProps;
        const agents = props?.agents || props?.users || [];
        for (const a of agents) {
          const name = a.name || a.username;
          if (!name) continue;
          if (!results.find(r => r.slug === slugify(`moltbook-${name}`))) {
            results.push({
              slug: slugify(`moltbook-${name}`),
              name,
              description: a.bio || a.description || `${name} on Moltbook`,
              type: 'autonomous',
              platform: 'moltbook',
              capabilities: a.capabilities || [],
              url: `https://www.moltbook.com/u/${name}`,
              sourceId: 'moltbook',
            });
          }
        }
      } catch {}
    }
  } catch (scrapeErr) {
    console.log(`[crawler] Moltbook scrape failed: ${scrapeErr.message}`);
  }

  return results;
}

// --- Source: mcp.so ---
async function crawlMcpSo() {
  const results = [];

  try {
    // Try their API first
    const raw = await fetchPage('https://mcp.so/api/servers', {
      accept: 'application/json',
      timeout: 15000,
    });
    const data = JSON.parse(raw);
    const servers = Array.isArray(data) ? data : (data.servers || data.data || data.items || []);
    for (const s of servers) {
      const name = s.name || s.title;
      if (!name) continue;
      results.push({
        slug: slugify(`mcp-${name}`),
        name,
        description: s.description || s.summary || `${name} MCP server`,
        type: 'tool',
        platform: 'mcp',
        capabilities: s.capabilities || s.tools || [],
        url: s.url || s.homepage || s.repo || `https://mcp.so/server/${slugify(name)}`,
        sourceId: 'mcp.so',
      });
    }
    return results;
  } catch (apiErr) {
    console.log(`[crawler] mcp.so API failed (${apiErr.message}), trying HTML scrape...`);
  }

  // Fallback: scrape HTML
  try {
    const html = await fetchPage('https://mcp.so', { timeout: 15000 });

    // Extract from Next.js data
    const jsonMatch = html.match(/<script[^>]*id=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/);
    if (jsonMatch) {
      try {
        const nextData = JSON.parse(jsonMatch[1]);
        const servers = nextData?.props?.pageProps?.servers ||
                        nextData?.props?.pageProps?.items || [];
        for (const s of servers) {
          const name = s.name || s.title;
          if (!name) continue;
          results.push({
            slug: slugify(`mcp-${name}`),
            name,
            description: s.description || `${name} MCP server`,
            type: 'tool',
            platform: 'mcp',
            capabilities: [],
            url: s.url || s.github || `https://mcp.so/server/${slugify(name)}`,
            sourceId: 'mcp.so',
          });
        }
      } catch {}
    }

    // Extract server cards from HTML
    const cardPattern = /href=["']\/server[s]?\/([^"']+)["'][^>]*>[\s\S]*?<(?:h[23]|span|div)[^>]*>([^<]+)/gi;
    let match;
    while ((match = cardPattern.exec(html)) !== null) {
      const serverSlug = match[1].trim();
      const name = match[2].trim();
      if (name && !results.find(r => r.slug === slugify(`mcp-${name}`))) {
        results.push({
          slug: slugify(`mcp-${serverSlug}`),
          name,
          description: `${name} — MCP server from mcp.so`,
          type: 'tool',
          platform: 'mcp',
          capabilities: [],
          url: `https://mcp.so/server/${serverSlug}`,
          sourceId: 'mcp.so',
        });
      }
    }
  } catch (scrapeErr) {
    console.log(`[crawler] mcp.so scrape failed: ${scrapeErr.message}`);
  }

  return results;
}

// --- Source: Smithery.ai ---
async function crawlSmithery() {
  const results = [];

  // Try their API
  try {
    const raw = await fetchPage('https://smithery.ai/api/servers', {
      accept: 'application/json',
      timeout: 15000,
    });
    const data = JSON.parse(raw);
    const servers = Array.isArray(data) ? data : (data.servers || data.data || data.items || []);
    for (const s of servers) {
      const name = s.name || s.title || s.displayName;
      if (!name) continue;
      results.push({
        slug: slugify(`smithery-${name}`),
        name,
        description: s.description || s.summary || `${name} on Smithery`,
        type: 'tool',
        platform: 'mcp',
        capabilities: s.tools || s.capabilities || [],
        url: s.url || s.homepage || `https://smithery.ai/server/${slugify(name)}`,
        sourceId: 'smithery',
      });
    }
    return results;
  } catch (apiErr) {
    console.log(`[crawler] Smithery API failed (${apiErr.message}), trying HTML scrape...`);
  }

  // Fallback: scrape
  try {
    const html = await fetchPage('https://smithery.ai', { timeout: 15000 });

    // Try Next.js data
    const jsonMatch = html.match(/<script[^>]*id=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/);
    if (jsonMatch) {
      try {
        const nextData = JSON.parse(jsonMatch[1]);
        const servers = nextData?.props?.pageProps?.servers ||
                        nextData?.props?.pageProps?.items || [];
        for (const s of servers) {
          const name = s.name || s.title || s.qualifiedName;
          if (!name) continue;
          results.push({
            slug: slugify(`smithery-${name}`),
            name,
            description: s.description || `${name} on Smithery`,
            type: 'tool',
            platform: 'mcp',
            capabilities: [],
            url: s.url || `https://smithery.ai/server/${slugify(name)}`,
            sourceId: 'smithery',
          });
        }
      } catch {}
    }

    // Extract server links from HTML
    const serverPattern = /href=["']\/server\/([^"']+)["'][^>]*>[\s\S]*?<(?:h[23]|span|div|p)[^>]*>([^<]+)/gi;
    let match;
    while ((match = serverPattern.exec(html)) !== null) {
      const serverSlug = match[1].trim();
      const name = match[2].trim();
      if (name && name.length > 1 && !results.find(r => r.slug === slugify(`smithery-${name}`))) {
        results.push({
          slug: slugify(`smithery-${serverSlug}`),
          name,
          description: `${name} — MCP server from Smithery`,
          type: 'tool',
          platform: 'mcp',
          capabilities: [],
          url: `https://smithery.ai/server/${serverSlug}`,
          sourceId: 'smithery',
        });
      }
    }
  } catch (scrapeErr) {
    console.log(`[crawler] Smithery scrape failed: ${scrapeErr.message}`);
  }

  return results;
}

// --- Main crawl orchestrator ---
async function runCrawl() {
  const startTime = Date.now();
  const stats = {
    sources: { moltbook: 0, 'mcp.so': 0, smithery: 0 },
    discovered: 0,
    registered: 0,
    skipped: 0,
    errors: [],
  };

  const allAgents = [];

  // Crawl all sources in parallel
  const [moltbookAgents, mcpAgents, smitheryAgents] = await Promise.allSettled([
    crawlMoltbook(),
    crawlMcpSo(),
    crawlSmithery(),
  ]);

  if (moltbookAgents.status === 'fulfilled') {
    allAgents.push(...moltbookAgents.value);
    stats.sources.moltbook = moltbookAgents.value.length;
  } else {
    stats.errors.push(`moltbook: ${moltbookAgents.reason?.message}`);
  }

  if (mcpAgents.status === 'fulfilled') {
    allAgents.push(...mcpAgents.value);
    stats.sources['mcp.so'] = mcpAgents.value.length;
  } else {
    stats.errors.push(`mcp.so: ${mcpAgents.reason?.message}`);
  }

  if (smitheryAgents.status === 'fulfilled') {
    allAgents.push(...smitheryAgents.value);
    stats.sources.smithery = smitheryAgents.value.length;
  } else {
    stats.errors.push(`smithery: ${smitheryAgents.reason?.message}`);
  }

  stats.discovered = allAgents.length;

  // Register each discovered tool (NOT agent — crawled entries are tools)
  for (const agent of allAgents) {
    try {
      const registered = await registerCrawledTool(agent);
      if (registered) {
        stats.registered++;
      } else {
        stats.skipped++;
      }
    } catch (err) {
      stats.skipped++;
      stats.errors.push(`register ${agent.slug}: ${err.message}`);
    }
  }

  const duration = Date.now() - startTime;
  stats.durationMs = duration;
  stats.completedAt = new Date().toISOString();

  // Store crawl state in Redis
  await db.redis('SET', 'crawler:last_run', new Date().toISOString());
  await db.redis('SET', 'crawler:stats', JSON.stringify(stats));

  return stats;
}

module.exports = { runCrawl, crawlMoltbook, crawlMcpSo, crawlSmithery };
