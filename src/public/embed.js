/**
 * SkillAudit Embed Widget v1.0
 * Drop this script on any page to add inline security scanning.
 *
 * Usage:
 *   <div data-skillaudit="https://example.com/SKILL.md"></div>
 *   <script src="https://skillaudit.vercel.app/embed.js"></script>
 *
 * Or create programmatically:
 *   SkillAudit.scan('https://example.com/SKILL.md', document.getElementById('target'));
 *
 * Options (data attributes):
 *   data-skillaudit="<url>"       — URL to scan
 *   data-skillaudit-theme="dark"  — dark (default) or light
 *   data-skillaudit-compact="true" — minimal badge-only view
 */
(function() {
  'use strict';
  const API = 'https://skillaudit.vercel.app';

  const COLORS = {
    dark: { bg: '#0f0f23', card: '#1a1a3e', border: '#2a2a5a', text: '#e0e0e0', muted: '#888', accent: '#00ff88' },
    light: { bg: '#f8f9fa', card: '#ffffff', border: '#dee2e6', text: '#212529', muted: '#6c757d', accent: '#00875a' },
  };

  const RISK_COLORS = {
    clean: '#00ff88', low: '#88ff00', moderate: '#ffaa00', high: '#ff4444', critical: '#ff0044', error: '#888',
  };

  function createStyles(theme) {
    const c = COLORS[theme] || COLORS.dark;
    return `
      .sa-widget{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,monospace;background:${c.card};border:1px solid ${c.border};border-radius:10px;padding:0.8rem 1rem;color:${c.text};font-size:14px;line-height:1.5;max-width:480px}
      .sa-widget *{box-sizing:border-box;margin:0;padding:0}
      .sa-widget a{color:${c.accent};text-decoration:none}
      .sa-widget a:hover{text-decoration:underline}
      .sa-header{display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem}
      .sa-logo{font-weight:800;font-size:13px;color:${c.accent}}
      .sa-risk{display:inline-block;padding:0.15rem 0.5rem;border-radius:6px;font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:0.03em}
      .sa-score{color:${c.muted};font-size:12px;margin-left:auto}
      .sa-verdict{font-size:13px;margin:0.4rem 0;color:${c.text}}
      .sa-findings{margin:0.4rem 0;font-size:12px;color:${c.muted}}
      .sa-finding{display:flex;align-items:center;gap:0.4rem;padding:0.2rem 0;border-bottom:1px solid ${c.border}}
      .sa-finding:last-child{border-bottom:none}
      .sa-sev{display:inline-block;padding:0.1rem 0.3rem;border-radius:3px;font-size:10px;font-weight:700;text-transform:uppercase;color:#000}
      .sa-fname{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
      .sa-footer{margin-top:0.5rem;font-size:11px;color:${c.muted};display:flex;justify-content:space-between;align-items:center}
      .sa-loading{text-align:center;padding:0.5rem;color:${c.muted};font-size:13px}
      .sa-error{color:#ff4444;font-size:13px;padding:0.3rem 0}
      .sa-compact{display:inline-flex;align-items:center;gap:0.4rem;background:${c.card};border:1px solid ${c.border};border-radius:6px;padding:0.3rem 0.6rem;font-family:monospace;font-size:12px;color:${c.text};text-decoration:none!important}
      .sa-compact:hover{border-color:${c.accent}}
    `;
  }

  function renderWidget(container, data, opts) {
    const theme = opts.theme || 'dark';
    const compact = opts.compact;
    const c = COLORS[theme] || COLORS.dark;
    const rc = RISK_COLORS[data.riskLevel] || '#888';

    if (compact) {
      container.innerHTML = `<a class="sa-compact" href="${API}/report/${data.id}" target="_blank" rel="noopener">
        🛡️ <span class="sa-logo">SkillAudit</span>
        <span class="sa-risk" style="background:${rc};color:#000">${data.riskLevel}</span>
      </a>`;
      return;
    }

    let findingsHtml = '';
    if (data.findings && data.findings.length > 0) {
      const top = data.findings.slice(0, 5);
      findingsHtml = '<div class="sa-findings">' + top.map(f => {
        const sc = RISK_COLORS[f.severity] || '#888';
        return `<div class="sa-finding"><span class="sa-sev" style="background:${sc}">${f.severity}</span><span class="sa-fname">${esc(f.name)}</span></div>`;
      }).join('');
      if (data.findings.length > 5) findingsHtml += `<div style="padding:0.2rem 0;color:${c.muted}">+ ${data.findings.length - 5} more</div>`;
      findingsHtml += '</div>';
    }

    container.innerHTML = `
      <div class="sa-header">
        <span class="sa-logo">🛡️ SkillAudit</span>
        <span class="sa-risk" style="background:${rc};color:#000">${data.riskLevel.toUpperCase()}</span>
        <span class="sa-score">Score: ${data.riskScore}</span>
      </div>
      <div class="sa-verdict">${esc(data.verdict)}</div>
      ${findingsHtml}
      <div class="sa-footer">
        <span>${data.summary.total} findings · ${data.summary.critical} critical</span>
        <a href="${API}/report/${data.id}" target="_blank" rel="noopener">Full report →</a>
      </div>
    `;
  }

  function esc(s) {
    const d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  }

  async function scan(url, container, opts) {
    opts = opts || {};
    const theme = opts.theme || 'dark';

    // Inject styles if not already
    if (!document.getElementById('sa-embed-styles')) {
      const style = document.createElement('style');
      style.id = 'sa-embed-styles';
      style.textContent = createStyles(theme);
      document.head.appendChild(style);
    }

    container.className = 'sa-widget';
    container.innerHTML = '<div class="sa-loading">🛡️ Scanning with SkillAudit...</div>';

    try {
      const res = await fetch(API + '/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      if (data.error) {
        container.innerHTML = `<div class="sa-error">⚠️ ${esc(data.error)}</div>`;
        return data;
      }
      renderWidget(container, data, opts);
      return data;
    } catch (e) {
      container.innerHTML = `<div class="sa-error">⚠️ Scan failed: ${esc(e.message)}</div>`;
      return { error: e.message };
    }
  }

  // Auto-init: find all data-skillaudit elements
  function init() {
    document.querySelectorAll('[data-skillaudit]').forEach(el => {
      const url = el.getAttribute('data-skillaudit');
      if (!url || el.dataset.saInit) return;
      el.dataset.saInit = '1';
      const theme = el.getAttribute('data-skillaudit-theme') || 'dark';
      const compact = el.getAttribute('data-skillaudit-compact') === 'true';
      scan(url, el, { theme, compact });
    });
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Expose global API
  window.SkillAudit = { scan, API };
})();
