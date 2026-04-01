/**
 * Non-operator HTTP routes: HTML service home, health, dev playground registry,
 * operator catalog JSON, and aggregate stats.
 */

const express = require('express');

/** @param {unknown} str */
function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Escape for double-quoted HTML attributes */
function escapeAttr(str) {
  return escapeHtml(str);
}

/** Bucket by first character of operator name: A–Z or # (digits, CJK, etc.) */
function operatorBucketLetter(name) {
  const c = String(name || '').charAt(0);
  const u = c.toUpperCase();
  if (u >= 'A' && u <= 'Z') return u;
  return '#';
}

/**
 * Register base routes
 * @param {object} app - Express app
 * @param {object} appService - Application service
 * @param {object} config - Config object
 */
function setupRoutes(app, appService, config) {
  const apiPrefix = config.apiPrefix || '/api';
  // Home: serve on `/` and `apiPrefix` (smoke tests, deep links, browser open root URL)
  const renderServiceHome = (req, res) => {
    const stats = appService.getStats();
    const operators = appService.getOperators();
    const packageInfo = require('../../package.json');

    // Copy-paste friendly URLs: avoids duplicating apiPrefix when OPERATORS_BASE_URL already includes it
    const publicRouteBase = config.getPublicRouteBaseUrl();
    const docsUrl = `${publicRouteBase}/docs`;
    const operatorsListUrl = `${publicRouteBase}/operators`;
    const versionSafe = escapeHtml(packageInfo.version);

    const AZ_LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ#'.split('');
    const sortedOps = [...operators].sort((a, b) =>
      String(a.name || '').localeCompare(String(b.name || ''), 'en', { sensitivity: 'base' })
    );
    const byLetter = sortedOps.reduce((acc, op) => {
      const L = operatorBucketLetter(op.name);
      if (!acc[L]) acc[L] = [];
      acc[L].push(op);
      return acc;
    }, /** @type {Record<string, typeof operators>} */ ({}));

    const lettersPresent = new Set(Object.keys(byLetter));
    const azNavHtml =
      operators.length === 0
        ? ''
        : `<div class="az-nav-shell">
            <nav class="az-nav" aria-label="Jump to operators by first letter of name">${AZ_LETTERS.map((L) => {
            const has = lettersPresent.has(L);
            const id = L === '#' ? 'az-other' : `az-${L}`;
            const label = L === '#' ? '#' : L;
            if (has) {
              return `<a class="az-pill" href="#${id}">${label}</a>`;
            }
            return `<span class="az-pill az-pill-disabled" aria-hidden="true">${label}</span>`;
          }).join('')}</nav>
          </div>`;

    const operatorsGroupedHtml =
      operators.length === 0
        ? '<p class="section-desc empty-hint">No operators registered.</p>'
        : AZ_LETTERS.filter((L) => byLetter[L] && byLetter[L].length > 0)
            .map((L) => {
              const id = L === '#' ? 'az-other' : `az-${L}`;
              const heading = L === '#' ? '# · Other' : L;
              const rows = byLetter[L]
                .map((op) => {
                  const defUrl = `${publicRouteBase}/operators/${op.category}/${op.name}/definition`;
                  const cat =
                    op.category && String(op.category).trim()
                      ? String(op.category).trim()
                      : 'Other';
                  return `
            <div class="operator-row">
                <span class="row-cat" title="Top-level category">${escapeHtml(cat)}</span>
                <div class="row-main">
                    <div class="row-title-line">
                        <span class="row-title">${escapeHtml(op.title)}</span>
                        <span class="row-id">${escapeHtml(op.name)}</span>
                    </div>
                    <p class="row-desc">${escapeHtml(op.description || '')}</p>
                </div>
                <span class="row-methods">${op.endpointCount} methods</span>
                <div class="row-actions">
                    <div class="copy-inline">
                        <code class="copy-inline-code">${escapeHtml(defUrl)}</code>
                        <button type="button" class="copy-btn copy-btn-sm" data-copy="${escapeAttr(defUrl)}">Copy</button>
                    </div>
                </div>
            </div>`;
                })
                .join('');
              return `
            <section class="letter-section" id="${id}">
                <h3 class="letter-heading">${escapeHtml(heading)}</h3>
                <div class="operator-rows">${rows}</div>
            </section>`;
            })
            .join('');

    const html = `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GeniSpace Custom Operators</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&family=Geist+Mono:wght@400;500&family=Noto+Sans+SC:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script>
(function(){
  try {
    var t = localStorage.getItem('gs_operators_service_theme');
    document.documentElement.classList.remove('light','dark');
    document.documentElement.classList.add(t === 'light' ? 'light' : 'dark');
  } catch (e) {
    document.documentElement.classList.add('dark');
  }
})();
    </script>
    <style>
        html.light {
            --g-bg: #f8fafc;
            --g-bg-raised: #ffffff;
            --g-bg-card: #ffffff;
            --g-bg-hover: #f1f5f9;
            --g-border: rgba(15, 23, 42, 0.08);
            --g-border-hover: rgba(15, 23, 42, 0.14);
            --g-text: #0f172a;
            --g-text-secondary: #475569;
            --g-text-muted: #64748b;
            --g-accent: #3b82f6;
            --g-accent-hover: #2563eb;
            --g-accent-dim: rgba(59, 130, 246, 0.12);
            --g-accent-glow: rgba(59, 130, 246, 0.2);
            --g-green: #059669;
            --g-red: #dc2626;
            --g-radius: 12px;
            --g-radius-sm: 8px;
            --g-mono: 'Geist Mono', 'Consolas', monospace;
        }
        html.dark {
            --g-bg: #0b0b0f;
            --g-bg-raised: #12121a;
            --g-bg-card: #16161f;
            --g-bg-hover: #1c1c28;
            --g-border: rgba(255, 255, 255, 0.06);
            --g-border-hover: rgba(255, 255, 255, 0.12);
            --g-text: #e8e8ec;
            --g-text-secondary: #9393a0;
            --g-text-muted: #5c5c6e;
            --g-accent: #3b82f6;
            --g-accent-hover: #2563eb;
            --g-accent-dim: rgba(59, 130, 246, 0.12);
            --g-accent-glow: rgba(59, 130, 246, 0.25);
            --g-green: #34d399;
            --g-red: #f87171;
            --g-radius: 12px;
            --g-radius-sm: 8px;
            --g-mono: 'Geist Mono', 'Consolas', monospace;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        html { scroll-behavior: smooth; }
        body {
            font-family: Inter, 'Noto Sans SC', system-ui, -apple-system, sans-serif;
            font-size: 15px;
            line-height: 1.65;
            color: var(--g-text);
            background: var(--g-bg);
            -webkit-font-smoothing: antialiased;
            min-height: 100vh;
        }
        .container { max-width: 1120px; margin: 0 auto; padding: 0 32px 80px; }
        .hero {
            position: relative;
            padding: 56px 0 40px;
            text-align: center;
            overflow: hidden;
        }
        .hero::before {
            content: '';
            position: absolute;
            top: -120px; left: 50%; transform: translateX(-50%);
            width: 560px; height: 560px;
            background: radial-gradient(circle, var(--g-accent-glow) 0%, transparent 70%);
            opacity: 0.45;
            pointer-events: none;
        }
        .hero-inner { position: relative; z-index: 1; }
        .hero-top {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 16px;
            flex-wrap: wrap;
            margin-bottom: 24px;
        }
        .hero-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 14px;
            border-radius: 100px;
            background: var(--g-accent-dim);
            border: 1px solid rgba(59, 130, 246, 0.22);
            color: var(--g-accent);
            font-size: 12px;
            font-weight: 500;
            letter-spacing: 0.04em;
            text-transform: uppercase;
        }
        .hero-badge::before {
            content: '';
            width: 6px; height: 6px;
            border-radius: 50%;
            background: var(--g-accent);
            box-shadow: 0 0 8px var(--g-accent);
        }
        .theme-toggle {
            font-family: inherit;
            font-size: 13px;
            font-weight: 500;
            padding: 8px 14px;
            border-radius: 100px;
            border: 1px solid var(--g-border);
            background: var(--g-bg-card);
            color: var(--g-text-secondary);
            cursor: pointer;
            transition: background 0.2s, border-color 0.2s, color 0.2s;
        }
        .theme-toggle:hover {
            background: var(--g-bg-hover);
            border-color: var(--g-border-hover);
            color: var(--g-text);
        }
        .hero-title {
            font-family: 'Space Grotesk', 'Noto Sans SC', sans-serif;
            font-size: clamp(1.85rem, 4vw, 2.75rem);
            font-weight: 700;
            letter-spacing: -0.03em;
            line-height: 1.12;
            margin-bottom: 14px;
            background: linear-gradient(135deg, var(--g-text) 0%, var(--g-text-secondary) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        html.light .hero-title {
            background: linear-gradient(135deg, #0f172a 0%, #475569 100%);
            -webkit-background-clip: text;
            background-clip: text;
        }
        .hero-sub {
            font-size: 1.02rem;
            color: var(--g-text-secondary);
            max-width: 560px;
            margin: 0 auto;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 40px;
        }
        .stat-card {
            background: var(--g-bg-card);
            border: 1px solid var(--g-border);
            border-radius: var(--g-radius);
            padding: 22px;
            text-align: center;
            transition: border-color 0.2s;
        }
        .stat-card:hover { border-color: var(--g-border-hover); }
        .stat-number {
            font-size: 1.85rem;
            font-weight: 700;
            color: var(--g-accent);
            font-variant-numeric: tabular-nums;
        }
        .stat-label {
            color: var(--g-text-muted);
            font-size: 0.88rem;
            margin-top: 6px;
        }
        .section {
            background: var(--g-bg-card);
            border: 1px solid var(--g-border);
            border-radius: var(--g-radius);
            padding: 28px 28px 32px;
            margin-bottom: 28px;
        }
        .section-title {
            font-family: 'Space Grotesk', 'Noto Sans SC', sans-serif;
            font-size: 1.45rem;
            font-weight: 600;
            letter-spacing: -0.02em;
            color: var(--g-text);
            margin-bottom: 8px;
        }
        .section-desc {
            color: var(--g-text-secondary);
            font-size: 0.92rem;
            margin-bottom: 28px;
            max-width: 640px;
        }
        .empty-hint { margin-bottom: 0; }
        /* Sticky wrapper: distinct from section fill; avoid --g-bg as shadow color (muddy halo) */
        .az-nav-shell {
            position: sticky;
            top: 0;
            z-index: 40;
            margin: 0 0 18px;
            padding: 10px 12px 12px;
            border-radius: var(--g-radius-sm);
            border: 1px solid var(--g-border);
            background: var(--g-bg-raised);
            isolation: isolate;
            box-shadow:
                0 1px 0 rgba(255, 255, 255, 0.04),
                0 12px 40px rgba(0, 0, 0, 0.35);
        }
        html.light .az-nav-shell {
            background: var(--g-bg-hover);
            box-shadow: 0 4px 20px rgba(15, 23, 42, 0.07);
        }
        .az-nav {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            align-items: center;
        }
        .az-pill {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 2rem;
            height: 2rem;
            padding: 0 8px;
            border-radius: 8px;
            font-size: 0.8rem;
            font-weight: 600;
            font-family: var(--g-mono);
            text-decoration: none;
            color: var(--g-accent);
            border: 1px solid var(--g-border);
            background: var(--g-bg-raised);
            transition: background 0.15s, border-color 0.15s, color 0.15s;
        }
        .az-pill:hover {
            background: var(--g-accent-dim);
            border-color: rgba(59, 130, 246, 0.35);
        }
        .az-pill-disabled {
            opacity: 0.28;
            cursor: default;
            pointer-events: none;
            color: var(--g-text-muted);
        }
        .letter-section {
            scroll-margin-top: 100px;
            margin-top: 28px;
        }
        .letter-section:first-of-type { margin-top: 4px; }
        .letter-heading {
            font-family: 'Space Grotesk', 'Noto Sans SC', sans-serif;
            font-size: 1.05rem;
            font-weight: 600;
            color: var(--g-text-secondary);
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--g-border);
        }
        .operator-rows {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .operator-row {
            display: flex;
            flex-wrap: wrap;
            align-items: flex-start;
            gap: 14px 18px;
            padding: 14px 16px;
            border: 1px solid var(--g-border);
            border-radius: var(--g-radius-sm);
            background: var(--g-bg-raised);
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .operator-row:hover {
            border-color: var(--g-border-hover);
            box-shadow: 0 4px 18px rgba(59, 130, 246, 0.08);
        }
        .row-cat {
            flex: 0 0 auto;
            align-self: flex-start;
            margin-top: 2px;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.72rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: var(--g-accent);
            background: var(--g-accent-dim);
            border: 1px solid rgba(59, 130, 246, 0.2);
            max-width: 140px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .row-main {
            flex: 1 1 200px;
            min-width: 0;
        }
        .row-title-line {
            display: flex;
            flex-wrap: wrap;
            align-items: baseline;
            gap: 8px 12px;
            margin-bottom: 6px;
        }
        .row-title {
            font-weight: 600;
            font-size: 0.95rem;
            color: var(--g-text);
        }
        .row-id {
            font-family: var(--g-mono);
            font-size: 0.78rem;
            color: var(--g-text-muted);
        }
        .row-desc {
            font-size: 0.84rem;
            line-height: 1.5;
            color: var(--g-text-secondary);
            margin: 0;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }
        .row-methods {
            flex: 0 0 auto;
            align-self: center;
            color: var(--g-green);
            font-weight: 500;
            font-size: 0.82rem;
            white-space: nowrap;
        }
        .row-actions {
            flex: 1 1 240px;
            min-width: 0;
        }
        .copy-inline {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 8px;
            padding: 8px 10px;
            border-radius: var(--g-radius-sm);
            background: var(--g-bg-hover);
            border: 1px solid var(--g-border);
        }
        .copy-inline-code {
            flex: 1 1 160px;
            min-width: 0;
            font-family: var(--g-mono);
            font-size: 0.75rem;
            color: var(--g-text-secondary);
            word-break: break-all;
            line-height: 1.45;
        }
        .copy-btn-sm {
            padding: 6px 12px;
            font-size: 0.78rem;
        }
        .copy-btn {
            flex-shrink: 0;
            background: var(--g-accent);
            color: #fff;
            border: none;
            padding: 8px 14px;
            border-radius: var(--g-radius-sm);
            cursor: pointer;
            font-size: 0.82rem;
            font-weight: 500;
            transition: background 0.2s, transform 0.15s;
            box-shadow: 0 1px 3px rgba(59, 130, 246, 0.3);
        }
        .copy-btn:hover { background: var(--g-accent-hover); }
        .copy-btn:active { transform: scale(0.97); }
        .copy-btn.copied {
            background: var(--g-green);
            box-shadow: none;
        }
        .copy-url {
            font-family: var(--g-mono);
            background: var(--g-bg-hover);
            border: 1px solid var(--g-border);
            padding: 10px 12px;
            border-radius: var(--g-radius-sm);
            font-size: 0.8rem;
            word-break: break-all;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 10px;
        }
        .copy-url code {
            color: var(--g-text-secondary);
            font-size: inherit;
            background: none;
        }
        .api-hint {
            margin: 4px 0 14px;
            color: var(--g-text-muted);
            font-size: 0.86rem;
        }
    </style>
</head>
<body>
    <div class="hero">
        <div class="hero-inner container" style="padding-top:0;padding-bottom:0">
            <div class="hero-top">
                <span class="hero-badge">Operators</span>
                <button type="button" id="theme-toggle" class="theme-toggle" aria-label="Switch light or dark theme">Theme</button>
            </div>
            <h1 class="hero-title">GeniSpace Custom Operators</h1>
            <p class="hero-sub">Operator registry and HTTP API · v${versionSafe}</p>
        </div>
    </div>
    <div class="container">
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">${stats.totalOperators || 0}</div>
                <div class="stat-label">Registered operators</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${stats.totalEndpoints || 0}</div>
                <div class="stat-label">API endpoints</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${stats.routesCount || 0}</div>
                <div class="stat-label">Registered routes</div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">Registered operators</h2>
            <p class="section-desc">Indexed A–Z by operator <code style="font-family:var(--g-mono);font-size:0.88em;color:var(--g-accent)">name</code>. The badge is the top-level folder under <code style="font-family:var(--g-mono);font-size:0.88em;color:var(--g-accent)">operators/&lt;category&gt;/…</code> in the repo.</p>
            ${azNavHtml}
            ${operatorsGroupedHtml}
        </div>

        <div class="section">
            <h2 class="section-title">Common API URLs</h2>
            <div class="api-links">
                <div class="copy-url">
                    <code>${escapeHtml(docsUrl)}</code>
                    <button type="button" class="copy-btn" data-copy="${escapeAttr(docsUrl)}">Copy</button>
                </div>
                <div class="api-hint">Swagger UI</div>
                <div class="copy-url">
                    <code>${escapeHtml(operatorsListUrl)}</code>
                    <button type="button" class="copy-btn" data-copy="${escapeAttr(operatorsListUrl)}">Copy</button>
                </div>
                <div class="api-hint">Operators list (JSON)</div>
            </div>
        </div>
    </div>

    <script>
(function () {
  var THEME_KEY = 'gs_operators_service_theme';
  function applyTheme(mode) {
    var root = document.documentElement;
    root.classList.remove('light', 'dark');
    root.classList.add(mode === 'light' ? 'light' : 'dark');
    var btn = document.getElementById('theme-toggle');
    if (btn) btn.textContent = mode === 'light' ? 'Dark' : 'Light';
  }
  function readStored() {
    try {
      var t = localStorage.getItem(THEME_KEY);
      if (t === 'light' || t === 'dark') return t;
    } catch (e) {}
    return 'dark';
  }
  applyTheme(readStored());
  var toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      var next = document.documentElement.classList.contains('dark') ? 'light' : 'dark';
      try {
        localStorage.setItem(THEME_KEY, next);
      } catch (e) {}
      applyTheme(next);
    });
  }
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.copy-btn[data-copy]');
    if (!btn) return;
    var text = btn.getAttribute('data-copy');
    if (!text) return;
    function done() {
      var orig = btn.getAttribute('data-label') || btn.textContent;
      if (!btn.getAttribute('data-label')) btn.setAttribute('data-label', orig);
      btn.textContent = 'Copied';
      btn.classList.add('copied');
      setTimeout(function () {
        btn.textContent = btn.getAttribute('data-label');
        btn.classList.remove('copied');
      }, 2000);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(function () {
        fallbackSelect(btn);
      });
    } else {
      fallbackSelect(btn);
    }
    // Clipboard unavailable or denied: select visible text for manual copy
    function fallbackSelect(button) {
      var row = button.closest('.copy-url');
      var code = row && row.querySelector('code');
      if (!code) return;
      var range = document.createRange();
      range.selectNodeContents(code);
      var sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    }
  });
})();
    </script>
</body>
</html>`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  };

  app.get(apiPrefix, renderServiceHome);
  app.get('/', renderServiceHome);

  // Health check
  app.get('/health', (req, res) => {
    const stats = appService.getStats();
    const packageInfo = require('../../package.json');

    res.json({
      success: true,
      data: {
        status: 'healthy',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        version: packageInfo.version,
        environment: process.env.NODE_ENV || 'development',
        memory: process.memoryUsage(),
        operators: {
          loaded: stats.totalOperators,
          categories: stats.categories,
          endpoints: stats.totalEndpoints
        }
      }
    });
  });

  // Dev playground registry: operators, methods, schema, chatPluginConfig (no auth)
  app.get(`${apiPrefix}/dev/playground-registry`, (req, res) => {
    try {
      const operators = appService.getPlaygroundRegistry(req);
      res.json({
        success: true,
        data: { operators }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message || 'playground-registry failed',
        code: 'PLAYGROUND_REGISTRY_ERROR'
      });
    }
  });

  // Operators list API
  app.get(`${apiPrefix}/operators`, (req, res) => {
    const operators = appService.getOperators();
    const stats = appService.getStats();

    res.json({
      success: true,
      data: {
        operators,
        total: stats.totalOperators,
        categories: stats.categories,
        endpoints: stats.totalEndpoints
      }
    });
  });

  // Single operator definition (export / import)
  app.get(`${apiPrefix}/operators/:category/:name/definition`, (req, res) => {
    try {
      const { category, name } = req.params;
      const operatorId = `${category}/${name}`;

      const operatorDefinition = appService.getOperatorDefinition(operatorId, req);

      if (!operatorDefinition) {
        return res.status(404).json({
          success: false,
          error: 'Operator not found',
          code: 'OPERATOR_NOT_FOUND'
        });
      }

      res.json({
        success: true,
        data: operatorDefinition
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Failed to load operator definition',
        code: 'INTERNAL_ERROR'
      });
    }
  });

  // Operators in one category
  app.get(`${apiPrefix}/operators/:category`, (req, res) => {
    const { category } = req.params;
    const operators = appService.getOperatorsByCategory(category);

    if (operators.length === 0) {
      return res.status(404).json({
        success: false,
        error: `Category "${category}" not found or has no operators`,
        code: 'CATEGORY_NOT_FOUND'
      });
    }

    res.json({
      success: true,
      data: {
        category,
        operators,
        total: operators.length
      }
    });
  });

  // Operator stats
  app.get(`${apiPrefix}/stats`, (req, res) => {
    const stats = appService.getStats();

    res.json({
      success: true,
      data: {
        ...stats,
        timestamp: new Date().toISOString()
      }
    });
  });
}

module.exports = { setupRoutes };
