import API from '../lib/api.js';
import { showToast } from '../lib/utils.js';

const SOURCE_INFO = {
  nvd: { name: 'NVD', desc: 'National Vulnerability Database', url: 'https://nvd.nist.gov' },
  kev: { name: 'CISA KEV', desc: 'Known Exploited Vulnerabilities', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
  epss: { name: 'EPSS', desc: 'Exploit Prediction Scoring System', url: 'https://www.first.org/epss/' },
  attck: { name: 'MITRE ATT&CK', desc: 'Enterprise ATT&CK Framework', url: 'https://attack.mitre.org' },
  ghsa: { name: 'GitHub Advisory', desc: 'GitHub Security Advisories', url: 'https://github.com/advisories' },
};

export async function renderSources(container) {
  container.innerHTML = '<div class="skeleton" style="height:300px"></div>';

  let health = { sources: [] };
  try {
    health = await API.sourcesHealth();
  } catch (err) {
    showToast('Failed to load source health', 'error');
  }

  const healthMap = {};
  health.sources.forEach(s => { healthMap[s.source_name] = s; });

  container.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--space-4)">
      <h2>Data Sources</h2>
      <div style="display:flex;gap:var(--space-2)">
        <button class="btn btn-sm" onclick="window._refreshAttck()">Update ATT&CK</button>
        <button class="btn btn-sm" onclick="window._refreshKev()">Sync KEV</button>
      </div>
    </div>
    <div id="sources-list"></div>
  `;

  const list = document.getElementById('sources-list');

  for (const [key, info] of Object.entries(SOURCE_INFO)) {
    const h = healthMap[key];
    const statusCls = !h ? 'info' : h.status === 'ok' ? 'success' : h.status === 'degraded' ? 'warning' : 'error';
    const statusText = !h ? 'Unknown' : h.status;
    const lastCheck = h?.last_check_at ? new Date(h.last_check_at).toLocaleString() : 'Never';

    const card = document.createElement('div');
    card.className = 'source-card';
    card.innerHTML = `
      <div class="source-info">
        <span class="status-dot status-${statusCls === 'success' ? 'completed' : statusCls === 'error' ? 'failed' : ''}" style="background:var(--${statusCls === 'success' ? 'success' : statusCls === 'error' ? 'error' : 'info'})"></span>
        <div>
          <strong>${info.name}</strong>
          <div style="font-size:var(--text-xs);color:var(--text-secondary)">${info.desc}</div>
          <div style="font-size:var(--text-xs);color:var(--text-muted)">Last check: ${lastCheck}</div>
        </div>
      </div>
      <div style="display:flex;gap:var(--space-2);align-items:center">
        <span class="badge badge-${statusCls}">${statusText}</span>
        <button class="btn btn-sm" onclick="window._testSource('${key}')">Test</button>
      </div>
    `;
    list.appendChild(card);
  }

  window._testSource = async (name) => {
    showToast(`Testing ${name}...`);
    try {
      const result = await API.testSource(`/sources/test/${name}`);
      // Refresh page to show updated status
      renderSources(container);
    } catch (err) {
      showToast(`${name}: ${err.message}`, 'error');
    }
  };

  window._refreshAttck = async () => {
    showToast('Updating ATT&CK data...');
    try {
      await API.post('/sources/refresh_attck');
      showToast('ATT&CK updated');
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  window._refreshKev = async () => {
    showToast('Syncing KEV...');
    try {
      await API.post('/sources/refresh_kev');
      showToast('KEV synced');
    } catch (err) {
      showToast(err.message, 'error');
    }
  };
}
