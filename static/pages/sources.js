import API from '../lib/api.js';
import { showToast } from '../lib/utils.js';

const SOURCE_INFO = {
  nvd: { name: 'NVD', desc: '国家漏洞数据库', url: 'https://nvd.nist.gov' },
  kev: { name: 'CISA KEV', desc: '已知被利用漏洞', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
  epss: { name: 'EPSS', desc: '漏洞利用预测评分系统', url: 'https://www.first.org/epss/' },
  attck: { name: 'MITRE ATT&CK', desc: '企业 ATT&CK 框架', url: 'https://attack.mitre.org' },
  ghsa: { name: 'GitHub Advisory', desc: 'GitHub 安全公告', url: 'https://github.com/advisories' },
};

export async function renderSources(container) {
  container.innerHTML = '<div class="skeleton" style="height:300px"></div>';

  let health = { sources: [] };
  try {
    health = await API.sourcesHealth();
  } catch (err) {
    showToast('加载数据源状态失败', 'error');
  }

  const healthMap = {};
  health.sources.forEach(s => { healthMap[s.source_name] = s; });

  container.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--space-4)">
      <h2>数据源</h2>
      <div style="display:flex;gap:var(--space-2)">
        <button class="btn btn-sm" onclick="window._refreshAttck()">更新 ATT&CK</button>
        <button class="btn btn-sm" onclick="window._refreshKev()">同步 KEV</button>
      </div>
    </div>
    <div id="sources-list"></div>
  `;

  const list = document.getElementById('sources-list');

  for (const [key, info] of Object.entries(SOURCE_INFO)) {
    const h = healthMap[key];
    const statusCls = !h ? 'info' : h.status === 'ok' ? 'success' : h.status === 'degraded' ? 'warning' : 'error';
    const statusText = !h ? '未知' : h.status;
    const lastCheck = h?.last_check_at ? new Date(h.last_check_at).toLocaleString() : '从未检查';

    const card = document.createElement('div');
    card.className = 'source-card';
    card.innerHTML = `
      <div class="source-info">
        <span class="status-dot status-${statusCls === 'success' ? 'completed' : statusCls === 'error' ? 'failed' : ''}" style="background:var(--${statusCls === 'success' ? 'success' : statusCls === 'error' ? 'error' : 'info'})"></span>
        <div>
          <strong>${info.name}</strong>
          <div style="font-size:var(--text-xs);color:var(--text-secondary)">${info.desc}</div>
          <div style="font-size:var(--text-xs);color:var(--text-muted)">上次检查：${lastCheck}</div>
        </div>
      </div>
      <div style="display:flex;gap:var(--space-2);align-items:center">
        <span class="badge badge-${statusCls}">${statusText}</span>
        <button class="btn btn-sm" onclick="window._testSource('${key}')">测试</button>
      </div>
    `;
    list.appendChild(card);
  }

  window._testSource = async (name) => {
    showToast(`正在测试 ${name}...`);
    try {
      const result = await API.testSource(`/sources/test/${name}`);
      renderSources(container);
    } catch (err) {
      showToast(`${name}: ${err.message}`, 'error');
    }
  };

  window._refreshAttck = async () => {
    showToast('正在更新 ATT&CK 数据...');
    try {
      await API.post('/sources/refresh_attck');
      showToast('ATT&CK 已更新');
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  window._refreshKev = async () => {
    showToast('正在同步 KEV...');
    try {
      await API.post('/sources/refresh_kev');
      showToast('KEV 已同步');
    } catch (err) {
      showToast(err.message, 'error');
    }
  };
}
