import API from '../lib/api.js';
import { showToast } from '../lib/utils.js';

const SOURCE_INFO = {
  nvd: { name: 'NVD', desc: '国家漏洞数据库', url: 'https://nvd.nist.gov' },
  kev: { name: 'CISA KEV', desc: '已知被利用漏洞', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
  epss: { name: 'EPSS', desc: '漏洞利用预测评分系统', url: 'https://www.first.org/epss/' },
  attck: { name: 'MITRE ATT&CK', desc: '企业 ATT&CK 框架', url: 'https://attack.mitre.org' },
  ghsa: { name: 'GitHub Advisory', desc: 'GitHub 安全公告', url: 'https://github.com/advisories' },
};

let lastSourceSummary = null;

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
    <div class="page-content">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--space-4)">
      <h2>数据源</h2>
      <div style="display:flex;gap:var(--space-2)">
        <button class="ti-btn ti-btn--secondary ti-btn--sm" onclick="window._refreshAttck()">更新 ATT&CK</button>
        <button class="ti-btn ti-btn--secondary ti-btn--sm" onclick="window._refreshKev()">同步 KEV</button>
      </div>
    </div>
    <div id="source-update-summary" class="source-update-summary" style="display:none"></div>
    <div id="sources-list"></div>
    </div>
  `;

  const list = document.getElementById('sources-list');

  for (const [key, info] of Object.entries(SOURCE_INFO)) {
    const h = healthMap[key];
    const statusCls = !h ? 'info' : h.status === 'ok' ? 'success' : h.status === 'degraded' ? 'warning' : 'error';
    const statusText = !h ? '未知' : h.status;
    const lastCheck = h?.last_check_at ? new Date(h.last_check_at).toLocaleString() : '从未检查';
    const lastError = h?.last_error || '';

    const card = document.createElement('div');
    card.className = 'source-card';
    card.innerHTML = `
      <div class="source-info">
        <span class="status-dot status-${statusCls === 'success' ? 'completed' : statusCls === 'error' ? 'failed' : ''}" style="background:var(--${statusCls === 'success' ? 'success' : statusCls === 'error' ? 'error' : 'info'})"></span>
        <div>
          <strong>${info.name}</strong>
          <div style="font-size:var(--text-xs);color:var(--text-secondary)">${info.desc}</div>
          <div style="font-size:var(--text-xs);color:var(--text-muted)">上次检查：${lastCheck}</div>
          ${lastError ? `<div style="font-size:var(--text-xs);color:var(--error);max-width:620px;line-height:1.45">原因：${escapeHtml(lastError)}</div>` : ''}
        </div>
      </div>
      <div style="display:flex;gap:var(--space-2);align-items:center">
        <span class="ti-badge ti-badge--${statusCls === 'success' ? 'success' : statusCls === 'error' ? 'error' : 'info'}">${statusText}</span>
        <button class="ti-btn ti-btn--secondary ti-btn--sm" onclick="window._testSource('${key}')">测试</button>
      </div>
    `;
    list.appendChild(card);
  }

  if (lastSourceSummary) {
    renderSourceSummary();
  }

  window._testSource = async (name) => {
    showToast(`正在测试 ${name}...`);
    try {
      const result = await API.testSource(name);
      showToast(`${SOURCE_INFO[name]?.name || name}: ${result.status}${result.response_time_ms ? ` (${result.response_time_ms}ms)` : ''}`);
      setSourceSummary(`${SOURCE_INFO[name]?.name || name} 测试结果`, [
        `状态：${result.status}`,
        `耗时：${result.response_time_ms ?? 'N/A'}ms`,
        result.hint ? `提示：${result.hint}` : '',
      ].filter(Boolean));
      await renderSources(container);
    } catch (err) {
      showToast(`${name}: ${err.message}`, 'error');
    }
  };

  window._refreshAttck = async () => {
    showToast('正在更新 ATT&CK 数据...');
    try {
      const result = await API.post('/sources/refresh_attck');
      showToast('ATT&CK 已更新');
      setSourceSummary('ATT&CK 更新完成', [
        `对象总数：${result.objects_count ?? 'N/A'}`,
        `技术：${result.attack_patterns ?? 'N/A'}`,
        `组织：${result.groups ?? 'N/A'}`,
        `软件/工具：${result.software ?? 'N/A'}`,
        `文件大小：${formatBytes(result.size_bytes)}`,
        `更新时间：${new Date(result.timestamp).toLocaleString()}`,
      ]);
      await renderSources(container);
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  window._refreshKev = async () => {
    showToast('正在同步 KEV...');
    try {
      const result = await API.post('/sources/refresh_kev');
      showToast('KEV 已同步');
      setSourceSummary('KEV 同步完成', [
        `漏洞条目：${result.vulnerabilities_count ?? 'N/A'}`,
        `文件大小：${formatBytes(result.size_bytes)}`,
        `更新时间：${new Date(result.timestamp).toLocaleString()}`,
      ]);
      await renderSources(container);
    } catch (err) {
      showToast(err.message, 'error');
    }
  };
}

function setSourceSummary(title, lines) {
  lastSourceSummary = { title, lines };
  renderSourceSummary();
}

function renderSourceSummary() {
  const el = document.getElementById('source-update-summary');
  if (!el || !lastSourceSummary) return;
  const { title, lines } = lastSourceSummary;
  const items = Array.isArray(lines) ? lines : [lines];
  el.style.display = 'block';
  el.innerHTML = `
    <strong>${title}</strong>
    <div style="display:flex;gap:var(--space-3);flex-wrap:wrap;margin-top:var(--space-2)">
      ${items.map(item => `<span class="badge badge-info">${escapeHtml(String(item))}</span>`).join('')}
    </div>
  `;
}

function formatBytes(bytes) {
  if (!bytes && bytes !== 0) return 'N/A';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
