import API from '../lib/api.js';
import { showToast } from '../lib/utils.js';

export async function renderSettings(container) {
  container.innerHTML = '<div class="skeleton" style="height:300px"></div>';

  let settings = {};
  try {
    settings = await API.settings();
  } catch (err) {
    showToast('加载设置失败', 'error');
  }

  container.innerHTML = `
    <div class="page-content">
    <h2 style="margin-bottom:var(--space-4)">系统设置</h2>

    <div class="settings-group ti-card" style="padding:var(--space-5)">
      <h3>API 密钥</h3>
      <div class="form-row">
        <label>NVD API 密钥</label>
        <input id="set-nvd" class="ti-input" type="password" placeholder="${settings.nvd_api_key || '未设置'}">
      </div>
      <div class="form-row">
        <label>GitHub 令牌</label>
        <input id="set-gh" class="ti-input" type="password" placeholder="${settings.github_token || '未设置'}">
      </div>
    </div>

    <div class="settings-group ti-card" style="padding:var(--space-5)">
      <h3>预算与限制</h3>
      <div class="form-row">
        <label>月度预算（元）</label>
        <input id="set-budget" class="ti-input" type="number" value="${settings.monthly_budget_usd || 300}">
      </div>
      <div class="form-row">
        <label>单任务令牌上限</label>
        <input id="set-tokens" class="ti-input" type="number" value="${settings.single_task_token_limit || 900000}">
      </div>
      <div class="form-row">
        <label>研究代理数量</label>
        <input id="set-researchers" class="ti-input" type="number" value="${settings.researcher_count_default || 4}" min="1" max="5">
      </div>
    </div>

    <div class="settings-group ti-card" style="padding:var(--space-5)">
      <h3>显示设置</h3>
      <div class="form-row">
        <label>默认 TLP</label>
        <select id="set-tlp" class="ti-input" style="max-width:200px">
          ${['WHITE','GREEN','AMBER','AMBER+STRICT','RED'].map(t =>
            `<option value="${t}" ${settings.tlp_default === t ? 'selected' : ''}>${t}</option>`
          ).join('')}
        </select>
      </div>
      <div class="form-row">
        <label>主题</label>
        <button class="ti-btn ti-btn--secondary ti-btn--sm" onclick="window.toggleTheme()">切换亮色/暗色</button>
      </div>
    </div>

    <button class="ti-btn ti-btn--primary" onclick="window._saveSettings()">保存设置</button>

    <div class="settings-group ti-card" style="margin-top:var(--space-6);padding:var(--space-5)">
      <h3>可信源白名单</h3>
      <p style="font-size:var(--text-xs);color:var(--text-muted);margin-bottom:var(--space-3)">可信域名的来源在报告中自动标记为高置信度</p>
      <div style="display:flex;gap:var(--space-2);margin-bottom:var(--space-3)">
        <input id="trusted-domain-input" class="ti-input" placeholder="输入域名，如 nist.gov" style="flex:1">
        <input id="trusted-note-input" class="ti-input" placeholder="备注（可选）" style="flex:1">
        <button class="ti-btn ti-btn--primary ti-btn--sm" onclick="window._addTrusted()">添加</button>
      </div>
      <div id="trusted-list"></div>
    </div>

    <div class="settings-group ti-card" style="margin-top:var(--space-6);padding:var(--space-5)">
      <h3>审计日志</h3>
      <p style="font-size:var(--text-xs);color:var(--text-muted);margin-bottom:var(--space-3)">记录分析启动、导出、删除、设置变更等操作（保留 90 天）</p>
      <div id="audit-log-list"></div>
    </div>
    </div>
  `;

  // Load trusted sources
  _loadTrustedSources();

  // Load audit logs
  _loadAuditLogs();

  window._addTrusted = async () => {
    const domain = document.getElementById('trusted-domain-input').value.trim();
    const note = document.getElementById('trusted-note-input').value.trim();
    if (!domain) { showToast('请输入域名', 'error'); return; }
    try {
      await API.addTrustedSource(domain, note);
      showToast('已添加');
      document.getElementById('trusted-domain-input').value = '';
      document.getElementById('trusted-note-input').value = '';
      _loadTrustedSources();
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  window._deleteTrusted = async (domain) => {
    if (!confirm(`确定删除 ${domain}？`)) return;
    try {
      await API.deleteTrustedSource(domain);
      showToast('已删除');
      _loadTrustedSources();
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  window._saveSettings = async () => {
    const data = {};
    const nvd = document.getElementById('set-nvd').value.trim();
    const gh = document.getElementById('set-gh').value.trim();
    if (nvd) data.nvd_api_key = nvd;
    if (gh) data.github_token = gh;
    data.monthly_budget_usd = parseFloat(document.getElementById('set-budget').value);
    data.single_task_token_limit = parseInt(document.getElementById('set-tokens').value);
    data.researcher_count_default = parseInt(document.getElementById('set-researchers').value);
    data.tlp_default = document.getElementById('set-tlp').value;

    try {
      await API.updateSettings(data);
      showToast('设置已保存');
      // Clear password fields
      document.getElementById('set-nvd').value = '';
      document.getElementById('set-gh').value = '';
    } catch (err) {
      showToast(err.message, 'error');
    }
  };
}

async function _loadTrustedSources() {
  const el = document.getElementById('trusted-list');
  if (!el) return;
  try {
    const sources = await API.trustedSources();
    if (!sources.length) {
      el.innerHTML = '<p style="font-size:var(--text-xs);color:var(--text-muted)">暂无可信源</p>';
      return;
    }
    el.innerHTML = sources.map(s => `
      <div style="display:flex;justify-content:space-between;align-items:center;padding:var(--space-2) 0;border-bottom:1px solid var(--border-hairline-soft)">
        <div>
          <code style="font-size:var(--text-sm)">${s.domain}</code>
          ${s.note ? `<span style="font-size:var(--text-xs);color:var(--text-muted);margin-left:var(--space-2)">${s.note}</span>` : ''}
        </div>
        <button class="ti-btn ti-btn--danger ti-btn--sm" onclick="window._deleteTrusted('${s.domain}')">删除</button>
      </div>
    `).join('');
  } catch {
    el.innerHTML = '<p style="font-size:var(--text-xs);color:var(--text-muted)">加载失败</p>';
  }
}

async function _loadAuditLogs() {
  const el = document.getElementById('audit-log-list');
  if (!el) return;
  try {
    const data = await API.get('/audit_logs?limit=30');
    const items = data.items || [];
    if (!items.length) {
      el.innerHTML = '<p style="font-size:var(--text-xs);color:var(--text-muted)">暂无审计记录</p>';
      return;
    }
    el.innerHTML = items.map(item => {
      const eventMap = {
        'analysis_started': '分析启动',
        'analysis_deleted': '分析删除',
        'exported': '报告导出',
        'setting_changed': '设置变更',
        'analysis_refreshed': '增量刷新',
      };
      const label = eventMap[item.event_type] || item.event_type;
      const detail = item.detail ? Object.entries(item.detail).map(([k, v]) => `${k}: ${v}`).join(', ') : '';
      return `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:var(--space-2) 0;border-bottom:1px solid var(--border-hairline-soft);font-size:var(--text-xs)">
          <div>
            <span class="badge badge-info" style="margin-right:var(--space-2)">${label}</span>
            <span style="color:var(--text-muted)">${detail}</span>
          </div>
          <span style="color:var(--text-muted)">${item.created_at?.slice(0, 19).replace('T', ' ') || ''}</span>
        </div>
      `;
    }).join('');
  } catch {
    el.innerHTML = '<p style="font-size:var(--text-xs);color:var(--text-muted)">加载失败</p>';
  }
}
