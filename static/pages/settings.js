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
    <h2 style="margin-bottom:var(--space-4)">系统设置</h2>

    <div class="settings-group card">
      <h3>API 密钥</h3>
      <div class="form-row">
        <label>NVD API 密钥</label>
        <input id="set-nvd" class="input" type="password" placeholder="${settings.nvd_api_key || '未设置'}">
      </div>
      <div class="form-row">
        <label>GitHub 令牌</label>
        <input id="set-gh" class="input" type="password" placeholder="${settings.github_token || '未设置'}">
      </div>
    </div>

    <div class="settings-group card">
      <h3>预算与限制</h3>
      <div class="form-row">
        <label>月度预算（美元）</label>
        <input id="set-budget" class="input" type="number" value="${settings.monthly_budget_usd || 50}">
      </div>
      <div class="form-row">
        <label>单任务令牌上限</label>
        <input id="set-tokens" class="input" type="number" value="${settings.single_task_token_limit || 200000}">
      </div>
      <div class="form-row">
        <label>研究代理数量</label>
        <input id="set-researchers" class="input" type="number" value="${settings.researcher_count_default || 4}" min="1" max="5">
      </div>
    </div>

    <div class="settings-group card">
      <h3>显示设置</h3>
      <div class="form-row">
        <label>默认 TLP</label>
        <select id="set-tlp" class="input" style="max-width:200px">
          ${['WHITE','GREEN','AMBER','AMBER+STRICT','RED'].map(t =>
            `<option value="${t}" ${settings.tlp_default === t ? 'selected' : ''}>${t}</option>`
          ).join('')}
        </select>
      </div>
      <div class="form-row">
        <label>主题</label>
        <button class="btn btn-sm" onclick="window.toggleTheme()">切换亮色/暗色</button>
      </div>
    </div>

    <button class="btn btn-primary" onclick="window._saveSettings()">保存设置</button>
  `;

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
