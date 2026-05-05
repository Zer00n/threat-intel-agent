import API from '../lib/api.js';
import { showToast } from '../lib/utils.js';

export async function renderSettings(container) {
  container.innerHTML = '<div class="skeleton" style="height:300px"></div>';

  let settings = {};
  try {
    settings = await API.settings();
  } catch (err) {
    showToast('Failed to load settings', 'error');
  }

  container.innerHTML = `
    <h2 style="margin-bottom:var(--space-4)">Settings</h2>

    <div class="settings-group card">
      <h3>API Keys</h3>
      <div class="form-row">
        <label>NVD API Key</label>
        <input id="set-nvd" class="input" type="password" placeholder="${settings.nvd_api_key || 'Not set'}">
      </div>
      <div class="form-row">
        <label>GitHub Token</label>
        <input id="set-gh" class="input" type="password" placeholder="${settings.github_token || 'Not set'}">
      </div>
    </div>

    <div class="settings-group card">
      <h3>Budget & Limits</h3>
      <div class="form-row">
        <label>Monthly Budget (USD)</label>
        <input id="set-budget" class="input" type="number" value="${settings.monthly_budget_usd || 50}">
      </div>
      <div class="form-row">
        <label>Single Task Token Limit</label>
        <input id="set-tokens" class="input" type="number" value="${settings.single_task_token_limit || 200000}">
      </div>
      <div class="form-row">
        <label>Researcher Count</label>
        <input id="set-researchers" class="input" type="number" value="${settings.researcher_count_default || 4}" min="1" max="5">
      </div>
    </div>

    <div class="settings-group card">
      <h3>Display</h3>
      <div class="form-row">
        <label>Default TLP</label>
        <select id="set-tlp" class="input" style="max-width:200px">
          ${['WHITE','GREEN','AMBER','AMBER+STRICT','RED'].map(t =>
            `<option value="${t}" ${settings.tlp_default === t ? 'selected' : ''}>${t}</option>`
          ).join('')}
        </select>
      </div>
      <div class="form-row">
        <label>Theme</label>
        <button class="btn btn-sm" onclick="window.toggleTheme()">Toggle Light/Dark</button>
      </div>
    </div>

    <button class="btn btn-primary" onclick="window._saveSettings()">Save Settings</button>
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
      showToast('Settings saved');
      // Clear password fields
      document.getElementById('set-nvd').value = '';
      document.getElementById('set-gh').value = '';
    } catch (err) {
      showToast(err.message, 'error');
    }
  };
}
