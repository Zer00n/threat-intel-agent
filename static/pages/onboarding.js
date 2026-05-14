/**
 * First-time startup onboarding wizard.
 * 3 steps: theme selection → API key config → done
 * Shows only when no ANTHROPIC_API_KEY is configured (detected via /health endpoint).
 */
import API from '../lib/api.js';
import { showToast } from '../lib/utils.js';

const ONBOARDING_KEY = 'ti-onboarding-done';
const TOTAL_STEPS = 3;

export async function needsOnboarding() {
  // Skip if already completed
  if (localStorage.getItem(ONBOARDING_KEY)) return false;
  // Check if API key is configured
  try {
    const health = await API.get('/health');
    // If health says no API key, show onboarding
    return health.api_key_configured === false;
  } catch {
    // Can't reach server — skip onboarding, let error handling kick in
    return false;
  }
}

export function renderOnboarding(container) {
  let currentStep = 0;
  let selectedTheme = localStorage.getItem('ti-theme') || 'light';
  let apiKeyValue = '';

  function render() {
    container.innerHTML = `
      <div class="onboarding">
        <div class="onboarding__card">
          <div class="onboarding__logo">
            <h1>Threat Intel Agent</h1>
            <p>企业级威胁情报分析平台</p>
          </div>

          <div class="onboarding__step" id="onboarding-step">
            ${renderStep(currentStep)}
          </div>

          <div class="onboarding__footer">
            <div class="onboarding__dots">
              ${Array.from({ length: TOTAL_STEPS }, (_, i) =>
                `<div class="onboarding__dot${i === currentStep ? ' active' : ''}"></div>`
              ).join('')}
            </div>
            <div style="display:flex;gap:var(--space-2)">
              ${currentStep > 0 ? '<button class="ti-btn ti-btn--secondary" id="onboarding-prev">上一步</button>' : ''}
              ${currentStep < TOTAL_STEPS - 1
                ? '<button class="ti-btn ti-btn--primary" id="onboarding-next">下一步</button>'
                : '<button class="ti-btn ti-btn--primary" id="onboarding-finish">开始使用</button>'}
            </div>
          </div>
        </div>
      </div>
    `;

    // Bind events
    document.getElementById('onboarding-prev')?.addEventListener('click', () => {
      currentStep = Math.max(0, currentStep - 1);
      render();
    });

    document.getElementById('onboarding-next')?.addEventListener('click', () => {
      handleNext();
    });

    document.getElementById('onboarding-finish')?.addEventListener('click', () => {
      handleFinish();
    });

    // Bind step-specific events
    bindStepEvents();
  }

  function renderStep(step) {
    switch (step) {
      case 0:
        return `
          <h3 class="onboarding__step-title">选择界面主题</h3>
          <div class="onboarding__option ${selectedTheme === 'light' ? 'selected' : ''}" data-theme="light">
            <span class="onboarding__option-icon">☀️</span>
            <div class="onboarding__option-text">
              <strong>浅色模式</strong>
              <span>明亮的界面，适合白天使用</span>
            </div>
          </div>
          <div class="onboarding__option ${selectedTheme === 'dark' ? 'selected' : ''}" data-theme="dark">
            <span class="onboarding__option-icon">🌙</span>
            <div class="onboarding__option-text">
              <strong>深色模式</strong>
              <span>暗色界面，保护眼睛</span>
            </div>
          </div>
        `;
      case 1:
        return `
          <h3 class="onboarding__step-title">配置 API 密钥</h3>
          <p style="font-size:var(--text-sm);color:var(--text-muted);margin-bottom:var(--space-4)">
            需要配置 AI 模型 API 密钥才能进行威胁情报分析。<br>
            支持 Anthropic、OpenRouter、SiliconFlow 等 OpenAI 兼容接口。
          </p>
          <div style="margin-bottom:var(--space-3)">
            <label style="display:block;font-size:var(--text-sm);font-weight:500;margin-bottom:var(--space-1)">API 密钥</label>
            <input type="password" id="onboarding-apikey" class="ti-input" placeholder="sk-..."
              value="${escapeAttr(apiKeyValue)}" style="width:100%" />
          </div>
          <div style="margin-bottom:var(--space-3)">
            <label style="display:block;font-size:var(--text-sm);font-weight:500;margin-bottom:var(--space-1)">API 基础 URL（可选）</label>
            <input type="text" id="onboarding-baseurl" class="ti-input" placeholder="https://api.openai.com/v1"
              style="width:100%" />
          </div>
          <div>
            <label style="display:block;font-size:var(--text-sm);font-weight:500;margin-bottom:var(--space-1)">API 格式</label>
            <div style="display:flex;gap:var(--space-2)">
              <label class="onboarding__option" style="flex:1;margin:0;padding:var(--space-2) var(--space-3)">
                <input type="radio" name="api-format" value="openai" checked style="margin-right:var(--space-2)" />
                <span style="font-size:var(--text-sm)">OpenAI 兼容</span>
              </label>
              <label class="onboarding__option" style="flex:1;margin:0;padding:var(--space-2) var(--space-3)">
                <input type="radio" name="api-format" value="anthropic" style="margin-right:var(--space-2)" />
                <span style="font-size:var(--text-sm)">Anthropic</span>
              </label>
            </div>
          </div>
        `;
      case 2:
        return `
          <h3 class="onboarding__step-title">配置完成</h3>
          <div style="text-align:center;padding:var(--space-4) 0">
            <div style="font-size:48px;margin-bottom:var(--space-4)">🛡️</div>
            <p style="font-size:var(--text-base);color:var(--text-primary);margin-bottom:var(--space-2)">
              一切准备就绪！
            </p>
            <p style="font-size:var(--text-sm);color:var(--text-muted)">
              你现在可以输入 CVE 编号、APT 组织名称、IOC 指标或 ATT&CK 技术编号<br>
              开始进行威胁情报深度调研。
            </p>
          </div>
        `;
      default:
        return '';
    }
  }

  function bindStepEvents() {
    // Step 0: Theme selection
    if (currentStep === 0) {
      container.querySelectorAll('.onboarding__option[data-theme]').forEach(opt => {
        opt.addEventListener('click', () => {
          selectedTheme = opt.dataset.theme;
          document.documentElement.dataset.theme = selectedTheme;
          localStorage.setItem('ti-theme', selectedTheme);
          container.querySelectorAll('.onboarding__option[data-theme]').forEach(o => o.classList.remove('selected'));
          opt.classList.add('selected');
        });
      });
    }
  }

  async function handleNext() {
    if (currentStep === 1) {
      // Save API key before proceeding
      const keyInput = document.getElementById('onboarding-apikey');
      const baseUrlInput = document.getElementById('onboarding-baseurl');
      apiKeyValue = keyInput?.value?.trim() || '';

      if (!apiKeyValue) {
        showToast('请输入 API 密钥', 'error');
        return;
      }

      try {
        const formatEl = container.querySelector('input[name="api-format"]:checked');
        const format = formatEl?.value || 'openai';
        await API.updateSettings({
          anthropic_api_key: apiKeyValue,
          anthropic_base_url: baseUrlInput?.value?.trim() || '',
          api_format: format,
        });
        showToast('API 密钥已保存');
      } catch (err) {
        showToast('保存失败：' + err.message, 'error');
        return;
      }
    }
    currentStep = Math.min(TOTAL_STEPS - 1, currentStep + 1);
    render();
  }

  function handleFinish() {
    localStorage.setItem(ONBOARDING_KEY, '1');
    window.location.hash = '#/';
  }

  // Initial render
  render();
}

function escapeAttr(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
