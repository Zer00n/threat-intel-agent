/** Error boundary pages: 404, 500, network error. */
import { router } from '../lib/router.js';

export function renderError(container, opts = {}) {
  const {
    code = 404,
    title = '页面未找到',
    message = '请求的页面不存在，请检查 URL 是否正确。',
    icon = '🔍',
    showRetry = false,
    showHome = true,
  } = opts;

  container.innerHTML = `
    <div class="error-page">
      <div class="error-page__inner">
        <div class="error-page__icon">${icon}</div>
        <h1 class="error-page__code">${code}</h1>
        <h2 class="error-page__title">${title}</h2>
        <p class="error-page__message">${message}</p>
        <div class="error-page__actions">
          ${showRetry ? '<button class="ti-btn ti-btn--secondary" onclick="location.reload()">刷新重试</button>' : ''}
          ${showHome ? '<a class="ti-btn" href="#/">返回工作台</a>' : ''}
        </div>
      </div>
    </div>
  `;
}

export function render404(container) {
  renderError(container, {
    code: 404,
    title: '页面未找到',
    message: '请求的页面不存在，请检查 URL 是否正确。',
    icon: '🔍',
  });
}

export function render500(container, detail = '') {
  renderError(container, {
    code: 500,
    title: '服务器错误',
    message: detail || '服务遇到了一个内部错误，请稍后重试。',
    icon: '⚠️',
    showRetry: true,
  });
}

export function renderNetworkError(container) {
  renderError(container, {
    code: 0,
    title: '网络连接失败',
    message: '无法连接到服务器，请检查网络连接后重试。',
    icon: '🔌',
    showRetry: true,
  });
}
