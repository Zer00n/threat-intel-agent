import { router } from './router.js';
import API from './api.js';
import { renderWorkspace } from '../pages/workspace.js';
import { renderHistoryList } from '../pages/history-list.js';
import { renderHistoryDetail } from '../pages/history-detail.js';
import { renderSettings } from '../pages/settings.js';
import { renderSources } from '../pages/sources.js';
import { render404 } from '../pages/error.js';
import { needsOnboarding, renderOnboarding } from '../pages/onboarding.js';

const container = document.getElementById('page-container');

// Theme
const savedTheme = localStorage.getItem('ti-theme') || 'light';
document.documentElement.dataset.theme = savedTheme;

// Theme toggle
document.getElementById('theme-toggle')?.addEventListener('click', () => {
  window.toggleTheme();
});

window.toggleTheme = () => {
  const current = document.documentElement.dataset.theme;
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  localStorage.setItem('ti-theme', next);
};

// Breadcrumb helper
function setBreadcrumb(html) {
  const el = document.getElementById('header-breadcrumb');
  if (el) el.innerHTML = html;
}

// Remove workspace class when leaving workspace page
function clearPageClass() {
  window._suspendWorkspace?.();
  document.body.classList.remove('page-workspace');
}

// Router
router
  .on('/', () => renderWorkspace(container))
  .on('/history', () => {
    clearPageClass();
    setBreadcrumb('<a href="#/">工作区</a><span class="sep">›</span><span>历史记录</span>');
    renderHistoryList(container);
  })
  .on('/history/:id', (id) => {
    clearPageClass();
    setBreadcrumb('<a href="#/">工作区</a><span class="sep">›</span><a href="#/history">历史</a><span class="sep">›</span><span class="app-header__taskid">' + id.slice(0, 8) + '</span>');
    renderHistoryDetail(container, id);
  })
  .on('/settings', () => {
    clearPageClass();
    setBreadcrumb('<a href="#/">工作区</a><span class="sep">›</span><span>系统设置</span>');
    renderSettings(container);
  })
  .on('/sources', () => {
    clearPageClass();
    setBreadcrumb('<a href="#/">工作区</a><span class="sep">›</span><span>数据源</span>');
    renderSources(container);
  })
  .on('*', () => {
    clearPageClass();
    setBreadcrumb('<span>页面未找到</span>');
    render404(container);
  });

// Boot: check onboarding first, then start router
async function boot() {
  try {
    if (await needsOnboarding()) {
      clearPageClass();
      setBreadcrumb('<span>首次配置</span>');
      renderOnboarding(container);
      return;
    }
  } catch {
    // Ignore — proceed to normal routing
  }
  router.start();
}

boot();
