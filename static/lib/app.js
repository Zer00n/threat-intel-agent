import { router } from './router.js';
import API from './api.js';
import { renderWorkspace } from '../pages/workspace.js';
import { renderHistoryList } from '../pages/history-list.js';
import { renderHistoryDetail } from '../pages/history-detail.js';
import { renderSettings } from '../pages/settings.js';
import { renderSources } from '../pages/sources.js';

const container = document.getElementById('page-container');

// Theme
const savedTheme = localStorage.getItem('ti-theme') || 'light';
document.documentElement.dataset.theme = savedTheme;

// Router
router
  .on('/', () => renderWorkspace(container))
  .on('/history', () => renderHistoryList(container))
  .on('/history/:id', (id) => renderHistoryDetail(container, id))
  .on('/settings', () => renderSettings(container))
  .on('/sources', () => renderSources(container))
  .on('*', () => { container.innerHTML = '<div class="empty-state"><h2>页面未找到</h2></div>'; })
  .start();

// Theme toggle
window.toggleTheme = () => {
  const current = document.documentElement.dataset.theme;
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  localStorage.setItem('ti-theme', next);
};
