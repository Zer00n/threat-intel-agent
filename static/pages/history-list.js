import API from '../lib/api.js';
import { formatDate, statusBadge, tlpBadge, showToast } from '../lib/utils.js';
import { router } from '../lib/router.js';

export async function renderHistoryList(container) {
  container.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--space-4)">
      <h2>Analysis History</h2>
      <div style="display:flex;gap:var(--space-2)">
        <input id="history-search" class="input" placeholder="Search..." style="width:250px">
        <select id="history-filter-status" class="input" style="width:120px">
          <option value="">All Status</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
          <option value="stopped">Stopped</option>
        </select>
      </div>
    </div>
    <div id="history-list" class="history-list">
      <div class="skeleton" style="height:60px;margin-bottom:8px"></div>
      <div class="skeleton" style="height:60px;margin-bottom:8px"></div>
      <div class="skeleton" style="height:60px"></div>
    </div>
    <div id="history-pagination" style="display:flex;justify-content:center;gap:var(--space-2);margin-top:var(--space-4)"></div>
  `;

  let offset = 0;
  const limit = 20;

  const loadHistory = async (search = '', status = '') => {
    const params = { limit, offset };
    if (search) params.q = search;
    if (status) params.status = status;

    try {
      const data = await API.history(params);
      renderList(data);
    } catch (err) {
      showToast('Failed to load history', 'error');
    }
  };

  const renderList = (data) => {
    const list = document.getElementById('history-list');
    if (!data.items.length) {
      list.innerHTML = '<div class="empty-state"><h3>No analyses yet</h3><p>Start a new analysis from the workspace</p></div>';
      return;
    }

    list.innerHTML = data.items.map(item => `
      <div class="history-item" onclick="window._openHistory('${item.id}')">
        <div class="history-item-header">
          <span class="history-item-query">${escapeHtml(item.query)}</span>
          <span>${statusBadge(item.status)}</span>
        </div>
        <div class="history-item-meta">
          ${item.intent ? `<span class="badge badge-info">${item.intent}</span>` : ''}
          ${tlpBadge(item.tlp)}
          ${item.overall_confidence ? `<span>Confidence: ${item.overall_confidence}</span>` : ''}
          <span>${formatDate(item.created_at)}</span>
          ${item.duration_s ? `<span>${item.duration_s}s</span>` : ''}
          ${item.cost_usd ? `<span>$${item.cost_usd.toFixed(2)}</span>` : ''}
        </div>
      </div>
    `).join('');

    // Pagination
    const totalPages = Math.ceil(data.total / limit);
    const currentPage = Math.floor(offset / limit) + 1;
    const pagination = document.getElementById('history-pagination');
    pagination.innerHTML = '';
    if (totalPages > 1) {
      for (let i = 1; i <= Math.min(totalPages, 10); i++) {
        const btn = document.createElement('button');
        btn.className = `btn btn-sm ${i === currentPage ? 'btn-primary' : ''}`;
        btn.textContent = i;
        btn.onclick = () => { offset = (i - 1) * limit; loadHistory(); };
        pagination.appendChild(btn);
      }
    }
  };

  document.getElementById('history-search').addEventListener('input', debounce((e) => {
    offset = 0;
    loadHistory(e.target.value, document.getElementById('history-filter-status').value);
  }, 300));

  document.getElementById('history-filter-status').addEventListener('change', (e) => {
    offset = 0;
    loadHistory(document.getElementById('history-search').value, e.target.value);
  });

  window._openHistory = (id) => router.navigate(`/history/${id}`);
  window._deleteHistory = async (id) => {
    if (!confirm('Delete this analysis?')) return;
    try {
      await API.deleteHistory(id);
      showToast('Deleted');
      loadHistory();
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  await loadHistory();
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function debounce(fn, ms) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}
