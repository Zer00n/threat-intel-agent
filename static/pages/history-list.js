import API from '../lib/api.js';
import { formatDate, statusBadge, tlpBadge, showToast } from '../lib/utils.js';
import { router } from '../lib/router.js';

let _selectedIds = new Set();

export async function renderHistoryList(container) {
  container.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--space-4)">
      <h2>分析历史</h2>
      <div style="display:flex;gap:var(--space-2);align-items:center">
        <button id="batch-export-btn" class="btn btn-sm" style="display:none" onclick="window._batchExport()">批量导出</button>
        <input id="history-search" class="input" placeholder="搜索..." style="width:250px">
        <select id="history-filter-status" class="input" style="width:120px">
          <option value="">全部状态</option>
          <option value="completed">已完成</option>
          <option value="failed">失败</option>
          <option value="stopped">已停止</option>
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
      showToast('加载历史记录失败', 'error');
    }
  };

  const renderList = (data) => {
    const list = document.getElementById('history-list');
    if (!data.items.length) {
      list.innerHTML = '<div class="empty-state"><h3>暂无分析记录</h3><p>从工作区开始新的分析</p></div>';
      return;
    }

    _selectedIds = new Set();
    list.innerHTML = `
      <div style="display:flex;align-items:center;gap:var(--space-2);padding:var(--space-2) 0;border-bottom:1px solid var(--border-hairline);font-size:var(--text-xs);color:var(--text-muted)">
        <input type="checkbox" id="select-all" onchange="window._toggleSelectAll(this.checked)">
        <span>全选</span>
        <span id="selected-count"></span>
      </div>
      ${data.items.map(item => `
        <div class="history-item" style="display:flex;gap:var(--space-2);align-items:flex-start">
          <input type="checkbox" class="batch-check" data-id="${item.id}" onchange="window._toggleSelect('${item.id}', this.checked)" style="margin-top:var(--space-3)">
          <div style="flex:1;cursor:pointer" onclick="window._openHistory('${item.id}')">
            <div class="history-item-header">
              <span class="history-item-query">${escapeHtml(item.query)}</span>
              <span>${statusBadge(item.status)}</span>
            </div>
            <div class="history-item-meta">
              ${item.intent ? `<span class="badge badge-info">${item.intent}</span>` : ''}
              ${tlpBadge(item.tlp)}
              ${item.overall_confidence ? `<span>置信度：${item.overall_confidence}</span>` : ''}
              <span>${formatDate(item.created_at)}</span>
              ${item.duration_s ? `<span>${item.duration_s}秒</span>` : ''}
              ${item.cost_usd ? `<span>$${item.cost_usd.toFixed(2)}</span>` : ''}
            </div>
          </div>
        </div>
      `).join('')}
    `;

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
    if (!confirm('确定删除此分析？')) return;
    try {
      await API.deleteHistory(id);
      showToast('已删除');
      loadHistory();
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  window._toggleSelectAll = (checked) => {
    document.querySelectorAll('.batch-check').forEach(cb => {
      cb.checked = checked;
      _selectedIds[checked ? 'add' : 'delete'](cb.dataset.id);
    });
    _updateBatchBtn();
  };

  window._toggleSelect = (id, checked) => {
    _selectedIds[checked ? 'add' : 'delete'](id);
    _updateBatchBtn();
  };

  window._batchExport = async () => {
    if (_selectedIds.size === 0) return;
    showToast(`正在导出 ${_selectedIds.size} 条记录...`);
    try {
      const resp = await fetch('/export/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: [..._selectedIds], formats: ['md', 'stix', 'iocs', 'sigma'] }),
      });
      if (!resp.ok) throw new Error(`导出失败: ${resp.status}`);
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `ti-batch-${new Date().toISOString().slice(0,10)}.zip`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      showToast('批量导出完成');
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  await loadHistory();
}

function _updateBatchBtn() {
  const btn = document.getElementById('batch-export-btn');
  const cnt = document.getElementById('selected-count');
  if (btn) btn.style.display = _selectedIds.size > 0 ? 'inline-flex' : 'none';
  if (cnt) cnt.textContent = _selectedIds.size > 0 ? `已选 ${_selectedIds.size} 条` : '';
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
