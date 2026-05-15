import API from '../lib/api.js';
import { formatDate, statusBadge, tlpBadge, showToast } from '../lib/utils.js';
import { router } from '../lib/router.js';

let _selectedIds = new Set();

export async function renderHistoryList(container) {
  container.innerHTML = `
    <div class="page-content">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--space-4)">
      <h2>分析历史</h2>
      <div style="display:flex;gap:var(--space-2);align-items:center">
        <button id="batch-delete-btn" class="ti-btn ti-btn--danger ti-btn--sm" type="button" style="display:none" onclick="window._batchDelete()">批量删除</button>
        <button id="batch-export-btn" class="ti-btn ti-btn--secondary ti-btn--sm" type="button" style="display:none" onclick="window._batchExport()">批量导出</button>
        <input id="history-search" class="ti-input" placeholder="搜索..." style="width:220px">
        <select id="history-filter-status" class="ti-select" style="width:120px">
          <option value="">全部状态</option>
          <option value="completed">已完成</option>
          <option value="failed">失败</option>
          <option value="stopped">已停止</option>
        </select>
      </div>
    </div>
    <div id="history-list">
      <div class="skeleton" style="height:56px;margin-bottom:8px"></div>
      <div class="skeleton" style="height:56px;margin-bottom:8px"></div>
      <div class="skeleton" style="height:56px"></div>
    </div>
    <div id="history-pagination" style="display:flex;justify-content:center;gap:var(--space-2);margin-top:var(--space-4)"></div>
    </div>
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
    _selectedIds = new Set();
    _updateBatchBtn();
    if (!data.items.length) {
      list.innerHTML = '<div class="empty-state"><h3>暂无分析记录</h3><p>从工作区开始新的分析</p></div>';
      return;
    }

    list.innerHTML = `
      <div style="display:flex;align-items:center;gap:var(--space-2);padding:var(--space-2) 0;border-bottom:1px solid var(--border-hairline);font-size:var(--text-xs);color:var(--text-muted)">
        <input type="checkbox" id="select-all" onchange="window._toggleSelectAll(this.checked)">
        <span>全选</span>
        <span id="selected-count"></span>
      </div>
      ${data.items.map(item => _renderItem(item)).join('')}
    `;

    // Pagination
    const totalPages = Math.ceil(data.total / limit);
    const currentPage = Math.floor(offset / limit) + 1;
    const pagination = document.getElementById('history-pagination');
    pagination.innerHTML = '';
    if (totalPages > 1) {
      for (let i = 1; i <= Math.min(totalPages, 10); i++) {
        const btn = document.createElement('button');
        btn.className = `ti-btn ti-btn--sm ${i === currentPage ? 'ti-btn--primary' : 'ti-btn--secondary'}`;
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

  window._openHistory = (id, status = '') => {
    if (status === 'running') {
      sessionStorage.setItem('ti-active-task-id', id);
      router.navigate('/');
      return;
    }
    router.navigate(`/history/${id}`);
  };
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

  window._batchDelete = async () => {
    const ids = [..._selectedIds];
    if (ids.length === 0) return;
    if (!confirm(`确定删除选中的 ${ids.length} 条历史记录？运行中的任务会被跳过。`)) return;

    try {
      const result = await API.batchDeleteHistory(ids);
      const deletedCount = result.deleted?.length || 0;
      if (deletedCount === ids.length) {
        showToast(`已删除 ${deletedCount} 条历史记录`);
      } else {
        showToast(`已删除 ${deletedCount} 条历史记录，${ids.length - deletedCount} 条未删除`);
      }
      _selectedIds = new Set();
      offset = 0;
      await loadHistory(
        document.getElementById('history-search').value,
        document.getElementById('history-filter-status').value,
      );
    } catch (err) {
      showToast(err.message || '批量删除失败', 'error');
    }
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

function _renderItem(item) {
  const statusCls = item.status === 'completed' ? 'completed'
    : item.status === 'failed' ? 'failed'
    : item.status === 'stopped' ? 'interrupted'
    : item.status === 'running' ? 'running'
    : 'waiting';

  const metaParts = [
    item.intent ? `<span class="ti-badge ti-badge--info">${item.intent}</span>` : '',
    tlpBadge(item.tlp),
    item.overall_confidence ? `<span style="font-size:var(--text-xs);color:var(--text-secondary)">置信度：${item.overall_confidence}</span>` : '',
    `<span style="font-size:var(--text-xs);color:var(--text-muted)">${formatDate(item.created_at)}</span>`,
    item.duration_s ? `<span style="font-size:var(--text-xs);color:var(--text-muted)">${item.duration_s}秒</span>` : '',
    item.cost_usd ? `<span style="font-size:var(--text-xs);color:var(--text-muted)">¥${item.cost_usd.toFixed(4)}</span>` : '',
  ].filter(Boolean).join('');

  return `
    <div class="source-card" style="cursor:pointer;gap:var(--space-3)" onclick="window._toggleSelect('${item.id}', this.querySelector('.batch-check').checked = !this.querySelector('.batch-check').checked)">
      <div class="source-info" style="flex:1;min-width:0">
        <input type="checkbox" class="batch-check" data-id="${item.id}" onclick="event.stopPropagation();window._toggleSelect('${item.id}', this.checked)" style="flex-shrink:0">
        <span class="ti-status-dot ti-status-dot--${statusCls}"></span>
        <div style="min-width:0">
          <div style="font-weight:600;font-size:var(--text-sm);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escapeHtml(item.query)}</div>
          <div style="display:flex;gap:var(--space-2);flex-wrap:wrap;align-items:center;margin-top:var(--space-1)">
            ${metaParts}
          </div>
        </div>
      </div>
      <div style="display:flex;gap:var(--space-2);align-items:center;flex-shrink:0">
        <span class="ti-badge ti-badge--${statusCls === 'completed' ? 'success' : statusCls === 'failed' ? 'error' : statusCls === 'running' ? 'info' : 'warning'}">${statusLabel(item.status)}</span>
      </div>
    </div>
  `;
}

function statusLabel(status) {
  const map = { running: '运行中', completed: '已完成', failed: '失败', stopped: '已停止', timeout: '超时', budget_exceeded: '预算超限' };
  return map[status] || status;
}

function _updateBatchBtn() {
  const exportBtn = document.getElementById('batch-export-btn');
  const deleteBtn = document.getElementById('batch-delete-btn');
  const cnt = document.getElementById('selected-count');
  const selectAll = document.getElementById('select-all');
  const checks = [...document.querySelectorAll('.batch-check')];
  const visible = _selectedIds.size > 0 ? 'inline-flex' : 'none';
  if (exportBtn) exportBtn.style.display = visible;
  if (deleteBtn) deleteBtn.style.display = visible;
  if (cnt) cnt.textContent = _selectedIds.size > 0 ? `已选 ${_selectedIds.size} 条` : '';
  if (selectAll) {
    selectAll.checked = checks.length > 0 && checks.every(cb => cb.checked);
    selectAll.indeterminate = checks.some(cb => cb.checked) && !selectAll.checked;
  }
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
