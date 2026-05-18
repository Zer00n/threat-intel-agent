import API from '../lib/api.js';
import { showToast } from '../lib/utils.js';

let currentSpaceId = localStorage.getItem('ti-asset-space-id') || 'default';
let currentImportType = 'csv';
let currentDetailHostId = null;
let selectedAssetIds = new Set();

export async function renderAssets(container) {
  container.innerHTML = `
    <div class="page-content">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--space-4);gap:var(--space-3);flex-wrap:wrap">
        <div>
          <h2 style="margin:0">资产管理</h2>
          <div style="font-size:var(--text-xs);color:var(--text-muted);margin-top:var(--space-1)">
            按空间维护资产清单，并基于本地 CVE 缓存识别服务风险。
          </div>
        </div>
        <div style="display:flex;gap:var(--space-2);align-items:center">
          <select class="ti-select" id="asset-space-select" style="width:190px"></select>
          <button class="ti-btn ti-btn--secondary ti-btn--sm" id="btn-analyze-space">整体分析</button>
          <button class="ti-btn ti-btn--secondary ti-btn--sm" id="btn-manual-asset">手动录入</button>
          <button class="ti-btn ti-btn--secondary ti-btn--sm" id="btn-import-assets">导入</button>
          <button class="ti-btn ti-btn--secondary ti-btn--sm" id="btn-refresh-assets">刷新</button>
        </div>
      </div>

      <div class="source-update-summary" style="display:flex;gap:var(--space-2);align-items:center;flex-wrap:wrap">
        <input id="asset-search" class="ti-input" placeholder="搜索 IP / 主机名 / 产品" style="width:260px">
        <select id="asset-env" class="ti-select" style="width:130px">
          <option value="">全部环境</option>
          <option value="prod">生产</option>
          <option value="test">测试</option>
          <option value="dev">开发</option>
          <option value="unknown">未知</option>
        </select>
        <select id="asset-criticality" class="ti-select" style="width:130px">
          <option value="">全部关键性</option>
          <option value="high">高</option>
          <option value="medium">中</option>
          <option value="low">低</option>
        </select>
      </div>

      <div id="assets-summary" style="display:flex;gap:var(--space-3);align-items:center;margin:var(--space-3) 0;color:var(--text-muted);font-size:var(--text-xs)"></div>
      <div id="assets-list">
        <div class="skeleton" style="height:56px;margin-bottom:8px"></div>
        <div class="skeleton" style="height:56px;margin-bottom:8px"></div>
      </div>
    </div>
  `;

  await loadSpaces();
  await loadAssets();

  document.getElementById('asset-space-select').addEventListener('change', async (e) => {
    currentSpaceId = e.target.value;
    localStorage.setItem('ti-asset-space-id', currentSpaceId);
    await loadAssets();
  });
  document.getElementById('btn-analyze-space').addEventListener('click', analyzeCurrentSpace);
  document.getElementById('btn-manual-asset').addEventListener('click', showManualAssetModal);
  document.getElementById('btn-refresh-assets').addEventListener('click', loadAssets);
  document.getElementById('btn-import-assets').addEventListener('click', showImportModal);
  document.getElementById('asset-search').addEventListener('input', debounce(loadAssets, 250));
  document.getElementById('asset-env').addEventListener('change', loadAssets);
  document.getElementById('asset-criticality').addEventListener('change', loadAssets);
}

async function analyzeCurrentSpace() {
  const btn = document.getElementById('btn-analyze-space');
  btn.disabled = true;
  btn.textContent = '分析中';
  try {
    const result = await API.analyzeAssetSpace(currentSpaceId);
    showToast('空间整体分析已完成');
    window.location.hash = `#/history/${result.analysis_id}`;
  } catch (err) {
    showToast(err.message || '空间整体分析失败', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = '整体分析';
  }
}

async function loadSpaces() {
  const select = document.getElementById('asset-space-select');
  const spaces = await API.assetSpaces();
  if (!spaces.find(s => s.id === currentSpaceId)) currentSpaceId = 'default';
  select.innerHTML = spaces.map(s => `
    <option value="${escapeAttr(s.id)}" ${s.id === currentSpaceId ? 'selected' : ''}>
      ${escapeHtml(s.name)} (${s.asset_count?.hosts || 0})
    </option>
  `).join('');
}

async function loadAssets() {
  currentDetailHostId = null;
  const list = document.getElementById('assets-list');
  const summary = document.getElementById('assets-summary');
  list.innerHTML = `
    <div class="skeleton" style="height:56px;margin-bottom:8px"></div>
    <div class="skeleton" style="height:56px"></div>
  `;

  const params = {
    space_id: currentSpaceId,
    page_size: 100,
    search: document.getElementById('asset-search')?.value || '',
    environment: document.getElementById('asset-env')?.value || '',
    criticality: document.getElementById('asset-criticality')?.value || '',
  };
  Object.keys(params).forEach(k => { if (!params[k]) delete params[k]; });

  try {
    const data = await API.assets(params);
    const hosts = data.items || [];
    const serviceCount = hosts.reduce((n, h) => n + (h.services?.length || 0), 0);
    const currentIds = new Set(hosts.map(h => h.id));
    selectedAssetIds = new Set([...selectedAssetIds].filter(id => currentIds.has(id)));
    summary.innerHTML = `
      <span>共 ${data.total || 0} 个资产</span>
      <span>${serviceCount} 个服务</span>
      ${hosts.length ? `
        <label style="display:flex;gap:var(--space-1);align-items:center">
          <input type="checkbox" id="asset-select-all" ${selectedAssetIds.size && selectedAssetIds.size === hosts.length ? 'checked' : ''}>
          <span>全选当前页</span>
        </label>
        <button class="ti-btn ti-btn--secondary ti-btn--sm" id="btn-delete-selected-assets" ${selectedAssetIds.size ? '' : 'disabled'}>批量删除 ${selectedAssetIds.size || ''}</button>
      ` : ''}
    `;

    if (!hosts.length) {
      list.innerHTML = '<div class="empty-state"><h3>暂无资产</h3><p>当前空间还没有资产，可先导入 CSV 或 JSON。</p></div>';
      return;
    }

    list.innerHTML = hosts.map(renderHost).join('');
    wireBulkAssetActions(hosts);
    wireAssetActions();
  } catch (err) {
    list.innerHTML = '<div class="empty-state"><h3>加载失败</h3><p>请稍后重试。</p></div>';
    showToast(err.message || '加载资产失败', 'error');
  }
}

function renderHost(host) {
  const cveCount = host.services.reduce((sum, s) => sum + (s.cve_matches?.filter(m => m.status === 'open').length || 0), 0);
  const maxRisk = Math.max(0, ...host.services.flatMap(s => (s.cve_matches || []).map(m => m.risk_score || 0)));
  const riskLabel = maxRisk >= 12 ? '高危' : maxRisk >= 6 ? '中危' : cveCount ? '低危' : '待识别';
  const riskCls = maxRisk >= 12 ? 'error' : maxRisk >= 6 ? 'warning' : cveCount ? 'success' : 'info';
  const title = host.ip || host.hostname || '未知资产';

  return `
    <div class="source-card" style="display:block">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:var(--space-3)">
        <div class="source-info" style="min-width:0">
          <input type="checkbox" data-select-asset="${escapeAttr(host.id)}" ${selectedAssetIds.has(host.id) ? 'checked' : ''} aria-label="选择资产 ${escapeAttr(title)}">
          <span class="ti-status-dot ti-status-dot--${cveCount ? 'failed' : 'waiting'}"></span>
          <div style="min-width:0">
            <strong class="ti-mono">${escapeHtml(title)}</strong>
            <div style="font-size:var(--text-xs);color:var(--text-secondary)">
              ${escapeHtml(host.hostname || '')} · ${envLabel(host.environment)} · ${criticalityLabel(host.criticality)}
            </div>
          </div>
        </div>
        <div style="display:flex;gap:var(--space-2);align-items:center;flex-shrink:0">
          <span class="ti-badge ti-badge--${riskCls}">${riskLabel}${cveCount ? ` ${cveCount}` : ''}</span>
          <button class="ti-btn ti-btn--secondary ti-btn--sm" data-open-asset="${escapeAttr(host.id)}">详情</button>
          <button class="ti-btn ti-btn--secondary ti-btn--sm" data-identify-host="${escapeAttr(host.id)}">识别资产</button>
          <button class="ti-btn ti-btn--danger ti-btn--sm" data-delete-asset="${escapeAttr(host.id)}" data-asset-title="${escapeAttr(title)}">删除</button>
        </div>
      </div>
      <div style="margin-top:var(--space-3);border-top:1px solid var(--border-subtle)">
        ${(host.services || []).map(s => renderService(host, s)).join('')}
      </div>
    </div>
  `;
}

function renderService(host, service) {
  const ports = (service.exposures || []).map(e => `${e.port}/${e.protocol} ${scopeLabel(e.exposure_scope)}`).join(' · ');
  return `
    <div style="display:grid;grid-template-columns:minmax(0,1fr) 110px 88px;gap:var(--space-3);align-items:center;padding:var(--space-3) 0;border-bottom:1px solid var(--border-subtle)">
      <div style="min-width:0">
        <strong>${escapeHtml(service.product)} ${escapeHtml(service.version || '')}</strong>
        <div class="ti-mono" style="font-size:var(--text-xs);color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
          ${escapeHtml(service.cpe || '未识别 CPE')} · ${escapeHtml(service.cpe_confidence || 'unknown')}
        </div>
        <div style="font-size:var(--text-xs);color:var(--text-muted)">${escapeHtml(ports)}</div>
      </div>
      <span style="font-size:var(--text-sm);color:var(--text-secondary)">${(service.cve_matches || []).length} 个 CVE</span>
      <button class="ti-btn ti-btn--secondary ti-btn--sm" data-identify-service="${escapeAttr(host.id)}:${escapeAttr(service.id)}">识别</button>
    </div>
  `;
}

function wireBulkAssetActions(hosts) {
  document.getElementById('asset-select-all')?.addEventListener('change', (e) => {
    if (e.target.checked) {
      hosts.forEach(host => selectedAssetIds.add(host.id));
    } else {
      hosts.forEach(host => selectedAssetIds.delete(host.id));
    }
    renderSelectionState(hosts);
  });
  document.getElementById('btn-delete-selected-assets')?.addEventListener('click', () => {
    const ids = [...selectedAssetIds];
    if (!ids.length) return;
    showDeleteAssetsModal({
      title: `删除 ${ids.length} 个资产？`,
      body: '将删除选中的资产及其服务、暴露面和 CVE 命中记录。此操作不可撤销。',
      onConfirm: async () => {
        await API.batchDeleteAssets(ids);
        ids.forEach(id => selectedAssetIds.delete(id));
        showToast('已删除选中资产');
        await loadSpaces();
        await loadAssets();
      },
    });
  });
}

function wireAssetActions() {
  document.querySelectorAll('[data-select-asset]').forEach(input => {
    input.addEventListener('change', (e) => {
      if (e.target.checked) selectedAssetIds.add(input.dataset.selectAsset);
      else selectedAssetIds.delete(input.dataset.selectAsset);
      const hosts = [...document.querySelectorAll('[data-select-asset]')].map(item => ({ id: item.dataset.selectAsset }));
      renderSelectionState(hosts);
    });
  });
  document.querySelectorAll('[data-delete-asset]').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      const hostId = btn.dataset.deleteAsset;
      showDeleteAssetsModal({
        title: '删除这个资产？',
        body: `将删除 ${btn.dataset.assetTitle || '该资产'} 及其服务、暴露面和 CVE 命中记录。此操作不可撤销。`,
        onConfirm: async () => {
          await API.deleteAsset(hostId);
          selectedAssetIds.delete(hostId);
          showToast('资产已删除');
          await loadSpaces();
          await loadAssets();
        },
      });
    });
  });
  document.querySelectorAll('[data-open-asset]').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      await showAssetDetail(btn.dataset.openAsset);
    });
  });
  document.querySelectorAll('[data-identify-service]').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      const [hostId, serviceId] = btn.dataset.identifyService.split(':');
      btn.disabled = true;
      try {
        const result = await API.identifyService(hostId, serviceId);
        showIdentifyResult(result);
        await loadSpaces();
        await loadAssets();
      } catch (err) {
        showToast(err.message || '识别失败', 'error');
      } finally {
        btn.disabled = false;
      }
    });
  });
  document.querySelectorAll('[data-identify-host]').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      btn.disabled = true;
      try {
        await API.identifyHost(btn.dataset.identifyHost);
        showToast('资产识别完成');
        await loadSpaces();
        await loadAssets();
      } catch (err) {
        showToast(err.message || '识别失败', 'error');
      } finally {
        btn.disabled = false;
      }
    });
  });
}

function renderSelectionState(hosts) {
  document.querySelectorAll('[data-select-asset]').forEach(input => {
    input.checked = selectedAssetIds.has(input.dataset.selectAsset);
  });
  const currentIds = hosts.map(host => host.id);
  const selectedOnPage = currentIds.filter(id => selectedAssetIds.has(id)).length;
  const selectAll = document.getElementById('asset-select-all');
  if (selectAll) {
    selectAll.checked = currentIds.length > 0 && selectedOnPage === currentIds.length;
    selectAll.indeterminate = selectedOnPage > 0 && selectedOnPage < currentIds.length;
  }
  const deleteBtn = document.getElementById('btn-delete-selected-assets');
  if (deleteBtn) {
    deleteBtn.disabled = selectedAssetIds.size === 0;
    deleteBtn.textContent = `批量删除 ${selectedAssetIds.size || ''}`.trim();
  }
}

function showDeleteAssetsModal({ title, body, onConfirm }) {
  const overlay = document.createElement('div');
  overlay.className = 'ti-modal-backdrop';
  overlay.setAttribute('data-open', '');
  overlay.innerHTML = `
    <div class="ti-modal">
      <div class="ti-modal__header">
        <h3 class="ti-modal__title">${escapeHtml(title)}</h3>
        <button class="ti-btn ti-btn--ghost ti-btn--sm ti-modal__close">关闭</button>
      </div>
      <div class="ti-modal__body">
        <p style="margin:0;color:var(--text-secondary)">${escapeHtml(body)}</p>
      </div>
      <div class="ti-modal__footer">
        <button class="ti-btn ti-btn--secondary" id="asset-delete-cancel">取消</button>
        <button class="ti-btn ti-btn--danger" id="asset-delete-confirm">确认删除</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  const close = () => overlay.remove();
  overlay.querySelector('.ti-modal__close').addEventListener('click', close);
  overlay.querySelector('#asset-delete-cancel').addEventListener('click', close);
  overlay.querySelector('#asset-delete-confirm').addEventListener('click', async () => {
    const btn = overlay.querySelector('#asset-delete-confirm');
    btn.disabled = true;
    try {
      await onConfirm();
      close();
    } catch (err) {
      showToast(err.message || '删除失败', 'error');
      btn.disabled = false;
    }
  });
}

async function showAssetDetail(hostId) {
  currentDetailHostId = hostId;
  const list = document.getElementById('assets-list');
  const summary = document.getElementById('assets-summary');
  list.innerHTML = `
    <div class="skeleton" style="height:90px;margin-bottom:8px"></div>
    <div class="skeleton" style="height:160px"></div>
  `;
  try {
    const host = await API.assetDetail(hostId);
    const stats = assetRiskStats(host);
    summary.innerHTML = `
      <button class="ti-btn ti-btn--secondary ti-btn--sm" id="asset-detail-back">返回列表</button>
      <span>${escapeHtml(host.ip || host.hostname || '未知资产')}</span>
      <span>${stats.open} 个未处置 CVE</span>
    `;
    list.innerHTML = renderAssetDetail(host, stats);
    document.getElementById('asset-detail-back').addEventListener('click', loadAssets);
    wireAssetDetailActions(host.id);
  } catch (err) {
    list.innerHTML = '<div class="empty-state"><h3>加载失败</h3><p>请稍后重试。</p></div>';
    showToast(err.message || '加载资产详情失败', 'error');
  }
}

function renderAssetDetail(host, stats) {
  const title = host.ip || host.hostname || '未知资产';
  return `
    <div class="source-card" style="display:block">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:var(--space-3);flex-wrap:wrap">
        <div class="source-info" style="min-width:0">
          <span class="ti-status-dot ti-status-dot--${stats.open ? 'failed' : 'waiting'}"></span>
          <div style="min-width:0">
            <strong class="ti-mono">${escapeHtml(title)}</strong>
            <div style="font-size:var(--text-xs);color:var(--text-secondary)">
              ${escapeHtml(host.hostname || '')} · ${envLabel(host.environment)} · ${criticalityLabel(host.criticality)}
            </div>
          </div>
        </div>
        <button class="ti-btn ti-btn--secondary ti-btn--sm" data-detail-identify-host="${escapeAttr(host.id)}">重新识别</button>
      </div>

      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:var(--space-3);margin-top:var(--space-4)">
        ${detailMetric('服务', host.services.length)}
        ${detailMetric('未处置 CVE', stats.open)}
        ${detailMetric('高危', stats.high)}
        ${detailMetric('中危', stats.medium)}
      </div>

      <div class="source-update-summary" style="margin-top:var(--space-4);display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:var(--space-3)">
        ${detailField('操作系统', `${host.os_name || '-'} ${host.os_version || ''}`)}
        ${detailField('负责人', host.owner || '-')}
        ${detailField('来源', host.source || '-')}
        ${detailField('首次发现', host.first_seen_at || '-')}
        ${detailField('最近发现', host.last_seen_at || '-')}
        ${detailField('标签', (host.tags || []).join(', ') || '-')}
      </div>

      ${host.notes ? `<p style="font-size:var(--text-sm);color:var(--text-secondary);margin:var(--space-4) 0 0">${escapeHtml(host.notes)}</p>` : ''}
    </div>

    <div style="margin-top:var(--space-3)">
      ${(host.services || []).map(service => renderDetailService(host, service)).join('') || '<div class="empty-state"><h3>暂无服务</h3></div>'}
    </div>
  `;
}

function renderDetailService(host, service) {
  const matches = service.cve_matches || [];
  const ports = (service.exposures || []).map(e => `${e.port}/${e.protocol} ${scopeLabel(e.exposure_scope)}`).join(' · ') || '-';
  return `
    <div class="source-card" style="display:block">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:var(--space-3);flex-wrap:wrap">
        <div style="min-width:0">
          <strong>${escapeHtml(service.product)} ${escapeHtml(service.version || '')}</strong>
          <div class="ti-mono" style="font-size:var(--text-xs);color:var(--text-muted);margin-top:var(--space-1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
            ${escapeHtml(service.cpe || '未识别 CPE')}
          </div>
          <div style="font-size:var(--text-xs);color:var(--text-muted);margin-top:var(--space-1)">
            ${escapeHtml(ports)} · ${escapeHtml(service.service_type || 'other')} · ${escapeHtml(service.cpe_confidence || 'unknown')}
          </div>
        </div>
        <button class="ti-btn ti-btn--secondary ti-btn--sm" data-detail-identify-service="${escapeAttr(host.id)}:${escapeAttr(service.id)}">识别服务</button>
      </div>
      <div style="margin-top:var(--space-3);border-top:1px solid var(--border-subtle)">
        ${matches.map(renderDetailMatch).join('') || '<p style="font-size:var(--text-sm);color:var(--text-muted);margin:var(--space-3) 0 0">暂无 CVE 命中。</p>'}
      </div>
    </div>
  `;
}

function renderDetailMatch(match) {
  const badge = match.risk_level === 'high' ? 'error' : match.risk_level === 'medium' ? 'warning' : 'success';
  return `
    <div style="padding:var(--space-3) 0;border-bottom:1px solid var(--border-subtle)">
      <div style="display:flex;justify-content:space-between;gap:var(--space-3);align-items:center;flex-wrap:wrap">
        <div style="display:flex;gap:var(--space-2);align-items:center;flex-wrap:wrap">
          <strong>${escapeHtml(match.cve_id)}</strong>
          <span class="ti-badge ti-badge--${badge}">${escapeHtml(match.risk_level)} · ${match.risk_score ?? '-'}</span>
          <span class="ti-badge ti-badge--info">${escapeHtml(statusLabel(match.status))}</span>
        </div>
        <span style="font-size:var(--text-xs);color:var(--text-muted)">CVSS ${match.cvss_score ?? '-'} · KEV ${match.kev_flag ? '是' : '否'} · EPSS ${match.epss_score ?? '-'}</span>
      </div>
      <p style="font-size:var(--text-sm);color:var(--text-secondary);margin:var(--space-2) 0 0">${escapeHtml(match.summary || '')}</p>
      <div style="display:grid;grid-template-columns:150px minmax(0,1fr) 76px;gap:var(--space-2);align-items:center;margin-top:var(--space-3)">
        <select class="ti-select" data-cve-status="${escapeAttr(match.id)}">
          ${['open', 'acknowledged', 'mitigated', 'false_positive'].map(status => `
            <option value="${status}" ${status === match.status ? 'selected' : ''}>${statusLabel(status)}</option>
          `).join('')}
        </select>
        <input class="ti-input" data-cve-note="${escapeAttr(match.id)}" value="${escapeAttr(match.user_notes || '')}" placeholder="处置备注">
        <button class="ti-btn ti-btn--secondary ti-btn--sm" data-save-cve-match="${escapeAttr(match.id)}">保存</button>
      </div>
    </div>
  `;
}

function wireAssetDetailActions(hostId) {
  document.querySelectorAll('[data-detail-identify-service]').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      const [itemHostId, serviceId] = btn.dataset.detailIdentifyService.split(':');
      btn.disabled = true;
      try {
        await API.identifyService(itemHostId, serviceId);
        showToast('服务识别完成');
        await showAssetDetail(itemHostId);
      } catch (err) {
        showToast(err.message || '识别失败', 'error');
      } finally {
        btn.disabled = false;
      }
    });
  });
  document.querySelectorAll('[data-detail-identify-host]').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      btn.disabled = true;
      try {
        await API.identifyHost(hostId);
        showToast('资产识别完成');
        await showAssetDetail(hostId);
      } catch (err) {
        showToast(err.message || '识别失败', 'error');
      } finally {
        btn.disabled = false;
      }
    });
  });
  document.querySelectorAll('[data-save-cve-match]').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      const matchId = btn.dataset.saveCveMatch;
      const status = document.querySelector(`[data-cve-status="${cssEscape(matchId)}"]`)?.value || 'open';
      const userNotes = document.querySelector(`[data-cve-note="${cssEscape(matchId)}"]`)?.value || '';
      btn.disabled = true;
      try {
        await API.updateAssetCveMatch(matchId, { status, user_notes: userNotes });
        showToast('CVE 状态已更新');
        await showAssetDetail(hostId);
        await loadSpaces();
      } catch (err) {
        showToast(err.message || '更新状态失败', 'error');
      } finally {
        btn.disabled = false;
      }
    });
  });
}

function assetRiskStats(host) {
  const matches = (host.services || []).flatMap(s => s.cve_matches || []);
  const open = matches.filter(m => m.status === 'open');
  return {
    total: matches.length,
    open: open.length,
    high: open.filter(m => m.risk_level === 'high').length,
    medium: open.filter(m => m.risk_level === 'medium').length,
    low: open.filter(m => m.risk_level === 'low').length,
  };
}

function detailMetric(label, value) {
  return `
    <div style="border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:var(--space-3);min-width:0">
      <div style="font-size:var(--text-xs);color:var(--text-muted)">${escapeHtml(label)}</div>
      <strong style="font-size:var(--text-lg)">${escapeHtml(String(value))}</strong>
    </div>
  `;
}

function detailField(label, value) {
  return `
    <div style="min-width:0">
      <div style="font-size:var(--text-xs);color:var(--text-muted)">${escapeHtml(label)}</div>
      <div style="font-size:var(--text-sm);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escapeHtml(value || '-')}</div>
    </div>
  `;
}

function showManualAssetModal() {
  const overlay = document.createElement('div');
  overlay.className = 'ti-modal-backdrop';
  overlay.setAttribute('data-open', '');
  overlay.innerHTML = `
    <div class="ti-modal ti-modal--lg">
      <div class="ti-modal__header">
        <h3 class="ti-modal__title">手动录入资产</h3>
        <button class="ti-btn ti-btn--ghost ti-btn--sm ti-modal__close">关闭</button>
      </div>
      <div class="ti-modal__body">
        <div style="font-size:var(--text-xs);color:var(--text-muted);margin-bottom:var(--space-3)">
          至少填写 IP 或主机名，并录入一个服务和端口。服务版本只填干净版本号；nmap 或探测原文请放到原始 Banner。
        </div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:var(--space-3)">
          ${manualField('IP', '<input class="ti-input" id="manual-ip" placeholder="如 192.168.1.100；IP 和主机名二选一必填">')}
          ${manualField('主机名', '<input class="ti-input" id="manual-hostname" placeholder="如 web-prod-01；IP 为空时用主机名合并">')}
          ${manualField('环境', `
            <select class="ti-select" id="manual-environment">
              <option value="unknown">未知</option>
              <option value="prod">生产</option>
              <option value="test">测试</option>
              <option value="dev">开发</option>
            </select>
          `)}
          ${manualField('关键性', `
            <select class="ti-select" id="manual-criticality">
              <option value="medium">中</option>
              <option value="high">高</option>
              <option value="low">低</option>
            </select>
          `)}
          ${manualField('操作系统', '<input class="ti-input" id="manual-os-name" placeholder="如 Ubuntu / CentOS / Windows Server">')}
          ${manualField('系统版本', '<input class="ti-input" id="manual-os-version" placeholder="如 22.04 / 7.9 / 2019">')}
          ${manualField('负责人', '<input class="ti-input" id="manual-owner" placeholder="如 secops / app-team">')}
          ${manualField('标签', '<input class="ti-input" id="manual-tags" placeholder="逗号分隔，如 web, core, public">')}
        </div>

        <div style="height:1px;background:var(--border-subtle);margin:var(--space-4) 0"></div>

        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:var(--space-3)">
          ${manualField('产品/服务名', '<input class="ti-input" id="manual-product" placeholder="必填，如 nginx / tomcat / openssh">')}
          ${manualField('版本', '<input class="ti-input" id="manual-version" placeholder="只填版本号，如 1.18.0；不要粘贴整段 nmap 输出">')}
          ${manualField('厂商', '<input class="ti-input" id="manual-vendor" placeholder="选填，如 nginx / apache / openbsd / oracle">')}
          ${manualField('端口', '<input class="ti-input" id="manual-port" type="number" min="1" max="65535" placeholder="必填，如 80 / 443 / 3306">')}
          ${manualField('协议', `
            <select class="ti-select" id="manual-protocol">
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
            </select>
          `)}
          ${manualField('暴露范围', `
            <select class="ti-select" id="manual-exposure">
              <option value="unknown">未知</option>
              <option value="public">公网</option>
              <option value="internal">内网</option>
              <option value="isolated">隔离网</option>
            </select>
          `)}
        </div>

        <div style="display:grid;grid-template-columns:1fr;gap:var(--space-3);margin-top:var(--space-3)">
          ${manualField('标准 CPE', '<input class="ti-input ti-mono" id="manual-cpe" placeholder="选填，知道就填，如 cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*">')}
          ${manualField('原始 Banner', '<textarea class="ti-textarea ti-mono" id="manual-raw-banner" style="height:72px" placeholder="选填，可直接粘贴 nmap 或探测原文，如 OpenSSH 8.9p1 Ubuntu 3ubuntu0.6"></textarea>')}
          ${manualField('备注', '<textarea class="ti-textarea" id="manual-notes" style="height:72px" placeholder="选填，记录业务用途、来源、人工判断等"></textarea>')}
        </div>
      </div>
      <div class="ti-modal__footer">
        <button class="ti-btn ti-btn--primary" id="manual-submit">保存资产</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  const close = () => overlay.remove();
  overlay.querySelector('.ti-modal__close').addEventListener('click', close);
  overlay.querySelector('#manual-submit').addEventListener('click', async () => {
    const payload = readManualAssetPayload(overlay);
    if (!payload.ip && !payload.hostname) {
      showToast('请至少填写 IP 或主机名', 'error');
      return;
    }
    if (!payload.product) {
      showToast('请填写产品/服务名', 'error');
      return;
    }
    if (!payload.port) {
      showToast('请填写有效端口', 'error');
      return;
    }

    const btn = overlay.querySelector('#manual-submit');
    btn.disabled = true;
    try {
      const host = await API.createAsset(payload);
      showToast('资产已保存');
      close();
      await loadSpaces();
      await loadAssets();
      await showAssetDetail(host.id);
    } catch (err) {
      showToast(err.message || '保存资产失败', 'error');
    } finally {
      btn.disabled = false;
    }
  });
}

function manualField(label, control) {
  return `
    <label style="display:flex;flex-direction:column;gap:var(--space-1);min-width:0">
      <span style="font-size:var(--text-xs);color:var(--text-muted)">${label}</span>
      ${control}
    </label>
  `;
}

function readManualAssetPayload(root) {
  const value = id => root.querySelector(`#${id}`)?.value.trim() || '';
  const port = Number.parseInt(value('manual-port'), 10);
  return {
    space_id: currentSpaceId,
    ip: value('manual-ip') || null,
    hostname: value('manual-hostname') || null,
    os_name: value('manual-os-name') || null,
    os_version: value('manual-os-version') || null,
    environment: value('manual-environment') || 'unknown',
    criticality: value('manual-criticality') || 'medium',
    owner: value('manual-owner') || null,
    tags: value('manual-tags').split(',').map(item => item.trim()).filter(Boolean),
    notes: value('manual-notes') || null,
    product: value('manual-product'),
    version: value('manual-version') || null,
    vendor: value('manual-vendor') || null,
    cpe: value('manual-cpe') || null,
    raw_banner: value('manual-raw-banner') || null,
    port: Number.isFinite(port) ? port : null,
    protocol: value('manual-protocol') || 'tcp',
    exposure_scope: value('manual-exposure') || 'unknown',
  };
}

function showImportModal() {
  const overlay = document.createElement('div');
  overlay.className = 'ti-modal-backdrop';
  overlay.setAttribute('data-open', '');
  overlay.innerHTML = `
    <div class="ti-modal ti-modal--lg">
      <div class="ti-modal__header">
        <h3 class="ti-modal__title">导入资产</h3>
        <button class="ti-btn ti-btn--ghost ti-btn--sm ti-modal__close">关闭</button>
      </div>
      <div class="ti-modal__body">
        <div style="display:flex;gap:var(--space-2);align-items:center;margin-bottom:var(--space-3);flex-wrap:wrap">
          <select id="asset-import-type" class="ti-select" style="width:140px">
            <option value="csv">CSV</option>
            <option value="json">JSON</option>
            <option value="nmap">nmap XML</option>
          </select>
          <input id="asset-import-file" type="file" class="ti-input" accept=".csv,.json,.xml,application/json,text/csv,text/xml,application/xml" style="flex:1;min-width:240px">
        </div>
        <div class="source-update-summary" style="display:flex;gap:var(--space-2);align-items:center;flex-wrap:wrap;margin-bottom:var(--space-3)">
          <button class="ti-btn ti-btn--secondary ti-btn--sm" id="asset-download-csv-template">下载 CSV 模板</button>
          <button class="ti-btn ti-btn--secondary ti-btn--sm" id="asset-fill-json-example">填入 JSON 示例</button>
          <button class="ti-btn ti-btn--secondary ti-btn--sm" id="asset-fill-nmap-example">填入 nmap XML 示例</button>
          <span id="asset-import-help" style="font-size:var(--text-xs);color:var(--text-muted)">CSV 一行代表一个服务端口；JSON 使用平台标准结构；nmap XML 支持 nmap -oX 输出。</span>
        </div>
        <textarea id="asset-import-content" class="ti-textarea ti-mono" style="width:100%;height:260px" placeholder="选择文件或粘贴 CSV / JSON / nmap XML 内容"></textarea>
      </div>
      <div class="ti-modal__footer">
        <button class="ti-btn ti-btn--primary" id="asset-import-submit">导入</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  const close = () => overlay.remove();
  overlay.querySelector('.ti-modal__close').addEventListener('click', close);
  overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
  overlay.querySelector('#asset-import-type').value = currentImportType;
  overlay.querySelector('#asset-import-type').addEventListener('change', e => {
    currentImportType = e.target.value;
    updateImportHelp(overlay);
  });
  updateImportHelp(overlay);
  overlay.querySelector('#asset-download-csv-template').addEventListener('click', async () => {
    try {
      const template = await API.assetCsvTemplate();
      downloadTextFile(template.filename || 'asset-import-template.csv', template.content || '');
      currentImportType = 'csv';
      overlay.querySelector('#asset-import-type').value = currentImportType;
      updateImportHelp(overlay);
    } catch (err) {
      showToast(err.message || '下载模板失败', 'error');
    }
  });
  overlay.querySelector('#asset-fill-json-example').addEventListener('click', () => {
    currentImportType = 'json';
    overlay.querySelector('#asset-import-type').value = currentImportType;
    overlay.querySelector('#asset-import-content').value = JSON.stringify(assetJsonExample(), null, 2);
    updateImportHelp(overlay);
  });
  overlay.querySelector('#asset-fill-nmap-example').addEventListener('click', () => {
    currentImportType = 'nmap';
    overlay.querySelector('#asset-import-type').value = currentImportType;
    overlay.querySelector('#asset-import-content').value = assetNmapExample();
    updateImportHelp(overlay);
  });
  overlay.querySelector('#asset-import-file').addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const lower = file.name.toLowerCase();
    currentImportType = lower.endsWith('.json') ? 'json' : lower.endsWith('.xml') ? 'nmap' : 'csv';
    overlay.querySelector('#asset-import-type').value = currentImportType;
    overlay.querySelector('#asset-import-content').value = await file.text();
  });
  overlay.querySelector('#asset-import-submit').addEventListener('click', async () => {
    const content = overlay.querySelector('#asset-import-content').value;
    const filename = overlay.querySelector('#asset-import-file').files?.[0]?.name || `browser-paste.${currentImportType}`;
    try {
      const payload = { space_id: currentSpaceId, content, mode: 'merge', filename };
      const result = currentImportType === 'json'
        ? await API.importAssetsJsonText(payload)
        : currentImportType === 'nmap'
          ? await API.importAssetsNmapText(payload)
          : await API.importAssetsCsvText(payload);
      const summary = result.summary || {};
      showToast(`导入完成：新增 ${summary.hosts_created || 0}，更新 ${summary.hosts_updated || 0}，失败 ${summary.failed_rows || 0}`);
      close();
      await loadSpaces();
      await loadAssets();
    } catch (err) {
      showToast(err.message || '导入失败', 'error');
    }
  });
}

function updateImportHelp(root) {
  const help = root.querySelector('#asset-import-help');
  if (!help) return;
  help.textContent = {
    csv: 'CSV 一行代表一个 Service + Exposure；tags 用逗号分隔并加双引号，IP 和主机名至少填一个。',
    json: 'JSON 使用平台标准结构：hosts 数组下包含 os、services、exposures，适合 CMDB 导出后转换。',
    nmap: 'nmap XML 支持 nmap -oX 输出；如果 XML 内有 cpe 标签，将直接作为高置信度 CPE 采用。',
  }[currentImportType] || '选择文件或粘贴内容后导入。';
}

function downloadTextFile(filename, content) {
  const blob = new Blob([content], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function assetJsonExample() {
  return {
    version: '1.0',
    source: 'manual_export',
    exported_at: '2026-05-18T10:00:00Z',
    hosts: [{
      ip: '192.168.1.100',
      hostname: 'web-prod-01',
      os: {
        name: 'Ubuntu',
        version: '22.04',
        cpe: 'cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*',
      },
      environment: 'prod',
      criticality: 'high',
      owner: 'secops',
      tags: ['web', 'core'],
      services: [{
        product: 'nginx',
        version: '1.18.0',
        vendor: 'nginx',
        cpe: 'cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*',
        exposures: [
          { port: 80, protocol: 'tcp', scope: 'public' },
          { port: 443, protocol: 'tcp', scope: 'public' },
        ],
      }],
    }],
  };
}

function assetNmapExample() {
  return `<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="192.168.1.100" addrtype="ipv4"/>
    <hostnames><hostname name="web-prod-01"/></hostnames>
    <os><osmatch name="Linux 5.x" accuracy="98"/></os>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0">
          <cpe>cpe:/a:nginx:nginx:1.18.0</cpe>
        </service>
      </port>
    </ports>
  </host>
</nmaprun>`;
}

function showIdentifyResult(result) {
  const overlay = document.createElement('div');
  overlay.className = 'ti-modal-backdrop';
  overlay.setAttribute('data-open', '');
  overlay.innerHTML = `
    <div class="ti-modal ti-modal--lg">
      <div class="ti-modal__header">
        <h3 class="ti-modal__title">${escapeHtml(result.service.product)} ${escapeHtml(result.service.version || '')} 风险识别</h3>
        <button class="ti-btn ti-btn--ghost ti-btn--sm ti-modal__close">关闭</button>
      </div>
      <div class="ti-modal__body">
        <p style="color:var(--text-muted)">共发现 ${result.statistics.total} 个 CVE。</p>
        ${(result.matches || []).map(m => `
          <div style="padding:var(--space-3) 0;border-bottom:1px solid var(--border-subtle)">
            <div style="display:flex;gap:var(--space-2);align-items:center;flex-wrap:wrap">
              <strong>${escapeHtml(m.cve_id)}</strong>
              <span class="ti-badge ti-badge--${m.risk_level === 'high' ? 'error' : m.risk_level === 'medium' ? 'warning' : 'success'}">${escapeHtml(m.risk_level)} · ${m.risk_score}</span>
            </div>
            <div style="font-size:var(--text-xs);color:var(--text-muted);margin-top:var(--space-1)">CVSS ${m.cvss_score ?? '-'} · KEV ${m.kev_flag ? '是' : '否'} · EPSS ${m.epss_score ?? '-'}</div>
            <p style="font-size:var(--text-sm);margin-bottom:0">${escapeHtml(m.summary || '')}</p>
          </div>
        `).join('') || '<p style="color:var(--text-muted)">未命中本地 CVE 缓存，或 NVD 暂时不可用。</p>'}
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  overlay.querySelector('.ti-modal__close').addEventListener('click', () => overlay.remove());
}

function envLabel(value) {
  return ({ prod: '生产', test: '测试', dev: '开发', unknown: '未知' })[value] || value || '未知';
}

function criticalityLabel(value) {
  return ({ high: '高关键性', medium: '中关键性', low: '低关键性' })[value] || value || '未知关键性';
}

function scopeLabel(scope) {
  return ({ public: '公网', internal: '内网', isolated: '隔离', unknown: '未知' })[scope] || scope;
}

function statusLabel(status) {
  return ({
    open: '未处置',
    acknowledged: '已确认',
    mitigated: '已缓解',
    false_positive: '误报',
  })[status] || status || '未知';
}

function debounce(fn, ms) {
  let t;
  return () => { clearTimeout(t); t = setTimeout(fn, ms); };
}

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function escapeAttr(str) {
  return escapeHtml(str).replace(/"/g, '&quot;');
}

function cssEscape(value) {
  if (window.CSS?.escape) return window.CSS.escape(value);
  return String(value).replace(/["\\]/g, '\\$&');
}
