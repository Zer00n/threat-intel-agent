import API from '../lib/api.js';
import { showToast } from '../lib/utils.js';

let currentSpaceId = localStorage.getItem('ti-asset-space-id') || 'default';
let currentImportType = 'csv';
let currentDetailHostId = null;

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
    summary.innerHTML = `<span>共 ${data.total || 0} 个资产</span><span>${serviceCount} 个服务</span>`;

    if (!hosts.length) {
      list.innerHTML = '<div class="empty-state"><h3>暂无资产</h3><p>当前空间还没有资产，可先导入 CSV 或 JSON。</p></div>';
      return;
    }

    list.innerHTML = hosts.map(renderHost).join('');
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

function wireAssetActions() {
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
