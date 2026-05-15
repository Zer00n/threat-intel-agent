import API from '../lib/api.js';
import { formatDate, formatDuration, statusBadge, confidenceBadge, tlpBadge, iocChip, copyToClipboard, showToast, defang } from '../lib/utils.js';
import { getTechniqueNameZh, getTacticNameZh } from '../lib/attck-i18n.js';

export async function renderHistoryDetail(container, id) {
  container.innerHTML = '<div class="skeleton" style="height:400px"></div>';

  try {
    const data = await API.historyDetail(id);
    if (data.status === 'running') {
      sessionStorage.setItem('ti-active-task-id', data.id);
      window.location.hash = '#/';
      return;
    }
    renderDetail(container, data);
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><h3>未找到分析记录</h3><p>${err.message}</p></div>`;
  }
}

function renderDetail(container, data) {
  container.innerHTML = `
    <div class="report-page">
      <!-- 元信息条 -->
      <section class="report-meta">
        <div class="report-meta__inner">
          <div class="report-meta__title-row">
            <div>
              <h1 class="report-meta__title">${escapeHtml(data.query)}</h1>
              <div class="report-meta__sub">
                报告 ${data.id?.slice(0, 8) || ''} · 生成于 ${formatDate(data.created_at)}${data.duration_s ? ` · 耗时 ${formatDuration(data.duration_s)}` : ''}
              </div>
            </div>
            <div class="report-meta__badges">
              ${data.intent ? `<span class="ti-badge ti-badge--info">${data.intent}</span>` : ''}
              ${data.tlp ? tlpBadge(data.tlp) : ''}
              ${data.overall_confidence ? confidenceBadge(data.overall_confidence) : ''}
            </div>
          </div>
          ${data.sources_used?.length ? `
          <div class="report-meta__sources">
            <span class="report-meta__sources-label">数据源覆盖</span>
            ${data.sources_used.map(s => `
              <span class="source-pill" data-state="${s.is_trusted ? 'hit' : 'miss'}">
                <span class="source-pill__dot"></span>
                ${escapeHtml(s.source_type)}
              </span>
            `).join('')}
          </div>
          ` : ''}
        </div>
      </section>

      <!-- Tabs -->
      <nav class="tabs" role="tablist">
        <div class="tabs__inner">
          <button class="tab" data-tab="report" role="tab">分析报告</button>
          <button class="tab" data-tab="iocs" role="tab">IOC 列表 <span class="tab__count">${data.iocs?.length || 0}</span></button>
          <button class="tab" data-tab="techniques" role="tab">ATT&CK <span class="tab__count">${data.attack_techniques?.length || 0}</span></button>
          <button class="tab" data-tab="cves" role="tab">CVE 漏洞 <span class="tab__count">${data.cve_refs?.length || 0}</span></button>
          <button class="tab" data-tab="sources" role="tab">数据来源 <span class="tab__count">${data.sources_used?.length || 0}</span></button>
          <button class="tab" data-tab="trace" role="tab">调研轨迹</button>
        </div>
      </nav>

      <!-- Tab panels -->
      <section class="tabpanels">
        <div class="tabpanels__inner">
          <div class="panel" data-panel="report"></div>
          <div class="panel" data-panel="iocs"></div>
          <div class="panel" data-panel="techniques"></div>
          <div class="panel" data-panel="cves"></div>
          <div class="panel" data-panel="sources"></div>
          <div class="panel" data-panel="trace"></div>
        </div>
      </section>

      <!-- 底部操作区 -->
      <footer class="report-footer">
        <div class="report-footer__inner">
          <div class="report-footer__left">
            <button class="ti-btn ti-btn--secondary ti-btn--sm" onclick="window._refreshDetail()">
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M2 6a4 4 0 0 1 7-2.7M10 6a4 4 0 0 1-7 2.7" stroke-linecap="round"/>
                <path d="M9 1v2.7H6.3M3 11V8.3h2.7" stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
              刷新增量
            </button>
            <span class="ti-text-muted" style="font-size: var(--text-xs); margin-left: var(--space-2);">
              ${data.token_input ? `令牌：${data.token_input} 入 / ${data.token_output} 出` : ''}
              ${data.cost_usd ? ` · 费用：¥${data.cost_usd.toFixed(4)}` : ''}
            </span>
          </div>
          <div class="report-footer__right">
            <div class="ti-btn-group" role="group" aria-label="导出">
              <button class="ti-btn" onclick="window._exportDetail('md')">MD</button>
              <button class="ti-btn" onclick="window._exportDetail('pdf')">PDF</button>
              <button class="ti-btn" onclick="window._exportDetail('stix')">STIX</button>
              <button class="ti-btn" onclick="window._exportDetail('sigma')">Sigma</button>
              <button class="ti-btn" onclick="window._exportDetail('iocs')">IOC CSV</button>
              <button class="ti-btn" onclick="window._exportDetail('zip')">打包 .zip</button>
            </div>
            <button class="ti-btn ti-btn--danger ti-btn--sm" id="open-delete" style="margin-left: var(--space-2)">
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M2.5 3.5h7M5 5.5v3M7 5.5v3M3.5 3.5l.5 6h4l.5-6M4.5 3.5V2h3v1.5" stroke-linejoin="round"/>
              </svg>
              删除
            </button>
          </div>
        </div>
      </footer>
    </div>

    <!-- 删除二次确认 Modal -->
    <div class="ti-modal-backdrop" id="delete-modal">
      <div class="ti-modal" role="dialog" aria-modal="true" aria-labelledby="del-title">
        <div class="ti-modal__header">
          <h2 class="ti-modal__title" id="del-title">删除此报告？</h2>
          <button class="ti-btn ti-btn--ghost ti-btn--sm" id="close-delete" aria-label="关闭">✕</button>
        </div>
        <div class="ti-modal__body">
          此操作将永久删除 <span class="ti-mono">${escapeHtml(data.query)}</span> 的完整调研结果，包括:
          <ul style="margin: var(--space-3) 0; padding-left: 1.5em; color: var(--text-primary);">
            <li>${data.iocs?.length || 0} 条 IOC</li>
            <li>${data.attack_techniques?.length || 0} 条 ATT&CK 技术</li>
            <li>完整调研轨迹</li>
          </ul>
          操作不可撤销。
        </div>
        <div class="ti-modal__footer">
          <button class="ti-btn ti-btn--secondary" id="cancel-delete">取消</button>
          <button class="ti-btn ti-btn--danger" id="confirm-delete">永久删除</button>
        </div>
      </div>
    </div>
  `;

  // Tab switching
  const tabs = {
    report: () => renderReportTab(data),
    iocs: () => renderIOCSTab(data),
    techniques: () => renderTechniquesTab(data),
    cves: () => renderCVETab(data),
    sources: () => renderSourcesTab(data),
    trace: () => renderTraceTab(data),
  };

  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.removeAttribute('data-active'));
      document.querySelectorAll('.panel').forEach(p => p.removeAttribute('data-active'));
      tab.setAttribute('data-active', '');
      const target = tab.getAttribute('data-tab');
      const panel = document.querySelector(`[data-panel="${target}"]`);
      if (panel) {
        panel.setAttribute('data-active', '');
        tabs[target]?.();
      }
      document.querySelector('.tabpanels').scrollTop = 0;
    });
  });

  // Default: report tab
  const defaultTab = document.querySelector('.tab[data-tab="report"]');
  if (defaultTab) {
    defaultTab.setAttribute('data-active', '');
    document.querySelector('[data-panel="report"]')?.setAttribute('data-active', '');
    tabs.report();
  }

  // Modal handlers
  const modal = document.getElementById('delete-modal');
  document.getElementById('open-delete')?.addEventListener('click', () => modal?.setAttribute('data-open', ''));
  document.getElementById('close-delete')?.addEventListener('click', () => modal?.removeAttribute('data-open'));
  document.getElementById('cancel-delete')?.addEventListener('click', () => modal?.removeAttribute('data-open'));
  modal?.addEventListener('click', (e) => { if (e.target === modal) modal.removeAttribute('data-open'); });

  // Action handlers
  window._exportDetail = (format) => API.download(`/export/${format}/${data.id}`);
  window._deleteDetail = async () => {
    try {
      await API.deleteHistory(data.id);
      showToast('已删除');
      modal?.removeAttribute('data-open');
      window.location.hash = '#/history';
    } catch (err) {
      showToast(err.message, 'error');
    }
  };
  window._refreshDetail = async () => {
    showToast('正在创建增量刷新...');
    try {
      const result = await API.post(`/analyze/${data.id}/refresh`);
      showToast('增量分析已启动');
      window.location.hash = `#/history/${result.task_id}`;
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  // Confirm delete button
  document.getElementById('confirm-delete')?.addEventListener('click', window._deleteDetail);
}

function renderReportTab(data) {
  const panel = document.querySelector('[data-panel="report"]');
  if (!panel) return;

  if (!data.report_md) {
    panel.innerHTML = '<div class="empty-state"><p>未生成报告</p></div>';
    return;
  }

  try {
    panel.innerHTML = `<article class="md">${marked.parse(data.report_md, { breaks: true })}</article>`;
  } catch {
    panel.innerHTML = `<pre style="white-space:pre-wrap">${data.report_md}</pre>`;
    return;
  }

  const article = panel.querySelector('.md');
  const headings = article.querySelectorAll('h2');
  if (headings.length < 2) return;

  const tocItems = [];
  headings.forEach((h, i) => {
    const id = `sec-${i}`;
    h.id = id;
    tocItems.push({ id, text: h.textContent.trim() });
  });

  // Wrap article in flex layout
  const layout = document.createElement('div');
  layout.className = 'report-layout';
  article.parentNode.insertBefore(layout, article);
  layout.appendChild(article);

  // Build TOC sidebar
  const toc = document.createElement('nav');
  toc.className = 'report-toc';
  toc.setAttribute('aria-label', '报告目录');
  toc.innerHTML = `
    <div class="report-toc__title">目录</div>
    <ul class="report-toc__list">
      ${tocItems.map((item, i) => `
        <li class="report-toc__item${i === 0 ? ' report-toc__item--active' : ''}">
          <a href="#${item.id}" class="report-toc__link" title="${escapeAttr(item.text)}">${escapeHtml(item.text)}</a>
        </li>
      `).join('')}
    </ul>
  `;
  layout.appendChild(toc);

  // Smooth scroll on click
  toc.addEventListener('click', (e) => {
    const link = e.target.closest('.report-toc__link');
    if (!link) return;
    e.preventDefault();
    const target = document.getElementById(link.getAttribute('href').slice(1));
    if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  // Track active section via IntersectionObserver
  const tabpanels = document.querySelector('.tabpanels');
  const items = toc.querySelectorAll('.report-toc__item');
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        items.forEach(li => li.classList.remove('report-toc__item--active'));
        const idx = tocItems.findIndex(t => t.id === entry.target.id);
        if (idx >= 0) items[idx]?.classList.add('report-toc__item--active');
        break;
      }
    }
  }, { root: tabpanels, rootMargin: '-5% 0px -85% 0px', threshold: 0 });

  headings.forEach(h => observer.observe(h));

  // Disconnect observer when panel is re-rendered
  new MutationObserver((_, obs) => {
    if (!panel.contains(layout)) {
      observer.disconnect();
      obs.disconnect();
    }
  }).observe(panel, { childList: true });
}

function renderIOCSTab(data) {
  const panel = document.querySelector('[data-panel="iocs"]');
  if (!panel) return;

  if (!data.iocs?.length) {
    panel.innerHTML = '<div class="empty-state"><p>未提取到 IOC</p></div>';
    return;
  }

  const grouped = {};
  data.iocs.forEach(ioc => {
    if (!grouped[ioc.ioc_type]) grouped[ioc.ioc_type] = [];
    grouped[ioc.ioc_type].push(ioc);
  });

  const types = Object.keys(grouped);
  let defangOn = true;

  const chipCls = t => t === 'ipv4' || t === 'ipv6' ? 'ipv4' : t === 'domain' ? 'domain' : t === 'url' ? 'url' : 'hash';
  const chipIco = t => t === 'ipv4' || t === 'ipv6' ? 'IP' : t === 'domain' ? 'DN' : t === 'url' ? 'UR' : '#';

  panel.innerHTML = `
    <div class="ioc-toolbar">
      <div class="ioc-toolbar__group">
        <span class="ioc-toolbar__label">类型</span>
        <button class="ioc-filter" data-active data-type="all">全部 ${data.iocs.length}</button>
        ${types.map(t => `
          <button class="ioc-filter" data-type="${t}">${t.toUpperCase()} · ${grouped[t].length}</button>
        `).join('')}
      </div>
      <div class="ioc-toolbar__group">
        <span class="ioc-toolbar__label">Defang</span>
        <label class="switch"><input type="checkbox" id="defang-toggle" checked /><span class="switch__slider"></span></label>
        <button class="ti-btn ti-btn--ghost ti-btn--sm" id="copy-all-iocs">复制全部</button>
      </div>
    </div>
    ${Object.entries(grouped).map(([type, iocs]) => `
      <div class="ioc-group" data-ioc-type="${type}">
        <div class="ioc-group__head">
          <div class="ioc-group__type">
            <span class="ti-chip ti-chip--${chipCls(type)}">
              <span class="ti-chip__icon">${chipIco(type)}</span>
            </span>
            ${type.toUpperCase()}
          </div>
          <span class="ioc-group__count">${iocs.length} 条</span>
        </div>
        ${iocs.map(ioc => `
          <div class="ioc-row">
            <span class="ioc-row__value"
                  data-original="${escapeAttr(ioc.value)}"
                  data-defanged="${escapeAttr(ioc.value_defanged || defang(ioc.value, ioc.ioc_type))}"
            >${escapeHtml(ioc.value_defanged || defang(ioc.value, ioc.ioc_type))}</span>
            <span>${confidenceBadge(ioc.confidence)}</span>
            <span class="ioc-row__context">${escapeHtml(ioc.context || '')}</span>
            <span class="ioc-row__actions">
              <button class="ti-btn ti-btn--ghost ti-btn--sm ioc-copy-btn">复制</button>
            </span>
          </div>
        `).join('')}
      </div>
    `).join('')}
  `;

  // Type filter
  panel.querySelectorAll('.ioc-filter').forEach(btn => {
    btn.addEventListener('click', () => {
      panel.querySelectorAll('.ioc-filter').forEach(b => b.removeAttribute('data-active'));
      btn.setAttribute('data-active', '');
      const t = btn.dataset.type;
      panel.querySelectorAll('.ioc-group').forEach(g => {
        g.style.display = (t === 'all' || g.dataset.iocType === t) ? '' : 'none';
      });
    });
  });

  // DEFANG toggle: switch displayed values
  document.getElementById('defang-toggle')?.addEventListener('change', (e) => {
    defangOn = e.target.checked;
    panel.querySelectorAll('.ioc-row__value').forEach(el => {
      el.textContent = defangOn ? el.dataset.defanged : el.dataset.original;
    });
  });

  // Copy individual IOC (event delegation)
  panel.addEventListener('click', (e) => {
    if (!e.target.closest('.ioc-copy-btn')) return;
    const row = e.target.closest('.ioc-row');
    const valueEl = row?.querySelector('.ioc-row__value');
    if (valueEl) copyToClipboard(valueEl.textContent);
  });

  // Copy all — respects current filter and defang state
  document.getElementById('copy-all-iocs')?.addEventListener('click', () => {
    const activeType = panel.querySelector('.ioc-filter[data-active]')?.dataset.type || 'all';
    const iocs = activeType === 'all' ? data.iocs : (grouped[activeType] || []);
    const text = iocs.map(i => {
      const val = defangOn ? (i.value_defanged || defang(i.value, i.ioc_type)) : i.value;
      return `${i.ioc_type},${val}`;
    }).join('\n');
    copyToClipboard(text);
  });
}

function renderTechniquesTab(data) {
  const panel = document.querySelector('[data-panel="techniques"]');
  if (!panel) return;

  if (!data.attack_techniques?.length) {
    panel.innerHTML = '<div class="empty-state"><p>未映射 ATT&CK 技术</p></div>';
    return;
  }

  panel.innerHTML = `
    <div class="matrix-wrap">
      <div class="matrix-legend">
        <span>命中 ${data.attack_techniques.length} 个技术</span>
      </div>
      <div class="matrix-scroll">
        <div class="matrix">
          ${data.attack_techniques.map(t => {
            const nameZh = getTechniqueNameZh(t.technique_id, t.technique_name);
            const tacticZh = getTacticNameZh(t.tactic || '');
            return `
            <div class="matrix__col">
              <div class="matrix__head">${tacticZh || t.tactic}<span class="num">${t.technique_id}</span></div>
              <div class="matrix__cell" data-hit="3">
                ${escapeHtml(nameZh)}
                <span class="tid">${t.technique_id}</span>
              </div>
            </div>
          `}).join('')}
        </div>
      </div>
    </div>
    <table style="width:100%;margin-top:var(--space-4)">
      <thead><tr><th>技术 ID</th><th>名称</th><th>战术</th><th>置信度</th></tr></thead>
      <tbody>
        ${data.attack_techniques.map(t => {
          const nameZh = getTechniqueNameZh(t.technique_id, t.technique_name);
          const tacticZh = getTacticNameZh(t.tactic || '');
          return `
          <tr>
            <td><code>${t.technique_id}</code></td>
            <td>${escapeHtml(nameZh)}${nameZh !== t.technique_name ? `<br><span style="font-size:var(--text-xs);color:var(--text-muted)">${escapeHtml(t.technique_name || '')}</span>` : ''}</td>
            <td>${escapeHtml(tacticZh)}</td>
            <td>${confidenceBadge(t.confidence)}</td>
          </tr>
        `}).join('')}
      </tbody>
    </table>
  `;
}

function renderCVETab(data) {
  const panel = document.querySelector('[data-panel="cves"]');
  if (!panel) return;

  if (!data.cve_refs?.length) {
    panel.innerHTML = '<div class="empty-state"><p>无 CVE 参考</p></div>';
    return;
  }

  panel.innerHTML = `
    <table style="width:100%">
      <thead><tr><th>CVE</th><th>CVSS</th><th>KEV</th><th>EPSS</th></tr></thead>
      <tbody>
        ${data.cve_refs.map(c => `
          <tr>
            <td><code>${c.cve_id}</code></td>
            <td>${c.cvss_v3_score ?? 'N/A'}</td>
            <td>${c.is_in_kev ? '<span class="ti-badge ti-badge--error">KEV</span>' : '否'}</td>
            <td>${c.epss_score ?? 'N/A'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

function renderSourcesTab(data) {
  const panel = document.querySelector('[data-panel="sources"]');
  if (!panel) return;

  if (!data.sources_used?.length) {
    panel.innerHTML = '<div class="empty-state"><p>未记录数据来源</p></div>';
    return;
  }

  panel.innerHTML = `
    <table style="width:100%">
      <thead><tr><th>域名</th><th>类型</th><th>可信</th><th>链接</th></tr></thead>
      <tbody>
        ${data.sources_used.map(s => `
          <tr>
            <td>${escapeHtml(s.domain)}</td>
            <td><span class="ti-badge ti-badge--info">${s.source_type}</span></td>
            <td>${s.is_trusted ? '&#9989;' : ''}</td>
            <td style="font-size:var(--text-xs);max-width:300px;overflow:hidden;text-overflow:ellipsis"><a href="${escapeHtml(s.url)}" target="_blank">${escapeHtml(s.url)}</a></td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

function renderTraceTab(data) {
  const panel = document.querySelector('[data-panel="trace"]');
  if (!panel) return;

  if (!data.agent_logs?.length) {
    panel.innerHTML = '<div class="empty-state"><p>无追踪数据</p></div>';
    return;
  }

  const agentTraceLogs = data.agent_logs.filter(log => log.event_type === 'agent_trace' && log.payload);
  if (agentTraceLogs.length) {
    panel.innerHTML = renderAgentTraceGroups(agentTraceLogs);
    return;
  }

  panel.innerHTML = `
    <ul class="trace">
      ${data.agent_logs.map(log => `
        <li class="trace-item">
          <span class="trace-item__dot"><span class="ti-status-dot ti-status-dot--completed"></span></span>
          <details>
            <summary class="trace-item__head">
              <span class="trace-item__chev">▶</span>
              <span class="trace-item__label">${log.event_type}</span>
              ${log.agent_name ? `<span class="trace-item__source">${log.agent_name}</span>` : ''}
              <span class="trace-item__meta">${formatDate(log.created_at)}</span>
            </summary>
            <div class="trace-item__body">
              <pre>${log.payload ? escapeHtml(JSON.stringify(log.payload, null, 2)) : ''}</pre>
            </div>
          </details>
        </li>
      `).join('')}
    </ul>
  `;
}

function renderAgentTraceGroups(logs) {
  const groups = new Map();
  for (const log of logs) {
    const payload = log.payload || {};
    const agentId = payload.agent_id || log.agent_name || 'agent';
    if (!groups.has(agentId)) groups.set(agentId, []);
    groups.get(agentId).push({ log, payload });
  }

  return `
    <div class="agent-trace-list">
      ${[...groups.entries()].map(([agentId, entries]) => `
        <details class="agent-trace" open>
          <summary class="agent-trace__head">
            <span class="agent-trace__chev">▶</span>
            <span class="agent-trace__name">${escapeHtml(agentId)}</span>
            <span class="agent-trace__type">${escapeHtml(entries[0].payload.agent_type || 'Agent')}</span>
            <span class="agent-trace__count">${entries.length} steps</span>
          </summary>
          <div class="agent-trace__body">
            ${entries.map(({ log, payload }) => `
              <details class="agent-step" ${payload.status === 'running' || payload.action === 'tool_result' || payload.action === 'submit_findings' ? 'open' : ''}>
                <summary class="agent-step__head">
                  <span class="agent-step__dot"><span class="ti-status-dot ti-status-dot--${traceStatus(payload.status)}"></span></span>
                  <span class="agent-step__title">${escapeHtml(payload.title || payload.action || log.event_type)}</span>
                  ${payload.round ? `<span class="agent-step__round">Round ${payload.round}</span>` : ''}
                  <span class="agent-step__action">${escapeHtml(payload.action || '')}</span>
                  <span class="agent-step__time">${formatDate(log.created_at)}</span>
                </summary>
                <div class="agent-step__body">
                  ${payload.summary ? `<p class="agent-step__summary">${escapeHtml(payload.summary)}</p>` : ''}
                  ${renderTraceDetails(payload.details)}
                </div>
              </details>
            `).join('')}
          </div>
        </details>
      `).join('')}
    </div>
  `;
}

function traceStatus(status) {
  if (status === 'completed') return 'completed';
  if (status === 'failed' || status === 'error') return 'failed';
  if (status === 'interrupted') return 'interrupted';
  return 'running';
}

function renderTraceDetails(details = {}) {
  if (!details || Object.keys(details).length === 0) return '';

  if (Array.isArray(details.results)) {
    return `
      <div class="agent-step__section">搜索结果</div>
      <ol class="agent-step__results">
        ${details.results.map(r => `
          <li>
            <a href="${escapeAttr(r.url || '#')}" target="_blank" rel="noreferrer">${escapeHtml(r.title || r.url || 'Untitled')}</a>
            ${r.snippet ? `<p>${escapeHtml(r.snippet)}</p>` : ''}
          </li>
        `).join('')}
      </ol>
      ${renderTraceJson(details)}
    `;
  }

  if (Array.isArray(details.findings)) {
    return `
      <div class="agent-step__section">提交的发现</div>
      <ul class="agent-step__findings">
        ${details.findings.map(f => `
          <li>
            <strong>${escapeHtml(f.claim || '')}</strong>
            <span>${escapeHtml(f.confidence || '')}</span>
            ${f.source_url ? `<a href="${escapeAttr(f.source_url)}" target="_blank" rel="noreferrer">${escapeHtml(f.source_name || f.source_url)}</a>` : ''}
          </li>
        `).join('')}
      </ul>
      ${renderTraceJson(details)}
    `;
  }

  return renderTraceJson(details);
}

function renderTraceJson(details) {
  return `<pre class="agent-step__json">${escapeHtml(JSON.stringify(details, null, 2))}</pre>`;
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
