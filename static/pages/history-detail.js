import API from '../lib/api.js';
import { formatDate, formatDuration, statusBadge, confidenceBadge, tlpBadge, iocChip, copyToClipboard, showToast } from '../lib/utils.js';

export async function renderHistoryDetail(container, id) {
  container.innerHTML = '<div class="skeleton" style="height:400px"></div>';

  try {
    const data = await API.historyDetail(id);
    renderDetail(container, data);
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><h3>未找到分析记录</h3><p>${err.message}</p></div>`;
  }
}

function renderDetail(container, data) {
  container.innerHTML = `
    <div class="detail-header">
      <div>
        <h2>${escapeHtml(data.query)}</h2>
        <div style="display:flex;gap:var(--space-2);margin-top:var(--space-2)">
          ${statusBadge(data.status)}
          ${data.intent ? `<span class="badge badge-info">${data.intent}</span>` : ''}
          ${tlpBadge(data.tlp)}
          ${data.overall_confidence ? confidenceBadge(data.overall_confidence) : ''}
        </div>
      </div>
      <div style="display:flex;gap:var(--space-2)">
        <button class="btn btn-sm" onclick="window._refreshDetail()">刷新增量</button>
        <button class="btn btn-sm" onclick="window._exportDetail('md')">MD</button>
        <button class="btn btn-sm" onclick="window._exportDetail('pdf')">PDF</button>
        <button class="btn btn-sm" onclick="window._exportDetail('stix')">STIX</button>
        <button class="btn btn-sm" onclick="window._exportDetail('zip')">ZIP</button>
        <button class="btn btn-sm btn-danger" onclick="window._deleteDetail()">删除</button>
      </div>
    </div>

    <div class="detail-meta">
      <span>创建时间：${formatDate(data.created_at)}</span>
      ${data.duration_s ? `<span>耗时：${formatDuration(data.duration_s)}</span>` : ''}
      ${data.token_input ? `<span>令牌：${data.token_input} 输入 / ${data.token_output} 输出</span>` : ''}
      ${data.cost_usd ? `<span>费用：$${data.cost_usd.toFixed(2)}</span>` : ''}
    </div>

    <div class="tabs" id="detail-tabs">
      <div class="tab active" data-tab="report">分析报告</div>
      <div class="tab" data-tab="iocs">IOC 指标 (${data.iocs?.length || 0})</div>
      <div class="tab" data-tab="techniques">ATT&CK (${data.attack_techniques?.length || 0})</div>
      <div class="tab" data-tab="cves">CVE 漏洞 (${data.cve_refs?.length || 0})</div>
      <div class="tab" data-tab="sources">数据来源 (${data.sources_used?.length || 0})</div>
      <div class="tab" data-tab="diff">对比</div>
      <div class="tab" data-tab="trace">执行追踪</div>
    </div>

    <div id="tab-content"></div>
  `;

  const tabs = {
    report: () => renderReportTab(data),
    iocs: () => renderIOCSTab(data),
    techniques: () => renderTechniquesTab(data),
    cves: () => renderCVETab(data),
    sources: () => renderSourcesTab(data),
    diff: () => renderDiffTab(data),
    trace: () => renderTraceTab(data),
  };

  document.querySelectorAll('#detail-tabs .tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('#detail-tabs .tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const tabName = tab.dataset.tab;
      document.getElementById('tab-content').innerHTML = '';
      tabs[tabName]?.();
    });
  });

  // Default: report tab
  tabs.report();

  window._exportDetail = (format) => API.download(`/export/${format}/${data.id}`);
  window._deleteDetail = async () => {
    if (!confirm('确定删除此分析？')) return;
    try {
      await API.deleteHistory(data.id);
      showToast('已删除');
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
}

function renderReportTab(data) {
  const el = document.getElementById('tab-content');
  if (data.report_md) {
    try {
      el.innerHTML = `<div class="report-panel">${marked.parse(data.report_md, { breaks: true })}</div>`;
    } catch {
      el.innerHTML = `<pre style="white-space:pre-wrap">${data.report_md}</pre>`;
    }
  } else {
    el.innerHTML = '<div class="empty-state"><p>未生成报告</p></div>';
  }
}

function renderIOCSTab(data) {
  const el = document.getElementById('tab-content');
  if (!data.iocs?.length) {
    el.innerHTML = '<div class="empty-state"><p>未提取到 IOC</p></div>';
    return;
  }

  const grouped = {};
  data.iocs.forEach(ioc => {
    if (!grouped[ioc.ioc_type]) grouped[ioc.ioc_type] = [];
    grouped[ioc.ioc_type].push(ioc);
  });

  el.innerHTML = `
    <div style="margin-bottom:var(--space-3)">
      <button class="btn btn-sm" onclick="window._copyAllIOCs()">复制全部（脱敏）</button>
    </div>
    ${Object.entries(grouped).map(([type, iocs]) => `
      <h3 style="margin:var(--space-4) 0 var(--space-2)">${type.toUpperCase()} (${iocs.length})</h3>
      <table>
        <thead><tr><th>原始值</th><th>脱敏值</th><th>置信度</th><th>上下文</th></tr></thead>
        <tbody>
          ${iocs.map(ioc => `
            <tr>
              <td><code>${escapeHtml(ioc.value)}</code></td>
              <td><code>${escapeHtml(ioc.value_defanged)}</code></td>
              <td>${confidenceBadge(ioc.confidence)}</td>
              <td style="font-size:var(--text-xs);max-width:300px;overflow:hidden;text-overflow:ellipsis">${escapeHtml(ioc.context || '')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `).join('')}
  `;

  window._copyAllIOCs = () => {
    const text = data.iocs.map(i => `${i.ioc_type},${i.value_defanged}`).join('\n');
    copyToClipboard(text);
  };
}

function renderTechniquesTab(data) {
  const el = document.getElementById('tab-content');
  if (!data.attack_techniques?.length) {
    el.innerHTML = '<div class="empty-state"><p>未映射 ATT&CK 技术</p></div>';
    return;
  }
  el.innerHTML = `
    <table>
      <thead><tr><th>技术 ID</th><th>名称</th><th>战术</th><th>置信度</th></tr></thead>
      <tbody>
        ${data.attack_techniques.map(t => `
          <tr>
            <td><code>${t.technique_id}</code></td>
            <td>${escapeHtml(t.technique_name || '')}</td>
            <td>${escapeHtml(t.tactic || '')}</td>
            <td>${confidenceBadge(t.confidence)}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

function renderCVETab(data) {
  const el = document.getElementById('tab-content');
  if (!data.cve_refs?.length) {
    el.innerHTML = '<div class="empty-state"><p>无 CVE 参考</p></div>';
    return;
  }
  el.innerHTML = `
    <table>
      <thead><tr><th>CVE</th><th>CVSS</th><th>KEV</th><th>EPSS</th></tr></thead>
      <tbody>
        ${data.cve_refs.map(c => `
          <tr>
            <td><code>${c.cve_id}</code></td>
            <td>${c.cvss_v3_score ?? 'N/A'}</td>
            <td>${c.is_in_kev ? '<span class="badge badge-error">KEV</span>' : '否'}</td>
            <td>${c.epss_score ?? 'N/A'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

function renderSourcesTab(data) {
  const el = document.getElementById('tab-content');
  if (!data.sources_used?.length) {
    el.innerHTML = '<div class="empty-state"><p>未记录数据来源</p></div>';
    return;
  }
  el.innerHTML = `
    <table>
      <thead><tr><th>域名</th><th>类型</th><th>可信</th><th>链接</th></tr></thead>
      <tbody>
        ${data.sources_used.map(s => `
          <tr>
            <td>${escapeHtml(s.domain)}</td>
            <td><span class="badge badge-info">${s.source_type}</span></td>
            <td>${s.is_trusted ? '&#9989;' : ''}</td>
            <td style="font-size:var(--text-xs);max-width:300px;overflow:hidden;text-overflow:ellipsis"><a href="${escapeHtml(s.url)}" target="_blank">${escapeHtml(s.url)}</a></td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

async function renderDiffTab(data) {
  const el = document.getElementById('tab-content');
  el.innerHTML = `
    <div style="margin-bottom:var(--space-3)">
      <p style="font-size:var(--text-sm);color:var(--text-muted);margin-bottom:var(--space-2)">选择要对比的历史分析：</p>
      <div style="display:flex;gap:var(--space-2);align-items:center">
        <select id="diff-compare-id" class="input" style="max-width:400px">
          <option value="">加载中...</option>
        </select>
        <button class="btn btn-sm btn-primary" onclick="window._runDiff('${data.id}')">对比</button>
      </div>
    </div>
    <div id="diff-result"></div>
  `;

  // Load history list for selector
  try {
    const history = await API.history({ limit: 50 });
    const select = document.getElementById('diff-compare-id');
    select.innerHTML = '<option value="">选择对比目标...</option>' +
      history.items
        .filter(item => item.id !== data.id)
        .map(item => `<option value="${item.id}">${escapeHtml(item.query)} (${item.created_at?.slice(0, 10) || ''})</option>`)
        .join('');
  } catch {
    document.getElementById('diff-compare-id').innerHTML = '<option value="">加载失败</option>';
  }

  window._runDiff = async (id) => {
    const compareId = document.getElementById('diff-compare-id').value;
    if (!compareId) { showToast('请选择对比目标', 'error'); return; }
    const resultEl = document.getElementById('diff-result');
    resultEl.innerHTML = '<div class="skeleton" style="height:100px"></div>';

    try {
      const diff = await API.diffAnalyses(id, compareId);
      if (!diff.diffs.length) {
        resultEl.innerHTML = '<div class="empty-state"><p>两次分析无差异</p></div>';
        return;
      }
      resultEl.innerHTML = `
        <div style="display:flex;gap:var(--space-4);margin-bottom:var(--space-3);font-size:var(--text-xs);color:var(--text-muted)">
          <span>A：${escapeHtml(diff.analysis_a.query)} (${diff.analysis_a.created_at?.slice(0, 16) || ''})</span>
          <span>B：${escapeHtml(diff.analysis_b.query)} (${diff.analysis_b.created_at?.slice(0, 16) || ''})</span>
        </div>
        <table>
          <thead><tr><th>字段</th><th>上次</th><th>本次</th><th>变化</th></tr></thead>
          <tbody>
            ${diff.diffs.map(d => `
              <tr>
                <td style="font-weight:600">${escapeHtml(d.field)}</td>
                <td><code>${escapeHtml(d.old || '-')}</code></td>
                <td><code>${escapeHtml(d.new || '-')}</code></td>
                <td>${_diffIndicator(d.old, d.new)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        <p style="font-size:var(--text-xs);color:var(--text-muted);margin-top:var(--space-2)">共 ${diff.diff_count} 项差异</p>
      `;
    } catch (err) {
      resultEl.innerHTML = `<div class="empty-state"><p>对比失败：${escapeHtml(err.message)}</p></div>`;
    }
  };
}

function _diffIndicator(oldVal, newVal) {
  if (!oldVal || oldVal === '-') return '<span class="badge badge-success">新增</span>';
  if (!newVal || newVal === '-') return '<span class="badge badge-error">移除</span>';
  return '<span class="badge badge-warning">变更</span>';
}

function renderTraceTab(data) {
  const el = document.getElementById('tab-content');
  if (!data.agent_logs?.length) {
    el.innerHTML = '<div class="empty-state"><p>无追踪数据</p></div>';
    return;
  }
  el.innerHTML = `
    <div class="timeline-panel" style="max-height:none">
      ${data.agent_logs.map(log => `
        <div class="timeline-item">
          <div class="timeline-text">
            <div class="agent-name">${log.event_type} ${log.agent_name ? `(${log.agent_name})` : ''}</div>
            ${log.payload ? `<div class="detail"><pre style="font-size:var(--text-xs)">${escapeHtml(JSON.stringify(log.payload, null, 2))}</pre></div>` : ''}
          </div>
          <span style="font-size:var(--text-xs);color:var(--text-muted)">${formatDate(log.created_at)}</span>
        </div>
      `).join('')}
    </div>
  `;
}

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
