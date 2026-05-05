import API from '../lib/api.js';
import { formatDate, formatDuration, statusBadge, confidenceBadge, tlpBadge, iocChip, copyToClipboard, showToast } from '../lib/utils.js';

export async function renderHistoryDetail(container, id) {
  container.innerHTML = '<div class="skeleton" style="height:400px"></div>';

  try {
    const data = await API.historyDetail(id);
    renderDetail(container, data);
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><h3>Analysis not found</h3><p>${err.message}</p></div>`;
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
        <button class="btn btn-sm" onclick="window._exportDetail('md')">MD</button>
        <button class="btn btn-sm" onclick="window._exportDetail('pdf')">PDF</button>
        <button class="btn btn-sm" onclick="window._exportDetail('stix')">STIX</button>
        <button class="btn btn-sm" onclick="window._exportDetail('zip')">ZIP</button>
        <button class="btn btn-sm btn-danger" onclick="window._deleteDetail()">Delete</button>
      </div>
    </div>

    <div class="detail-meta">
      <span>Created: ${formatDate(data.created_at)}</span>
      ${data.duration_s ? `<span>Duration: ${formatDuration(data.duration_s)}</span>` : ''}
      ${data.token_input ? `<span>Tokens: ${data.token_input} in / ${data.token_output} out</span>` : ''}
      ${data.cost_usd ? `<span>Cost: $${data.cost_usd.toFixed(2)}</span>` : ''}
    </div>

    <div class="tabs" id="detail-tabs">
      <div class="tab active" data-tab="report">Report</div>
      <div class="tab" data-tab="iocs">IOCs (${data.iocs?.length || 0})</div>
      <div class="tab" data-tab="techniques">ATT&CK (${data.attack_techniques?.length || 0})</div>
      <div class="tab" data-tab="cves">CVEs (${data.cve_refs?.length || 0})</div>
      <div class="tab" data-tab="sources">Sources (${data.sources_used?.length || 0})</div>
      <div class="tab" data-tab="trace">Trace</div>
    </div>

    <div id="tab-content"></div>
  `;

  const tabs = {
    report: () => renderReportTab(data),
    iocs: () => renderIOCSTab(data),
    techniques: () => renderTechniquesTab(data),
    cves: () => renderCVETab(data),
    sources: () => renderSourcesTab(data),
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
    if (!confirm('Delete this analysis?')) return;
    try {
      await API.deleteHistory(data.id);
      showToast('Deleted');
      window.location.hash = '#/history';
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
    el.innerHTML = '<div class="empty-state"><p>No report generated</p></div>';
  }
}

function renderIOCSTab(data) {
  const el = document.getElementById('tab-content');
  if (!data.iocs?.length) {
    el.innerHTML = '<div class="empty-state"><p>No IOCs extracted</p></div>';
    return;
  }

  const grouped = {};
  data.iocs.forEach(ioc => {
    if (!grouped[ioc.ioc_type]) grouped[ioc.ioc_type] = [];
    grouped[ioc.ioc_type].push(ioc);
  });

  el.innerHTML = `
    <div style="margin-bottom:var(--space-3)">
      <button class="btn btn-sm" onclick="window._copyAllIOCs()">Copy All (defanged)</button>
    </div>
    ${Object.entries(grouped).map(([type, iocs]) => `
      <h3 style="margin:var(--space-4) 0 var(--space-2)">${type.toUpperCase()} (${iocs.length})</h3>
      <table>
        <thead><tr><th>Value</th><th>Defanged</th><th>Confidence</th><th>Context</th></tr></thead>
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
    el.innerHTML = '<div class="empty-state"><p>No ATT&CK techniques mapped</p></div>';
    return;
  }
  el.innerHTML = `
    <table>
      <thead><tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Confidence</th></tr></thead>
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
    el.innerHTML = '<div class="empty-state"><p>No CVE references</p></div>';
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
            <td>${c.is_in_kev ? '<span class="badge badge-error">KEV</span>' : 'No'}</td>
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
    el.innerHTML = '<div class="empty-state"><p>No sources recorded</p></div>';
    return;
  }
  el.innerHTML = `
    <table>
      <thead><tr><th>Domain</th><th>Type</th><th>Trusted</th><th>URL</th></tr></thead>
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

function renderTraceTab(data) {
  const el = document.getElementById('tab-content');
  if (!data.agent_logs?.length) {
    el.innerHTML = '<div class="empty-state"><p>No trace data</p></div>';
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
