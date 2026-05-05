import API from '../lib/api.js';
import { TIEventSource } from '../lib/sse.js';
import { formatDate, statusBadge, confidenceBadge, iocChip, showToast, copyToClipboard } from '../lib/utils.js';

let currentSSE = null;
let currentTaskId = null;

export function renderWorkspace(container) {
  if (currentSSE) { currentSSE.abort(); currentSSE = null; }
  currentTaskId = null;

  container.innerHTML = `
    <div class="workspace-layout">
      <div class="input-section">
        <h2 style="margin-bottom:var(--space-3)">New Threat Intelligence Analysis</h2>
        <div class="input-row">
          <textarea id="query-input" class="textarea" placeholder="Enter CVE ID, ATT&CK technique, APT group, IOC, or threat description..." rows="2"></textarea>
          <div style="display:flex;flex-direction:column;gap:var(--space-2)">
            <button id="btn-analyze" class="btn btn-primary" onclick="window._startAnalysis()">Analyze</button>
            <button id="btn-stop" class="btn btn-danger" style="display:none" onclick="window._stopAnalysis()">Stop</button>
          </div>
        </div>
        <div class="input-meta">
          <span id="intent-preview"></span>
          <span id="token-counter" style="margin-left:auto"></span>
          <button class="btn btn-sm" onclick="window.toggleTheme()">Toggle Theme</button>
        </div>
      </div>
      <div id="analysis-area" style="display:none">
        <div class="analysis-layout">
          <div class="timeline-panel" id="timeline"></div>
          <div class="report-panel" id="report">
            <div id="report-content"></div>
            <span id="cursor" class="cursor-blink" style="display:none"></span>
          </div>
        </div>
        <div class="export-bar" id="export-bar" style="display:none">
          <button class="btn btn-sm" onclick="window._export('md')">Markdown</button>
          <button class="btn btn-sm" onclick="window._export('pdf')">PDF</button>
          <button class="btn btn-sm" onclick="window._export('stix')">STIX</button>
          <button class="btn btn-sm" onclick="window._export('iocs')">IOC CSV</button>
          <button class="btn btn-sm" onclick="window._export('sigma')">Sigma</button>
          <button class="btn btn-sm" onclick="window._export('zip')">Package All</button>
        </div>
      </div>
    </div>
  `;

  const input = document.getElementById('query-input');
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      window._startAnalysis();
    }
  });
  input.focus();
}

window._startAnalysis = async () => {
  const input = document.getElementById('query-input');
  const query = input.value.trim();
  if (query.length < 3) { showToast('Query too short', 'error'); return; }

  const btn = document.getElementById('btn-analyze');
  const btnStop = document.getElementById('btn-stop');
  btn.disabled = true;
  btn.textContent = 'Starting...';

  try {
    const result = await API.analyze(query);
    currentTaskId = result.task_id;

    document.getElementById('analysis-area').style.display = 'block';
    document.getElementById('intent-preview').textContent = `Intent: ${result.intent_preview || 'detecting...'}`;
    btnStop.style.display = 'inline-flex';
    btn.style.display = 'none';

    document.getElementById('timeline').innerHTML = '';
    document.getElementById('report-content').innerHTML = '<p style="color:var(--text-muted)">Connecting to analysis stream...</p>';
    document.getElementById('cursor').style.display = 'inline-block';

    startSSE(result.task_id);
  } catch (err) {
    showToast(err.message, 'error');
    btn.disabled = false;
    btn.textContent = 'Analyze';
  }
};

window._stopAnalysis = async () => {
  if (!currentTaskId) return;
  try {
    await API.stop(currentTaskId);
    showToast('Analysis stopped');
  } catch (err) {
    showToast(err.message, 'error');
  }
};

let timelineItems = [];
let reportBuffer = '';
let renderScheduled = false;

function startSSE(taskId) {
  timelineItems = [];
  reportBuffer = '';

  const handlers = {
    intent_classified: (data) => {
      addTimeline('Intent classified', `${data.intent} (confidence: ${data.confidence})`, 'info');
      document.getElementById('intent-preview').textContent = `Intent: ${data.intent}`;
    },
    plan_result: (data) => {
      addTimeline('Plan created', `${data.research_questions?.length || 0} questions, sources: ${data.authoritative_sources?.join(', ')}`, 'plan');
    },
    data_source_query: (data) => {
      addTimeline(`Querying ${data.source.toUpperCase()}`, `Entity: ${data.entity}`, 'source');
    },
    data_source_hit: (data) => {
      updateTimelineLast(`${data.source.toUpperCase()} - found`, 'success');
    },
    data_source_miss: (data) => {
      updateTimelineLast(`${data.source.toUpperCase()} - not found`, 'warning');
    },
    data_source_error: (data) => {
      updateTimelineLast(`${data.source.toUpperCase()} - error`, 'error');
    },
    enrichment_done: () => {
      addTimeline('Enrichment complete', '', 'done');
    },
    agent_start: (data) => {
      addTimeline(`Research ${data.agent_id}`, data.question, 'research');
    },
    searching: (data) => {
      addTimeline(`  ${data.agent_id} searching`, `"${data.query}" (round ${data.round})`, 'search');
    },
    agent_done: (data) => {
      updateTimelineLast(`${data.agent_id} done - ${data.findings_count} findings`, 'done');
    },
    ioc_extracted: (data) => {
      addTimeline('IOC extraction', `${data.ioc_count} IOCs found`, 'done');
    },
    critic_done: (data) => {
      addTimeline('Critic review', `${data.issues_count} issues, confidence: ${data.overall_confidence}`, 'done');
    },
    synthesizing: () => {
      addTimeline('Synthesis', 'Generating report...', 'research');
    },
    report_chunk: (data) => {
      reportBuffer += data.content;
      scheduleRender();
    },
    done: (data) => {
      document.getElementById('cursor').style.display = 'none';
      document.getElementById('btn-stop').style.display = 'none';
      document.getElementById('export-bar').style.display = 'flex';
      document.getElementById('token-counter').textContent =
        `Tokens: ${data.token_usage?.input || 0} in / ${data.token_usage?.output || 0} out | Cost: $${data.cost_usd || 0}`;
      addTimeline('Complete', `Duration: ${data.duration_s}s`, 'done');
      renderMarkdown();
    },
    error: (data) => {
      document.getElementById('cursor').style.display = 'none';
      addTimeline('Error', data.message, 'error');
      showToast(data.message, 'error');
    },
    stopped: () => {
      document.getElementById('cursor').style.display = 'none';
      document.getElementById('btn-stop').style.display = 'none';
      addTimeline('Stopped', 'Analysis was cancelled', 'warning');
    },
    agent_error: (data) => {
      addTimeline(`Error: ${data.agent_id}`, data.message, 'error');
    },
  };

  currentSSE = new TIEventSource(taskId, handlers);
}

function addTimeline(text, detail, type = 'info') {
  const icons = {
    info: '&#9432;', plan: '&#128203;', source: '&#128269;', success: '&#9989;',
    warning: '&#9888;', error: '&#10060;', done: '&#10004;', research: '&#128270;',
    search: '&#128270;',
  };
  timelineItems.push({ text, detail, type });
  const panel = document.getElementById('timeline');
  if (!panel) return;
  const item = document.createElement('div');
  item.className = 'timeline-item';
  item.innerHTML = `
    <span class="timeline-icon">${icons[type] || icons.info}</span>
    <div class="timeline-text">
      <div class="agent-name">${text}</div>
      ${detail ? `<div class="detail">${detail}</div>` : ''}
    </div>
  `;
  panel.appendChild(item);
  panel.scrollTop = panel.scrollHeight;
}

function updateTimelineLast(text, type) {
  const panel = document.getElementById('timeline');
  if (!panel) return;
  const items = panel.querySelectorAll('.timeline-item');
  const last = items[items.length - 1];
  if (last) {
    const nameEl = last.querySelector('.agent-name');
    if (nameEl) nameEl.textContent = text;
  }
}

function scheduleRender() {
  if (renderScheduled) return;
  renderScheduled = true;
  requestAnimationFrame(() => {
    setTimeout(() => {
      renderScheduled = false;
      renderMarkdown();
    }, 100);
  });
}

function renderMarkdown() {
  const el = document.getElementById('report-content');
  if (!el || !reportBuffer) return;
  try {
    el.innerHTML = marked.parse(reportBuffer, { breaks: true });
  } catch {
    el.textContent = reportBuffer;
  }
}

window._export = (format) => {
  if (!currentTaskId) return;
  const endpoints = {
    md: `/export/md/${currentTaskId}`,
    pdf: `/export/pdf/${currentTaskId}`,
    stix: `/export/stix/${currentTaskId}`,
    iocs: `/export/iocs/${currentTaskId}`,
    sigma: `/export/sigma/${currentTaskId}`,
    zip: `/export/zip/${currentTaskId}`,
  };
  API.download(endpoints[format]);
};
