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
        <h2 style="margin-bottom:var(--space-3)">新建威胁情报分析</h2>
        <div class="input-row">
          <textarea id="query-input" class="textarea" placeholder="输入 CVE ID、ATT&CK 技术、APT 组织、IOC 或威胁描述..." rows="2"></textarea>
          <div style="display:flex;flex-direction:column;gap:var(--space-2)">
            <button id="btn-analyze" class="btn btn-primary" onclick="window._startAnalysis()">开始分析</button>
            <button id="btn-stop" class="btn btn-danger" style="display:none" onclick="window._stopAnalysis()">停止</button>
          </div>
        </div>
        <div class="input-meta">
          <span id="intent-preview"></span>
          <span id="token-counter" style="margin-left:auto"></span>
          <button class="btn btn-sm" onclick="window.toggleTheme()">切换主题</button>
        </div>
        <div id="intent-switcher" style="display:none;margin-top:var(--space-2);gap:var(--space-2);align-items:center;flex-wrap:wrap">
          <span style="font-size:var(--text-sm);color:var(--text-muted)">切换调研路径：</span>
          <button class="btn btn-sm" onclick="window._switchIntent('cve')">CVE</button>
          <button class="btn btn-sm" onclick="window._switchIntent('attack_technique')">ATT&CK</button>
          <button class="btn btn-sm" onclick="window._switchIntent('threat_actor')">APT/组织</button>
          <button class="btn btn-sm" onclick="window._switchIntent('malware')">恶意软件</button>
          <button class="btn btn-sm" onclick="window._switchIntent('generic')">通用</button>
        </div>
      </div>
      <div id="analysis-area" style="display:none">
        <div class="analysis-layout">
          <div class="timeline-panel" id="timeline"></div>
          <div class="report-panel" id="report">
            <details id="thinking-block" style="margin-bottom:var(--space-3);border:1px solid var(--border-hairline);border-radius:var(--radius-md);padding:var(--space-2)">
              <summary style="cursor:pointer;font-weight:600;font-size:var(--text-sm);color:var(--text-secondary)">思考过程</summary>
              <div id="thinking-content" style="font-size:var(--text-xs);color:var(--text-muted);max-height:200px;overflow-y:auto;margin-top:var(--space-2);font-family:var(--font-mono)"></div>
            </details>
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
          <button class="btn btn-sm" onclick="window._export('zip')">全部打包</button>
        </div>
      </div>
      <div id="token-sidebar" style="position:fixed;top:var(--space-4);right:var(--space-4);background:var(--bg-surface-card);border:1px solid var(--border-hairline);border-radius:var(--radius-lg);padding:var(--space-3);font-size:var(--text-xs);min-width:180px;z-index:100;display:none">
        <div style="font-weight:600;margin-bottom:var(--space-2);color:var(--text-ink)">本月消耗</div>
        <div id="token-sidebar-content"></div>
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

  // Load token balance sidebar
  _loadTokenSidebar();
}

async function _loadTokenSidebar() {
  try {
    const stats = await API.stats();
    const currentMonth = new Date().toISOString().slice(0, 7);
    const monthly = (stats.monthly_usage || []).find(m => m.year_month === currentMonth);
    const budget = 50; // default, could fetch from settings
    const spent = monthly ? monthly.total_cost_usd : 0;
    const remaining = Math.max(0, budget - spent);
    const pct = budget > 0 ? Math.round((spent / budget) * 100) : 0;
    const el = document.getElementById('token-sidebar-content');
    if (!el) return;
    el.innerHTML = `
      <div style="display:flex;justify-content:space-between;margin-bottom:4px">
        <span>已花费</span><span style="font-weight:600">$${spent.toFixed(2)}</span>
      </div>
      <div style="display:flex;justify-content:space-between;margin-bottom:4px">
        <span>剩余</span><span style="font-weight:600;color:${remaining < 5 ? 'var(--error)' : 'var(--success)'}">$${remaining.toFixed(2)}</span>
      </div>
      <div style="background:var(--bg-surface-soft);border-radius:var(--radius-sm);height:6px;margin:6px 0;overflow:hidden">
        <div style="background:${pct > 80 ? 'var(--error)' : 'var(--accent-primary)'};height:100%;width:${Math.min(pct, 100)}%;border-radius:var(--radius-sm)"></div>
      </div>
      <div style="display:flex;justify-content:space-between;color:var(--text-muted)">
        <span>分析次数：${monthly ? monthly.analysis_count : 0}</span>
        <span>${pct}%</span>
      </div>
    `;
    document.getElementById('token-sidebar').style.display = 'block';
  } catch {
    // Stats not available, hide sidebar
  }
}

window._startAnalysis = async () => {
  const input = document.getElementById('query-input');
  const query = input.value.trim();
  if (query.length < 3) { showToast('查询内容过短', 'error'); return; }

  const btn = document.getElementById('btn-analyze');
  const btnStop = document.getElementById('btn-stop');
  btn.disabled = true;
  btn.textContent = '启动中...';

  try {
    const result = await API.analyze(query);
    currentTaskId = result.task_id;

    document.getElementById('analysis-area').style.display = 'block';
    document.getElementById('intent-preview').textContent = `意图：${result.intent_preview || '识别中...'}`;
    btnStop.style.display = 'inline-flex';
    btn.style.display = 'none';

    document.getElementById('timeline').innerHTML = '';
    document.getElementById('report-content').innerHTML = '<p style="color:var(--text-muted)">正在连接分析流...</p>';
    document.getElementById('cursor').style.display = 'inline-block';

    startSSE(result.task_id);
  } catch (err) {
    showToast(err.message, 'error');
    btn.disabled = false;
    btn.textContent = '开始分析';
  }
};

window._stopAnalysis = async () => {
  if (!currentTaskId) return;
  try {
    await API.stop(currentTaskId);
    showToast('分析已停止');
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
      addTimeline('意图识别完成', `${data.intent}（置信度：${data.confidence}）`, 'info');
      document.getElementById('intent-preview').textContent = `意图：${data.intent}`;
      showIntentSwitcher();
    },
    intent_switched: (data) => {
      addTimeline('调研路径已切换', data.intent, 'plan');
      document.getElementById('intent-preview').textContent = `意图：${data.intent}`;
      hideIntentSwitcher();
    },
    plan_result: (data) => {
      addTimeline('分析计划已创建', `${data.research_questions?.length || 0} 个问题，数据源：${data.authoritative_sources?.join(', ')}`, 'plan');
    },
    data_source_query: (data) => {
      addTimeline(`正在查询 ${data.source.toUpperCase()}`, `实体：${data.entity}`, 'source');
    },
    data_source_hit: (data) => {
      updateTimelineLast(`${data.source.toUpperCase()} - 已找到`, 'success');
    },
    data_source_miss: (data) => {
      updateTimelineLast(`${data.source.toUpperCase()} - 未找到`, 'warning');
    },
    data_source_error: (data) => {
      updateTimelineLast(`${data.source.toUpperCase()} - 出错`, 'error');
    },
    enrichment_done: () => {
      addTimeline('信息丰富化完成', '', 'done');
    },
    agent_start: (data) => {
      addTimeline(`研究代理 ${data.agent_id}`, data.question, 'research');
    },
    thinking: (data) => {
      const el = document.getElementById('thinking-content');
      if (el) {
        const entry = document.createElement('div');
        entry.style.cssText = 'padding:4px 0;border-bottom:1px solid var(--border-hairline-soft)';
        entry.innerHTML = `<span style="color:var(--accent-primary);font-weight:600">[${data.agent_id || ''}]</span> ${escapeHtml(data.content || '')}`;
        el.appendChild(entry);
        el.scrollTop = el.scrollHeight;
      }
    },
    searching: (data) => {
      addTimeline(`  ${data.agent_id} 搜索中`, `"${data.query}"（第 ${data.round} 轮）`, 'search');
    },
    agent_done: (data) => {
      updateTimelineLast(`${data.agent_id} 完成 - ${data.findings_count} 条发现`, 'done');
    },
    ioc_extracted: (data) => {
      addTimeline('IOC 提取', `${data.ioc_count} 个 IOC`, 'done');
    },
    critic_done: (data) => {
      addTimeline('评审完成', `${data.issues_count} 个问题，置信度：${data.overall_confidence}`, 'done');
    },
    synthesizing: () => {
      addTimeline('报告合成', '正在生成报告...', 'research');
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
        `令牌：${data.token_usage?.input || 0} 输入 / ${data.token_usage?.output || 0} 输出 | 费用：$${data.cost_usd || 0}`;
      addTimeline('分析完成', `耗时：${data.duration_s}秒`, 'done');
      renderMarkdown();
    },
    error: (data) => {
      document.getElementById('cursor').style.display = 'none';
      addTimeline('错误', data.message, 'error');
      showToast(data.message, 'error');
    },
    stopped: () => {
      document.getElementById('cursor').style.display = 'none';
      document.getElementById('btn-stop').style.display = 'none';
      addTimeline('已停止', '分析已取消', 'warning');
    },
    agent_error: (data) => {
      addTimeline(`错误：${data.agent_id}`, data.message, 'error');
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

let intentSwitchTimer = null;

function showIntentSwitcher() {
  const el = document.getElementById('intent-switcher');
  if (!el) return;
  el.style.display = 'flex';
  clearTimeout(intentSwitchTimer);
  intentSwitchTimer = setTimeout(hideIntentSwitcher, 5000);
}

function hideIntentSwitcher() {
  const el = document.getElementById('intent-switcher');
  if (el) el.style.display = 'none';
  clearTimeout(intentSwitchTimer);
  intentSwitchTimer = null;
}

window._switchIntent = async (intent) => {
  if (!currentTaskId) return;
  try {
    await API.switchIntent(currentTaskId, intent);
    hideIntentSwitcher();
  } catch (err) {
    showToast(err.message, 'error');
  }
};

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
