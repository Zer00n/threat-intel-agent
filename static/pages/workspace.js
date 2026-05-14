import API from '../lib/api.js';
import { TIEventSource } from '../lib/sse.js';
import { formatDate, statusBadge, confidenceBadge, iocChip, showToast, copyToClipboard } from '../lib/utils.js';
import { getTechniqueNameZh } from '../lib/attck-i18n.js';

let currentSSE = null;
let currentTaskId = null;
const ACTIVE_TASK_KEY = 'ti-active-task-id';

export function renderWorkspace(container) {
  if (currentSSE) { currentSSE.abort(); currentSSE = null; }
  const taskToResume = sessionStorage.getItem(ACTIVE_TASK_KEY);
  if (!taskToResume) currentTaskId = null;

  // Set body class for workspace layout
  document.body.classList.add('page-workspace');

  // Update breadcrumb
  const breadcrumb = document.getElementById('header-breadcrumb');
  if (breadcrumb) {
    breadcrumb.innerHTML = '<a href="#/">工作区</a>';
  }

  container.innerHTML = `
    <div class="app-shell">
      <!-- ─────────────── 左侧栏 ─────────────── -->
      <aside class="sidebar">
        <section class="sidebar__pane sidebar__pane--history">
          <div class="sidebar__head">
            <h3>历史调研</h3>
            <span class="count" id="history-count">0</span>
          </div>
          <div class="history-controls">
            <div class="ti-input-wrap">
              <svg class="ti-input__icon" viewBox="0 0 16 16" fill="none">
                <circle cx="7" cy="7" r="5" stroke="currentColor" stroke-width="1.5"/>
                <path d="M11 11l3 3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
              </svg>
              <input id="history-search" class="ti-input ti-input--with-icon" placeholder="搜索 CVE / IOC / APT…" style="height: 28px; font-size: var(--text-xs);" />
            </div>
            <div class="filter-row" id="filter-intent">
              <span class="filter-chip" data-active data-value="">全部</span>
              <span class="filter-chip" data-value="cve">CVE</span>
              <span class="filter-chip" data-value="attack_technique">ATT&amp;CK</span>
              <span class="filter-chip" data-value="threat_actor">APT</span>
              <span class="filter-chip" data-value="ioc">IOC</span>
            </div>
          </div>
          <div class="history-list" id="sidebar-history"></div>
        </section>

        <section class="sidebar__pane sidebar__pane--timeline">
          <div class="sidebar__head">
            <h3>Agent 时间线</h3>
            <span class="count" id="timeline-count">0 / 0</span>
          </div>
          <div class="timeline" id="timeline">
            <div class="timeline__task" id="timeline-task" style="display:none">
              <span class="id" id="timeline-task-id"></span>
              <span class="elapsed" id="timeline-elapsed"></span>
            </div>
            <ul class="timeline__list" id="timeline-list"></ul>
          </div>
        </section>
      </aside>

      <!-- ─────────────── 主内容区 ─────────────── -->
      <main class="main">
        <!-- 顶部输入区 -->
        <section class="compose">
          <div class="compose__inner">
            <div class="compose__field">
              <textarea id="query-input" class="compose__textarea" rows="2"
                placeholder="输入 CVE 编号、ATT&CK 技术编号、APT 组织名或 IOC…"></textarea>
              <div class="compose__bar">
                <div class="compose__bar-left">
                  <button class="tlp-select" type="button" id="tlp-select" aria-label="选择 TLP 标记">
                    <span class="ti-badge ti-badge--tlp-green" id="tlp-badge" style="height: 16px; font-size: 9px;">GREEN</span>
                    <span class="tlp-select__chevron">▾</span>
                  </button>
                  <span class="ti-text-muted" style="font-size: var(--text-xs);">Ctrl + Enter 提交</span>
                </div>
                <div class="compose__bar-right">
                  <button id="btn-analyze" class="ti-btn ti-btn--primary ti-btn--sm" type="button">开始分析</button>
                  <button id="btn-stop" class="ti-btn ti-btn--danger ti-btn--sm" type="button" style="display:none">
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor"><rect width="10" height="10" rx="1.5"/></svg>
                    停止
                  </button>
                </div>
              </div>
            </div>
          </div>

          <!-- 意图识别预览条 -->
          <div id="intent-banner" class="intent-banner" style="display:none">
            <div class="intent-banner__lead">
              <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5">
                <circle cx="8" cy="8" r="6"/>
                <path d="M8 5v3.5l2 1.5" stroke-linecap="round"/>
              </svg>
              <span>已识别为</span>
              <span class="intent-banner__intent" id="intent-type"></span>
            </div>
            <span class="intent-banner__sep"></span>
            <div class="intent-banner__sources" id="intent-sources"></div>
            <div class="intent-banner__countdown" id="intent-countdown" style="display:none">
              <span>自动执行 <span class="intent-banner__count-num" id="countdown-num">5</span></span>
              <button class="ti-btn ti-btn--secondary ti-btn--sm" type="button" id="btn-switch-intent">切换路径</button>
            </div>
          </div>
        </section>

        <!-- 报告渲染区 -->
        <section class="report-scroll" id="report-scroll" style="display:none">
          <div class="report-inner">
            <!-- 报告顶部工具条 -->
            <div class="report-toolbar" id="report-toolbar">
              <div class="report-toolbar__meta">
                <span>报告</span>
                <span class="ti-mono" id="report-id"></span>
                <span>·</span>
                <span id="report-status">正在流式生成…</span>
              </div>
              <div class="ti-btn-group" id="export-bar" role="group" aria-label="导出" style="display:none">
                <button class="ti-btn" onclick="window._export('md')">MD</button>
                <button class="ti-btn" onclick="window._export('pdf')">PDF</button>
                <button class="ti-btn" onclick="window._export('stix')">STIX</button>
                <button class="ti-btn" onclick="window._export('sigma')">Sigma</button>
                <button class="ti-btn" onclick="window._export('iocs')">IOC CSV</button>
                <button class="ti-btn" onclick="window._export('zip')">打包 .zip</button>
              </div>
            </div>

            <!-- 思考过程折叠 -->
            <details class="thinking" id="thinking-block">
              <summary class="thinking__head">
                <span class="thinking__chevron">▶</span>
                <span class="thinking__label">Agent 执行日志</span>
                <span class="thinking__count" id="thinking-count">折叠</span>
              </summary>
              <div class="thinking__body" id="thinking-content"></div>
            </details>

            <!-- Markdown 渲染区 -->
            <article class="md" id="report-content"></article>
            <span id="cursor" class="typing-cursor" style="display:none"></span>
          </div>
        </section>
      </main>
    </div>
  `;

  // Event bindings
  const input = document.getElementById('query-input');
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      window._startAnalysis();
    }
  });
  input.focus();

  // TLP selector
  const tlpLevels = ['GREEN', 'AMBER', 'AMBER+STRICT', 'RED'];
  let currentTlp = 'GREEN';
  document.getElementById('tlp-select').addEventListener('click', () => {
    const idx = (tlpLevels.indexOf(currentTlp) + 1) % tlpLevels.length;
    currentTlp = tlpLevels[idx];
    const badge = document.getElementById('tlp-badge');
    badge.textContent = currentTlp;
    badge.className = `ti-badge ti-badge--tlp-${currentTlp.toLowerCase().split('+')[0]}`;
  });

  // Analyze button
  document.getElementById('btn-analyze').addEventListener('click', window._startAnalysis);

  // Stop button
  document.getElementById('btn-stop').addEventListener('click', window._stopAnalysis);

  // Switch intent button
  document.getElementById('btn-switch-intent')?.addEventListener('click', () => {
    showIntentSwitcher();
  });

  // History filter chips
  document.getElementById('filter-intent').addEventListener('click', (e) => {
    const chip = e.target.closest('.filter-chip');
    if (!chip) return;
    document.querySelectorAll('#filter-intent .filter-chip').forEach(c => c.removeAttribute('data-active'));
    chip.setAttribute('data-active', '');
    _loadSidebarHistory(chip.dataset.value);
  });

  // History search
  let searchTimeout;
  document.getElementById('history-search').addEventListener('input', (e) => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      const activeFilter = document.querySelector('#filter-intent .filter-chip[data-active]');
      _loadSidebarHistory(activeFilter?.dataset.value || '', e.target.value);
    }, 300);
  });

  // Load sidebar history
  _loadSidebarHistory();

  // Load token usage
  _loadTokenUsage();

  if (taskToResume) {
    resumeRunningTask(taskToResume);
  }
}

async function _loadSidebarHistory(intent = '', search = '') {
  const list = document.getElementById('sidebar-history');
  const countEl = document.getElementById('history-count');
  if (!list) return;

  try {
    const params = { limit: 20 };
    if (intent) params.intent = intent;
    if (search) params.q = search;
    const data = await API.history(params);

    countEl.textContent = data.total;

    list.innerHTML = data.items.map(item => `
      <a class="history-item ${item.id === currentTaskId ? 'data-active' : ''}" onclick="window._openHistory('${item.id}')">
        <div class="history-item__top">
          <span class="ti-status-dot ti-status-dot--${item.status === 'running' ? 'running' : item.status === 'completed' ? 'completed' : item.status === 'failed' ? 'failed' : 'waiting'}"></span>
          <span class="history-item__title">${escapeHtml(item.query)}</span>
        </div>
        <div class="history-item__bottom">
          <span class="history-item__intent">${item.intent || ''}</span>
          <span>${formatDate(item.created_at)}</span>
        </div>
      </a>
    `).join('');
  } catch {
    list.innerHTML = '<div style="padding:var(--space-3);font-size:var(--text-xs);color:var(--text-muted)">加载失败</div>';
  }
}

async function _loadTokenUsage() {
  try {
    const stats = await API.stats();
    const currentMonth = new Date().toISOString().slice(0, 7);
    const monthly = (stats.monthly_usage || []).find(m => m.year_month === currentMonth);
    // Budget: try CNY first, fall back to USD * 7.2
    const budgetCny = stats.monthly_budget_cny || (stats.monthly_budget_usd || 50) * 7.2;
    const spent = monthly ? (monthly.total_cost_usd || 0) : 0;
    const remaining = Math.max(0, budgetCny - spent);
    const pct = budgetCny > 0 ? Math.round((spent / budgetCny) * 100) : 0;

    document.getElementById('usage-bar').style.width = `${Math.min(pct, 100)}%`;
    document.getElementById('usage-monthly').textContent = `¥${remaining.toFixed(2)}`;
    document.getElementById('usage-widget').style.display = 'flex';
  } catch {
    // Stats not available
  }
}

window._openHistory = (id) => {
  if (id === currentTaskId) {
    window.location.hash = '#/';
    return;
  }
  window.location.hash = `#/history/${id}`;
};

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
    sessionStorage.setItem(ACTIVE_TASK_KEY, result.task_id);

    showRunningTaskUI(result.task_id, { reset: true });

    // Update breadcrumb
    const breadcrumb = document.getElementById('header-breadcrumb');
    if (breadcrumb) {
      breadcrumb.innerHTML = `
        <a href="#/">工作区</a>
        <span class="sep">›</span>
        <span class="app-header__taskid">${result.task_id.slice(0, 8)}</span>
        <span class="ti-badge ti-badge--info" style="margin-left: 4px;">运行中</span>
      `;
    }

    // Show intent banner
    showIntentBanner(result.intent_preview || '识别中...');

    startSSE(result.task_id);
  } catch (err) {
    showToast(err.message, 'error');
    btn.disabled = false;
    btn.textContent = '开始分析';
  }
};

window._resumeRunningTask = (id) => {
  if (!id) return;
  sessionStorage.setItem(ACTIVE_TASK_KEY, id);
  window.location.hash = '#/';
};

window._suspendWorkspace = () => {
  if (currentSSE) {
    currentSSE.abort();
    currentSSE = null;
  }
  if (elapsedInterval) {
    clearInterval(elapsedInterval);
    elapsedInterval = null;
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
let agentTraceCount = 0;
let reportBuffer = '';
let renderScheduled = false;
let elapsedSeconds = 0;
let elapsedInterval = null;

function startSSE(taskId) {
  startSSEWithOptions(taskId, {});
}

function startSSEWithOptions(taskId, options = {}) {
  timelineItems = [];
  agentTraceCount = 0;
  if (options.resetBuffer !== false) reportBuffer = '';
  elapsedSeconds = 0;

  // Start elapsed timer
  if (elapsedInterval) clearInterval(elapsedInterval);
  elapsedInterval = setInterval(() => {
    elapsedSeconds++;
    const el = document.getElementById('timeline-elapsed');
    if (el) {
      const m = Math.floor(elapsedSeconds / 60);
      const s = elapsedSeconds % 60;
      el.textContent = m > 0 ? `${m}m ${s}s` : `${s}s`;
    }
  }, 1000);

  const handlers = {
    intent_classified: (data) => {
      addTimeline('意图识别', `${data.intent}（置信度：${data.confidence}）`, 'intent', 'completed');
      showIntentBanner(data.intent);
    },
    intent_switched: (data) => {
      addTimeline('路径切换', data.intent, 'intent', 'completed');
      hideIntentBanner();
    },
    plan_result: (data) => {
      addTimeline('规划', `${data.research_questions?.length || 0} 个问题`, 'planner', 'completed');
    },
    data_source_query: (data) => {
      addTimeline(`${data.source.toUpperCase()}`, `查询 ${data.entity}`, 'data', 'running');
    },
    data_source_hit: (data) => {
      updateTimelineLast(`${data.source.toUpperCase()}`, '命中', 'completed');
    },
    data_source_miss: (data) => {
      updateTimelineLast(`${data.source.toUpperCase()}`, '未命中', 'failed');
    },
    data_source_error: (data) => {
      updateTimelineLast(`${data.source.toUpperCase()}`, '出错', 'failed');
    },
    enrichment_done: () => {
      addTimeline('数据增强', '完成', 'data', 'completed');
    },
    agent_start: (data) => {
      addTimeline(`${data.agent_id}`, data.question, 'research', 'running');
    },
    thinking: (data) => {
      addAgentTrace({
        agent_id: data.agent_id || 'agent',
        agent_type: 'Agent',
        action: (data.content || '').startsWith('Research round') ? 'round_start' : 'thinking',
        title: data.content || 'Thinking update',
        summary: data.content || '',
        status: 'running',
        details: {},
      });
    },
    agent_trace: (data) => {
      addAgentTrace(data);
    },
    searching: (data) => {
      addTimeline(`${data.agent_id}`, `搜索「${data.query}」第 ${data.round} 轮`, 'research', 'running');
    },
    agent_done: (data) => {
      updateTimelineLast(`${data.agent_id}`, `${data.findings_count} 条发现`, 'completed');
    },
    agent_error: (data) => {
      addTimeline(`错误：${data.agent_id}`, data.message, 'error', 'failed');
    },
    agent_timeout: (data) => {
      addTimeline(`超时：${data.agent_id}`, `${data.timeout_s}s`, 'error', 'failed');
    },
    ioc_extracting: () => {
      addTimeline('IOC 提取', '提取中...', 'extract', 'running');
    },
    ioc_extracted: (data) => {
      updateTimelineLast('IOC 提取', `${data.ioc_count} 个 IOC`, 'completed');
    },
    critic_review: () => {
      addTimeline('Critic 审查', '审查中...', 'critic', 'running');
    },
    critic_done: (data) => {
      updateTimelineLast('Critic 审查', `${data.issues_count} 个问题，置信度 ${data.overall_confidence}`, 'completed');
    },
    synthesizing: () => {
      addTimeline('Synthesis', '生成报告...', 'synth', 'running');
    },
    report_chunk: (data) => {
      reportBuffer += data.content;
      scheduleRender();
    },
    sigma_generating: () => {
      addTimeline('Sigma 生成', '生成检测规则...', 'sigma', 'running');
    },
    sigma_generated: (data) => {
      updateTimelineLast('Sigma 生成', `${data.rules_count} 条规则`, 'completed');
    },
    done: (data) => {
      clearActiveTask();
      if (elapsedInterval) { clearInterval(elapsedInterval); elapsedInterval = null; }
      document.getElementById('cursor').style.display = 'none';
      document.getElementById('btn-stop').style.display = 'none';
      document.getElementById('btn-analyze').style.display = 'inline-flex';
      document.getElementById('btn-analyze').disabled = false;
      document.getElementById('btn-analyze').textContent = '开始分析';
      document.getElementById('export-bar').style.display = 'inline-flex';
      document.getElementById('report-status').textContent =
        `完成 · 令牌 ${data.token_usage?.input || 0}入/${data.token_usage?.output || 0}出 · ¥${(data.cost_usd || 0).toFixed(4)}`;
      addTimeline('完成', `${data.duration_s}秒`, 'done', 'completed');
      renderMarkdown();
      _loadSidebarHistory();
      // Update usage widget with current task data
      const tokens = (data.token_usage?.input || 0) + (data.token_usage?.output || 0);
      document.getElementById('usage-current').textContent = tokens > 0 ? `${(tokens / 1000).toFixed(1)}k` : '--';
      _loadTokenUsage();
    },
    error: (data) => {
      clearActiveTask();
      if (elapsedInterval) { clearInterval(elapsedInterval); elapsedInterval = null; }
      document.getElementById('cursor').style.display = 'none';
      document.getElementById('btn-stop').style.display = 'none';
      document.getElementById('btn-analyze').style.display = 'inline-flex';
      document.getElementById('btn-analyze').disabled = false;
      document.getElementById('btn-analyze').textContent = '开始分析';
      addTimeline('错误', data.message, 'error', 'failed');
      showToast(data.message, 'error');
    },
    stopped: () => {
      clearActiveTask();
      if (elapsedInterval) { clearInterval(elapsedInterval); elapsedInterval = null; }
      document.getElementById('cursor').style.display = 'none';
      document.getElementById('btn-stop').style.display = 'none';
      document.getElementById('btn-analyze').style.display = 'inline-flex';
      document.getElementById('btn-analyze').disabled = false;
      document.getElementById('btn-analyze').textContent = '开始分析';
      addTimeline('已停止', '分析已取消', 'warning', 'interrupted');
    },
    budget_exceeded: (data) => {
      clearActiveTask();
      if (elapsedInterval) { clearInterval(elapsedInterval); elapsedInterval = null; }
      document.getElementById('cursor').style.display = 'none';
      addTimeline('预算超限', data.message, 'error', 'failed');
      showToast(data.message, 'error');
    },
    timeout: (data) => {
      clearActiveTask();
      if (elapsedInterval) { clearInterval(elapsedInterval); elapsedInterval = null; }
      document.getElementById('cursor').style.display = 'none';
      addTimeline('超时', data.message, 'error', 'failed');
      showToast(data.message, 'error');
    },
  };

  currentSSE = new TIEventSource(taskId, handlers, {
    lastEventId: options.replay ? 0 : null,
  });
}

function clearActiveTask() {
  sessionStorage.removeItem(ACTIVE_TASK_KEY);
}

async function resumeRunningTask(taskId) {
  currentTaskId = taskId;
  showRunningTaskUI(taskId, { reset: true });
  showToast('已恢复运行中的分析任务');
  startSSEWithOptions(taskId, { replay: true });
}

function showRunningTaskUI(taskId, { reset = false } = {}) {
  currentTaskId = taskId;
  document.getElementById('report-scroll').style.display = 'block';
  document.getElementById('btn-stop').style.display = 'inline-flex';
  document.getElementById('btn-analyze').style.display = 'none';
  document.getElementById('btn-analyze').disabled = false;

  const timelineTask = document.getElementById('timeline-task');
  if (timelineTask) timelineTask.style.display = 'flex';
  document.getElementById('timeline-task-id').textContent = taskId.slice(0, 8);
  document.getElementById('timeline-elapsed').textContent = '0s';
  document.getElementById('report-id').textContent = taskId.slice(0, 8);
  document.getElementById('report-status').textContent = '正在运行...';
  document.getElementById('cursor').style.display = 'inline-block';
  document.getElementById('export-bar').style.display = 'none';

  if (reset) {
    timelineItems = [];
    agentTraceCount = 0;
    reportBuffer = '';
    document.getElementById('timeline-list').innerHTML = '';
    document.getElementById('thinking-content').innerHTML = '';
    document.getElementById('thinking-count').textContent = '折叠';
    document.getElementById('report-content').innerHTML = '<p style="color:var(--text-muted)">正在恢复分析流...</p>';
  }

  const breadcrumb = document.getElementById('header-breadcrumb');
  if (breadcrumb) {
    breadcrumb.innerHTML = `
      <a href="#/">工作区</a>
      <span class="sep">›</span>
      <span class="app-header__taskid">${taskId.slice(0, 8)}</span>
      <span class="ti-badge ti-badge--info" style="margin-left: 4px;">运行中</span>
    `;
  }
}

function addAgentTrace(data) {
  const root = document.getElementById('thinking-content');
  if (!root) return;

  const agentId = data.agent_id || 'agent';
  let group = [...root.querySelectorAll('.agent-trace')]
    .find(el => el.dataset.agentTrace === agentId);
  if (!group) {
    group = document.createElement('details');
    group.className = 'agent-trace';
    group.open = true;
    group.dataset.agentTrace = agentId;
    group.innerHTML = `
      <summary class="agent-trace__head">
        <span class="agent-trace__chev">▶</span>
        <span class="agent-trace__name">${escapeHtml(agentId)}</span>
        <span class="agent-trace__type">${escapeHtml(data.agent_type || 'Agent')}</span>
        <span class="agent-trace__count" data-agent-count>0 steps</span>
      </summary>
      <div class="agent-trace__body"></div>
    `;
    root.appendChild(group);
  }

  const body = group.querySelector('.agent-trace__body');
  const step = document.createElement('details');
  step.className = 'agent-step';
  if (data.status === 'running' || data.action === 'tool_result' || data.action === 'submit_findings') {
    step.open = true;
  }
  step.innerHTML = `
    <summary class="agent-step__head">
      <span class="agent-step__dot"><span class="ti-status-dot ti-status-dot--${traceStatus(data.status)}"></span></span>
      <span class="agent-step__title">${escapeHtml(data.title || data.action || 'Step')}</span>
      ${data.round ? `<span class="agent-step__round">Round ${data.round}</span>` : ''}
      <span class="agent-step__action">${escapeHtml(data.action || '')}</span>
    </summary>
    <div class="agent-step__body">
      ${data.summary ? `<p class="agent-step__summary">${escapeHtml(data.summary)}</p>` : ''}
      ${renderTraceDetails(data.details)}
    </div>
  `;
  body.appendChild(step);

  const count = body.querySelectorAll('.agent-step').length;
  const countEl = group.querySelector('[data-agent-count]');
  if (countEl) countEl.textContent = `${count} steps`;

  agentTraceCount++;
  const globalCount = document.getElementById('thinking-count');
  if (globalCount) globalCount.textContent = `${agentTraceCount} 步`;
  root.scrollTop = root.scrollHeight;
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

function addTimeline(label, detail, source, status = 'running') {
  timelineItems.push({ label, detail, source, status });
  const list = document.getElementById('timeline-list');
  if (!list) return;

  const item = document.createElement('li');
  item.className = 'timeline-item';
  item.innerHTML = `
    <span class="timeline-item__dot"><span class="ti-status-dot ti-status-dot--${status}"></span></span>
    <div class="timeline-item__head">
      <span class="timeline-item__label">${escapeHtml(label)}</span>
      <span class="timeline-item__source">${escapeHtml(source)}</span>
    </div>
    ${detail ? `<span class="timeline-item__meta">${escapeHtml(detail)}</span>` : ''}
  `;
  list.appendChild(item);

  // Scroll to bottom
  const timeline = document.getElementById('timeline');
  if (timeline) timeline.scrollTop = timeline.scrollHeight;

  // Update count
  const total = list.querySelectorAll('.timeline-item').length;
  const completed = list.querySelectorAll('.ti-status-dot--completed').length;
  document.getElementById('timeline-count').textContent = `${completed} / ${total}`;
}

function updateTimelineLast(label, detail, status) {
  const list = document.getElementById('timeline-list');
  if (!list) return;
  const items = list.querySelectorAll('.timeline-item');
  const last = items[items.length - 1];
  if (last) {
    const labelEl = last.querySelector('.timeline-item__label');
    const metaEl = last.querySelector('.timeline-item__meta');
    const dotEl = last.querySelector('.ti-status-dot');
    if (labelEl) labelEl.textContent = label;
    if (metaEl) metaEl.textContent = detail;
    if (dotEl) {
      dotEl.className = `ti-status-dot ti-status-dot--${status}`;
    }
  }
  // Update count
  const total = items.length;
  const completed = list.querySelectorAll('.ti-status-dot--completed').length;
  document.getElementById('timeline-count').textContent = `${completed} / ${total}`;
}

function showIntentBanner(intent) {
  const banner = document.getElementById('intent-banner');
  const typeEl = document.getElementById('intent-type');
  if (banner && typeEl) {
    typeEl.textContent = intent;
    banner.style.display = 'flex';
  }
}

function hideIntentBanner() {
  const banner = document.getElementById('intent-banner');
  if (banner) banner.style.display = 'none';
}

/**
 * Show intent switcher modal so user can override the auto-detected intent.
 */
function showIntentSwitcher() {
  if (!currentTaskId) return;
  const intentGroups = [
    { label: '漏洞相关', items: [
      { value: 'cve', label: 'CVE 漏洞' },
      { value: 'multi_cve', label: '多 CVE 关联' },
      { value: 'vulnerability_advisory', label: '漏洞公告' },
      { value: 'product_vulnerability', label: '产品漏洞' },
    ]},
    { label: 'ATT&CK / TTP', items: [
      { value: 'attack_technique', label: '攻击技术' },
      { value: 'tool_or_ttp', label: '工具 / TTP' },
    ]},
    { label: '威胁主体', items: [
      { value: 'threat_actor', label: '威胁组织' },
      { value: 'campaign', label: '攻击活动' },
    ]},
    { label: '恶意软件', items: [
      { value: 'malware', label: '恶意软件' },
      { value: 'malware_artifact', label: '恶意样本' },
    ]},
    { label: 'IOC 指标', items: [
      { value: 'ioc_ip', label: 'IP 地址' },
      { value: 'ioc_domain', label: '域名' },
      { value: 'ioc_hash', label: '文件哈希' },
      { value: 'ioc_email', label: '邮箱' },
      { value: 'ioc_filepath', label: '文件路径' },
    ]},
    { label: '其他', items: [
      { value: 'incident_analysis', label: '事件分析' },
      { value: 'threat_activity', label: '威胁动态' },
      { value: 'cwe', label: 'CWE 弱点' },
      { value: 'cpe', label: 'CPE 产品' },
      { value: 'generic', label: '通用调研' },
    ]},
  ];
  const overlay = document.createElement('div');
  overlay.className = 'ti-modal-backdrop';
  overlay.setAttribute('data-open', '');
  overlay.innerHTML = `
    <div class="ti-modal" style="max-width:480px">
      <div class="ti-modal__header">
        <h3 class="ti-modal__title">切换调研路径</h3>
        <button class="ti-btn ti-btn--ghost ti-btn--sm ti-modal__close" aria-label="关闭">✕</button>
      </div>
      <div class="ti-modal__body" style="max-height:400px;overflow-y:auto">
        ${intentGroups.map(g => `
          <div style="margin-bottom:var(--space-3)">
            <div style="font-size:var(--text-xs);color:var(--text-muted);margin-bottom:var(--space-1)">${g.label}</div>
            <div style="display:flex;flex-wrap:wrap;gap:var(--space-1)">
              ${g.items.map(item => `
                <button class="ti-btn ti-btn--secondary ti-btn--sm" data-intent="${item.value}">${item.label}</button>
              `).join('')}
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  const close = () => overlay.remove();
  overlay.querySelector('.ti-modal__close').addEventListener('click', close);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });

  overlay.querySelectorAll('[data-intent]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const intent = btn.dataset.intent;
      try {
        await API.switchIntent(currentTaskId, intent);
        hideIntentBanner();
        close();
        showToast(`已切换到 ${btn.textContent} 路径`);
      } catch (err) {
        showToast(err.message || '切换失败', 'error');
      }
    });
  });
}

// ─── 100ms throttle render (LOGIC PRESERVED, only DOM target changed) ───
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
    enhanceAttckLinks(el);
    wireIOCChips(el);
  } catch {
    el.textContent = reportBuffer;
  }
}

/**
 * Wire click handlers on IOC chips to show a popover with copy actions.
 */
function wireIOCChips(root) {
  root.querySelectorAll('.chip[data-ioc], .ti-chip[data-ioc]').forEach(chip => {
    if (chip.dataset.wired) return;
    chip.dataset.wired = '1';
    chip.addEventListener('click', (e) => {
      e.stopPropagation();
      // Close any other open popovers
      document.querySelectorAll('[data-popover-open]').forEach(c => {
        if (c !== chip) delete c.dataset.popoverOpen;
      });
      const isOpen = chip.hasAttribute('data-popover-open');
      if (isOpen) {
        delete chip.dataset.popoverOpen;
        return;
      }
      let ioc;
      try { ioc = JSON.parse(chip.dataset.ioc); } catch { return; }
      // Remove old popover if any
      const old = chip.querySelector('.ti-chip__popover');
      if (old) old.remove();
      const pop = document.createElement('span');
      pop.className = 'ti-chip__popover';
      pop.innerHTML = `
        <div class="ti-chip__popover-row">
          <span class="ti-chip__popover-label">类型</span>
          <span class="ti-chip__popover-value">${escapeHtml(ioc.ioc_type || '')}</span>
        </div>
        <div class="ti-chip__popover-row">
          <span class="ti-chip__popover-label">原值</span>
          <span class="ti-chip__popover-value">${escapeHtml(ioc.value || '')}</span>
        </div>
        <div class="ti-chip__popover-row">
          <span class="ti-chip__popover-label">安全值</span>
          <span class="ti-chip__popover-value">${escapeHtml(ioc.value_defanged || '')}</span>
        </div>
        <div class="ti-chip__popover-actions">
          <button class="ti-btn ti-btn--secondary ti-btn--sm" data-copy="value">复制原值</button>
          <button class="ti-btn ti-btn--secondary ti-btn--sm" data-copy="defanged">复制安全值</button>
        </div>
      `;
      pop.querySelectorAll('[data-copy]').forEach(btn => {
        btn.addEventListener('click', (ev) => {
          ev.stopPropagation();
          const text = btn.dataset.copy === 'defanged' ? (ioc.value_defanged || ioc.value) : ioc.value;
          copyToClipboard(text);
          delete chip.dataset.popoverOpen;
        });
      });
      chip.appendChild(pop);
      chip.dataset.popoverOpen = '';
    });
  });
}

// Close IOC popovers when clicking outside
document.addEventListener('click', (e) => {
  if (!e.target.closest('.chip[data-ioc], .ti-chip[data-ioc]')) {
    document.querySelectorAll('[data-popover-open]').forEach(c => delete c.dataset.popoverOpen);
  }
});

/**
 * Post-process rendered HTML to auto-link ATT&CK technique IDs (e.g., T1059.001)
 * with tooltip showing Chinese translation.
 */
function enhanceAttckLinks(root) {
  // Match text nodes that contain ATT&CK technique IDs: T1xxx(.xxx)
  const ATTCK_RE = /\b(T\d{4}(?:\.\d{2,3})?)\b/g;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      // Skip inside <code>, <pre>, <a> tags
      let parent = node.parentElement;
      while (parent && parent !== root) {
        const tag = parent.tagName;
        if (tag === 'CODE' || tag === 'PRE' || tag === 'A') return NodeFilter.FILTER_REJECT;
        parent = parent.parentElement;
      }
      return ATTCK_RE.test(node.textContent) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
    },
  });

  const nodesToReplace = [];
  let node;
  while ((node = walker.nextNode())) {
    nodesToReplace.push(node);
  }

  for (const textNode of nodesToReplace) {
    const frag = document.createDocumentFragment();
    let lastIndex = 0;
    const text = textNode.textContent;
    ATTCK_RE.lastIndex = 0;
    let match;
    while ((match = ATTCK_RE.exec(text)) !== null) {
      // Preceding text
      if (match.index > lastIndex) {
        frag.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
      }
      // Create tooltip span
      const techniqueId = match[1];
      const zhName = getTechniqueNameZh(techniqueId, '');
      const span = document.createElement('span');
      span.className = 'attck-tooltip';
      span.textContent = techniqueId;
      if (zhName) {
        const popup = document.createElement('span');
        popup.className = 'attck-tooltip__popup';
        popup.innerHTML = `<strong>${techniqueId}</strong>${zhName}`;
        span.appendChild(popup);
      }
      frag.appendChild(span);
      lastIndex = ATTCK_RE.lastIndex;
    }
    // Trailing text
    if (lastIndex < text.length) {
      frag.appendChild(document.createTextNode(text.slice(lastIndex)));
    }
    textNode.parentNode.replaceChild(frag, textNode);
  }
}
// ─── END throttle render ───

window._export = (format) => {
  if (!currentTaskId) return;
  API.download(`/export/${format}/${currentTaskId}`);
};

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function escapeAttr(str) {
  return escapeHtml(str).replace(/"/g, '&quot;');
}
