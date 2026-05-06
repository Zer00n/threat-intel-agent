# PRD 整改说明

**整改日期**: 2026-05-06  
**对应文档**: `threat-intel-agent-prd-v2.md`  
**整改目标**: 根据代码审查结果，修复影响 PRD v2.0 闭环交付的运行、缓存、路径切换、审计、导出和接口缺口。

---

## 1. 整改摘要

本次整改重点处理以下问题：

- 修复 OpenAI 兼容模式缺少 `openai` 依赖的问题。
- 修复 `.env.example` 中模型默认值和 `RESEARCHER_MAX_ROUNDS` 环境变量名称。
- 服务启动时自动创建 SQLite FTS5 表和同步触发器，不再依赖手工初始化脚本才能使用全文搜索。
- 权威数据源调用接入 `data_source_cache`，支持 TTL 缓存和 `from_cache` 标记。
- 同一次分析内多个 ResearchAgent 共享 `SearchCache`。
- `switch_intent` 从空接口改为真实 5 秒决策窗口内可生效的路径切换。
- 前端新增 5 秒调研路径切换入口。
- SSE 事件实时写入 `agent_logs`，中断任务也能保留轨迹。
- 增加缺失的 `/history/{id}/diff/{compare_id}`、`/export/batch`、`/stats`、`/audit_logs` 接口。
- 修正 PDF 导出失败时返回伪 PDF 的问题。
- 设置 API Key 加密密钥自动持久化到 `data/secrets.key`。
- ATT&CK bundle 未初始化时提供最小内置兜底，保证基础校验和运行不崩溃。

---

## 2. PRD 对齐情况

| PRD 项 | 整改结果 |
|---|---|
| FR-04 路径展示/切换 | 后端 `switch_intent` 已写入 TaskManager 决策窗口，前端已提供 5 秒切换入口 |
| FR-07 跨 Agent 搜索缓存 | ResearchAgent 改为共享同一个任务级 SearchCache |
| FR-08 数据源健康检查 | 分析前增加限时健康检查，结果仍由后台 worker 写入状态表 |
| FR-05 / §7.6 数据源缓存 | Enrichment 编排层接入 `data_source_cache` |
| FR-12 中间状态持久化 | SSE 事件实时写入 `agent_logs` |
| FR-33 历史全文搜索 | 启动时自动创建 FTS5 表和触发器 |
| FR-35 增量刷新 diff | 新增历史 diff 接口用于比较 CVE、IOC、ATT&CK、成本和报告变化 |
| FR-36 历史归档导出 | 新增批量导出 ZIP 接口 |
| FR-39 API Key 管理 | 自动生成的加密密钥持久化，避免重启后无法解密 |
| FR-41 Token 预算 | 保留月度预算检查，并新增 `/stats` 暴露汇总视图 |
| §14.4 审计日志 | 增加导出、注入检测等审计记录，并新增审计日志查询接口 |

---

## 3. 修改文件

- `.env.example`
- `requirements.txt`
- `pyproject.toml`
- `app/db/engine.py`
- `app/scripts/init.py`
- `app/agents/enrichment/orchestrator.py`
- `app/agents/researcher.py`
- `app/agents/orchestrator.py`
- `app/task_manager.py`
- `app/routers/analyze.py`
- `app/routers/export.py`
- `app/routers/history.py`
- `app/routers/system.py`
- `app/exporters/pdf.py`
- `app/utils/crypto.py`
- `app/utils/attck_loader.py`
- `static/lib/api.js`
- `static/pages/workspace.js`
- `docs/remediation_report.md`

---

## 4. 验证结果

已执行：

```bash
python -m compileall -q app tests
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe -m pytest tests -q
```

结果：

```text
55 passed, 1 warning
```

额外验证：

- `init_db()` 可创建数据库、FTS5 表与触发器。
- FastAPI 路由已包含 `/stats`、`/audit_logs`、`/history/{analysis_id}/diff/{compare_id}`、`/export/batch`。

当前唯一警告为 `aiolimiter` 在测试中跨事件循环复用的 RuntimeWarning，未导致测试失败。后续如继续硬化，可把 NVD/EPSS 的全局 limiter 改为按事件循环或实例级创建。

---

## 5. 仍需后续强化的点

- PoC / 敏感信息默认遮蔽目前主要依赖报告 prompt 和前端展示约定，尚未做结构化 PoC 字段级控制。
- PDF 中文字体实际渲染质量仍依赖部署机器是否安装 CJK 字体。
- `POST /analyze/{id}/refresh` 已能创建刷新任务，diff 已补接口，但前端还没有完整 diff 可视化页面。
- Sigma 规则仍是启发式草稿生成，符合“AI 生成需人工审核”的最低要求，但距离生产级规则生成还有提升空间。
- 真实 API 端到端分析需要配置至少一个 LLM API Key 后再验证。

---

## 6. 需要注册的 API 与注册地址

### 必填：LLM API Key，至少选择一个

项目必须有一个可用大模型 API Key，否则 Agent 流水线无法完成 LLM 分类、研究、评审和报告合成。

| 供应商 | 用途 | 配置方式 | 注册/获取地址 |
|---|---|---|---|
| Anthropic Claude | 官方 Anthropic Messages API | `API_FORMAT=anthropic`，填写 `ANTHROPIC_API_KEY` | https://console.anthropic.com/ |
| OpenAI | OpenAI 兼容 chat completions | `API_FORMAT=openai`，`ANTHROPIC_BASE_URL=https://api.openai.com/v1`，填写 `ANTHROPIC_API_KEY` | https://platform.openai.com/api-keys |
| SiliconFlow 硅基流动 | 国内 OpenAI 兼容接口 | `API_FORMAT=openai`，`ANTHROPIC_BASE_URL=https://api.siliconflow.cn/v1` | https://cloud.siliconflow.cn/account/ak |
| DeepSeek | DeepSeek OpenAI 兼容接口 | `API_FORMAT=openai`，`ANTHROPIC_BASE_URL=https://api.deepseek.com/v1` | https://platform.deepseek.com/ |
| OpenRouter | 多模型聚合 OpenAI 兼容接口 | `API_FORMAT=openai`，`ANTHROPIC_BASE_URL=https://openrouter.ai/api/v1` | https://openrouter.ai/settings/keys |

说明：当前代码沿用 `ANTHROPIC_API_KEY` 这个配置名作为统一 LLM Key 字段；即使使用 OpenAI / SiliconFlow / DeepSeek / OpenRouter，也填到 `ANTHROPIC_API_KEY`。

### 推荐：数据源 API Key

| 供应商/数据源 | 是否必需 | 用途 | 注册/获取地址 |
|---|---:|---|---|
| NVD API Key | 推荐 | 提高 NVD API 限流额度，减少 CVE 查询失败 | https://nvd.nist.gov/developers/request-an-api-key |
| GitHub Token | 可选 | 启用 GitHub Advisory / GHSA GraphQL 查询 | https://github.com/settings/personal-access-tokens |

### 无需注册的默认数据源

- CISA KEV：公开 JSON feed，无需 API Key。
- EPSS：FIRST EPSS API 当前使用公开查询，无需 API Key。
- MITRE ATT&CK：初始化脚本下载公开 STIX bundle，无需 API Key。
- DuckDuckGo Lite：开放搜索补充当前无需 API Key，但稳定性不如正式搜索 API。

---

## 7. 推荐 `.env` 示例

### 使用 SiliconFlow

```bash
API_FORMAT=openai
ANTHROPIC_BASE_URL=https://api.siliconflow.cn/v1
ANTHROPIC_MODEL=deepseek-ai/DeepSeek-V3.2
ANTHROPIC_API_KEY=你的_SiliconFlow_API_Key
NVD_API_KEY=你的_NVD_API_Key
GITHUB_TOKEN=你的_GitHub_Token
```

### 使用 Anthropic 官方

```bash
API_FORMAT=anthropic
ANTHROPIC_BASE_URL=
ANTHROPIC_MODEL=claude-3-5-sonnet-20241022
ANTHROPIC_API_KEY=你的_Anthropic_API_Key
NVD_API_KEY=你的_NVD_API_Key
GITHUB_TOKEN=你的_GitHub_Token
```

