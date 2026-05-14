# Threat Intel Agent v2.0 开发进度记录

**最后更新**: 2026-05-14

---

## 项目概览

| 指标 | 数值 |
|------|------|
| 项目文件 | 115+ |
| 测试用例 | 118 (全部通过) |
| 数据库表 | 14 + 1 FTS5 |
| API 端点 | 23 |
| Agent | 7 |
| 后台 Worker | 5 |

---

## 已完成阶段

### Phase 1: 工程骨架 ✅
- 项目结构、依赖配置
- 数据库 ORM 模型 (14 张表)
- 配置系统 (Pydantic Settings)
- 工具函数 (time, slug, crypto)
- FastAPI 实例 + lifespan

### Phase 2: 数据源层 ✅
- NVD API 2.0 适配器 (限流 + 重试)
- CISA KEV 全量下载 + 本地索引
- EPSS API 适配器
- MITRE ATT&CK 本地 STIX bundle (25,843 对象)
- GitHub Advisory GraphQL
- 并发编排器 + 健康检查

### Phase 3: Agent 流水线 ✅
- IntentClassifier (正则优先 + LLM fallback)
- PlannerAgent (6 套调研模板)
- EnrichmentAgent (并行数据源 + 降级策略)
- ResearchAgent × N (ReAct + SearchCache)
- IOCExtractorAgent (正则 + LLM 双通道)
- CriticAgent (规则 + LLM 审查)
- SynthesisAgent (流式 + 完整 prompt)
- Orchestrator (超时 + 预算 + 持久化)

### Phase 4: API & SSE ✅
- POST /analyze (意图识别 + 任务创建)
- GET /stream/{task_id} (SSE + Last-Event-ID)
- POST /analyze/{id}/stop
- POST /analyze/{id}/refresh (增量刷新)
- GET /history (分页 + FTS 搜索)
- GET /history/{id} (详情)
- DELETE /history/{id}
- POST /history/batch_delete
- GET /sources/health
- POST /sources/test/{name}
- POST /sources/refresh_attck
- POST /sources/refresh_kev
- GET /settings
- PUT /settings
- GET /settings/trusted_sources
- POST /settings/trusted_sources
- DELETE /settings/trusted_sources/{domain}
- GET /health

### Phase 5: 导出 ✅
- Markdown (YAML frontmatter)
- PDF (WeasyPrint + CJK 字体)
- STIX 2.1 Bundle (vulnerability + indicator + attack-pattern + threat-actor + relationship SRO)
- IOC CSV (UTF-8 BOM + defanged/live)
- Sigma Rules (最多 3 条 + AI 标记)
- ZIP 打包

### Phase 6: 前端 ✅
- SPA 5 页面 (workspace, history, detail, settings, sources)
- SSE 客户端 (重连 + 节流)
- 流式渲染 (100ms 节流 + 打字机光标)
- Light/Dark 主题切换
- IOC chip + ATT&CK 高亮

### Phase 7: P0/P1 修复 ✅
- 中间状态落库 (findings/iocs/cve_refs/attack_techniques/agent_logs)
- 降级策略 (NVD→web_search, KEV→缓存, EPSS→跳过)
- health_check worker 实际执行
- 超时机制 (全局 8min + 分步超时)
- Token 预算检查 (per-task + 月度)
- 增量刷新端点
- STIX 完善 (relationship + threat-actor)
- sources_used 写入
- 后台 worker 注册
- 审计日志

---

## Prompt 文件

| 文件 | Agent | 状态 |
|------|-------|------|
| `app/agents/prompts/intent.md` | IntentClassifier | ✅ |
| `app/agents/prompts/planner.md` | PlannerAgent | ✅ |
| `app/agents/prompts/researcher.md` | ResearchAgent | ✅ |
| `app/agents/prompts/ioc_extractor.md` | IOCExtractor | ✅ |
| `app/agents/prompts/critic.md` | CriticAgent | ✅ |
| `app/agents/prompts/synthesis.md` | SynthesisAgent | ✅ (用户重写, 476 行专业级) |

---

## 配置说明

### .env 关键配置

```bash
# API Key
ANTHROPIC_API_KEY=sk-xxx

# 第三方 API (硅基流动等)
ANTHROPIC_BASE_URL=https://api.siliconflow.cn/v1
ANTHROPIC_MODEL=deepseek-ai/DeepSeek-V3.2
API_FORMAT=openai
```

### 支持的 API 格式

| API_FORMAT | 适用场景 |
|------------|---------|
| `anthropic` | Anthropic 官方 API |
| `openai` | 硅基流动、DeepSeek、OpenRouter 等 |

---

## 已知限制

### 未实现功能 (P2)
- ~~思考过程折叠块 (FR-23)~~ ✅ 已确认完整实现
- ~~Token 月度余量侧栏 (FR-25)~~ ✅ 已确认完整实现
- ~~IOC chip 点击交互 (FR-26)~~ ✅ 已实现（popover + 复制）
- ~~switch_intent 联动 (FR-04)~~ ✅ 已实现（modal 选择器）
- ~~输入注入定界符 (§14.1)~~ ✅ 已实现（全部 7 个 Agent）
- ~~cache_cleanup worker~~ ✅ 已实现（调用 cleanup_expired）

### 测试覆盖
- 单元测试: 38 个 ✅（含新增 cache_cleanup + injection_defense）
- 集成测试: 30 个 ✅（含新增 export STIX/Sigma/ZIP、settings CRUD、switch_intent、audit_logs）
- Agent 测试: 48 个 ✅
- E2E 测试: 2 个（需手动启用）

---

## 启动方式

### 一键启动 (Windows)
```bash
# 双击 start.bat
```

### 手动启动
```bash
cd "D:\Office\claude code\AI-SEC-AGENTS"
source venv/Scripts/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 访问地址
- 前端: http://127.0.0.1:8000
- API 文档: http://127.0.0.1:8000/docs

---

## 测试结果 (最近一次)

```
CVE-2024-21413 分析测试:
- 状态: completed
- Token Input: 12,907
- Token Output: 1,078
- 成本: $0.055
- 耗时: 103 秒
- 报告长度: 4,376 字符
- 意图识别: cve ✅
- 数据源: NVD/KEV/EPSS ✅
- ATT&CK: 3 个技术 ✅
```
