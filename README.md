# 威胁情报深度调研 Agent v0.6

企业 SOC 威胁情报调研助手。结合权威数据源（NVD、CISA KEV、EPSS、MITRE ATT&CK）与 AI 推理能力，自动生成结构化威胁情报报告。

> **v0.6 更新亮点**：全面重新设计前端 UI，采用 Inter 字体 + 冷蓝主色方案，全新的 `ti-*` BEM 组件库，视觉更美观、交互更流畅。

## 界面预览

| 工作台 | 历史记录 |
|:---:|:---:|
| ![工作台](docs/001.png) | ![历史记录](docs/002.png) |

| 系统设置 | 数据源 |
|:---:|:---:|
| ![系统设置](docs/003.png) | ![数据源](docs/004.png) |

## 系统架构

![系统架构](docs/ti_agent_system_architecture_layers.svg)

## 快速开始

```bash
# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 配置环境变量
cp .env.example .env
# 编辑 .env，填入 ANTHROPIC_API_KEY

# 初始化（创建数据库 + 下载 ATT&CK 数据）
python -m app.scripts.init

# 启动服务
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

浏览器访问 <http://127.0.0.1:8000>

## 核心功能

- **意图识别**：正则优先 + LLM 兜底，支持 CVE、ATT&CK、APT、IOC 等查询
- **权威数据源**：NVD、CISA KEV、EPSS、MITRE ATT&CK、GitHub Advisory
- **7-Agent 流水线**：IntentClassifier → Planner → Enrichment → Research × N → IOC Extractor → Critic → Synthesis
- **结构化输出**：Markdown 报告、STIX 2.1 Bundle、IOC CSV、Sigma 规则、PDF
- **实时流式**：SSE 推送 + Last-Event-ID 断线重连
- **Token 预算**：月度 + 单次任务限额，实时追踪用量

## v0.6 变更日志

- **全新前端 UI**：Inter 字体、冷蓝 #2563EB 主色、light/dark 双主题
- **`ti-*` BEM 组件库**：badge、chip、tag、modal、toast、skeleton 等 15+ 组件
- **页面级 CSS 拆分**：tokens → components → pages 三层架构
- **fix**：月度 Token 用量实时持久化，刷新页面不再归零
- **fix**：预算超限 SSE 事件字段名与前端对齐
- **新增**：new-design/ 设计参考文件、docs/design/ 组件演示页

## API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/analyze` | 启动分析 |
| GET | `/stream/{task_id}` | SSE 事件流 |
| POST | `/analyze/{id}/stop` | 停止分析 |
| POST | `/analyze/{id}/refresh` | 增量刷新 |
| GET | `/history` | 历史列表 |
| GET | `/history/{id}` | 分析详情 |
| DELETE | `/history/{id}` | 删除记录 |
| GET | `/export/{format}/{id}` | 导出（md/pdf/stix/iocs/sigma/zip） |
| GET | `/sources/health` | 数据源状态 |
| GET | `/settings` | 获取设置 |
| PUT | `/settings` | 更新设置 |
| GET | `/health` | 健康检查 |

## 技术栈

- **后端**：FastAPI + Python 3.11+ + SQLAlchemy async + SQLite WAL
- **AI**：支持 Anthropic API 和 OpenAI 兼容格式（硅基流动、DeepSeek、OpenRouter 等）
- **前端**：原生 HTML/CSS/JS SPA + ti-* 组件库（无框架依赖）
- **PDF**：WeasyPrint + 思源黑体

## 测试

```bash
pytest tests/ -v
```

## 项目结构

```
app/
  agents/          # 7-agent 流水线
  db/              # 数据库模型、引擎、仓储
  exporters/       # MD、PDF、STIX、CSV、Sigma、ZIP 导出
  routers/         # FastAPI 路由
  utils/           # IOC 正则、defang、slug、加密
  workers/         # 后台任务（健康检查、数据同步）
static/            # 前端 SPA
  assets/          # CSS（tokens、components、app、pages）
  lib/             # 核心 JS（api、sse、router、utils、app）
  pages/           # 页面组件（workspace、history-*、settings、sources）
  new-design/      # 新 UI 设计参考文件
templates/pdf/     # PDF HTML 模板
tests/             # 单元测试、Agent 测试、集成测试
docs/              # 文档（架构图、截图、开发进度）
```

## 配置说明

### 环境变量

```bash
# 必填
ANTHROPIC_API_KEY=sk-xxx

# 可选 - 第三方 API（硅基流动等）
ANTHROPIC_BASE_URL=https://api.siliconflow.cn/v1
ANTHROPIC_MODEL=deepseek-ai/DeepSeek-V3.2
API_FORMAT=openai

# 可选 - 数据源增强
NVD_API_KEY=        # 提升 NVD 限流额度
GITHUB_TOKEN=       # 启用 GitHub Advisory 查询
```

### 支持的 API 格式

| API_FORMAT | 适用场景 |
|------------|----------|
| `anthropic` | Anthropic 官方 API |
| `openai` | 硅基流动、DeepSeek、OpenRouter 等 OpenAI 兼容 API |

## 一键启动（Windows）

双击 `start.bat` 即可自动：

1. 创建虚拟环境
2. 安装依赖
3. 初始化数据库
4. 启动服务器

## 许可证

MIT License
