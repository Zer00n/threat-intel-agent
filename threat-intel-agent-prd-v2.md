# 威胁情报深度调研 Agent 系统 PRD v2.0

**版本**:v2.0(企业 SOC 定位重构版)  
**日期**:2026-05-05  
**前置版本**:v1.0(2026-05-04,定位为"AI 写作工具")  
**状态**:待开发  
**开发模式**:本地 Claude Code 实施 + Claude Design 设计核心页面

---

## 0. 版本变更记录

v2.0 相对 v1.0 的核心变化:

- **产品定位**:从"AI 辅助情报报告生成器"重定位为"企业 SOC 用的 TI 调研助手",目标用户从写作者改为 SOC 分析师/应急响应人员/安全咨询师
- **数据源策略**:从纯 web_search 改为"权威源直查 + 开放搜索补充"双层策略,接入 NVD / CISA KEV / EPSS / MITRE ATT&CK 等结构化数据源
- **输出形态**:从单一 Markdown 报告扩展为"Markdown 报告 + STIX 2.1 bundle + IOC CSV + Sigma 检测规则建议 + ATT&CK 映射"五种产物
- **Agent 流水线**:增加 IntentClassifier、EnrichmentAgent、IOCExtractorAgent、CriticAgent 四个新角色
- **可靠性设计**:补齐启动恢复、SSE 断连重连、Queue 背压、僵尸任务清理、agent_logs 实时落库等工程缺口
- **AI 工程**:Planner 改用 tool_use schema 而非 prompt 约束 JSON,增加共享搜索缓存与置信度评分
- **合规与安全**:增加 PoC 信息显示策略、TLP 标记、审计日志、输入注入防护
- **协作模式**:明确 Claude Design 与 Claude Code 的职责分工,定义设计 token 与组件库交付物

---

## 1. 产品定位与目标用户

### 1.1 产品定位

一款部署在企业内网的本地 Web 应用,将多个权威威胁情报源(NVD、CISA KEV、EPSS、MITRE ATT&CK 等)与 AI 推理能力结合,把一次安全查询(CVE 编号、ATT&CK 技术、APT 组织、IOC、自由文本描述)自动转化为**结构化、可直接用于检测与响应的情报产物**。

它不是写作工具,不是搜索引擎前端,也不是替代专业 TI 平台。它是 SOC 分析师手上的一个"调研放大器":把分析师原本要花 2-4 小时手动翻 NVD、查 KEV、对照 ATT&CK、整理 IOC 的工作,压缩到 5 分钟以内,且产出可直接喂给 SIEM / SOAR / 检测引擎。

### 1.2 目标用户与核心场景

- **甲方 SOC 分析师**:接到告警后快速调研涉及的 CVE 或攻击技术,判断是否在 KEV 列表、是否有现成检测规则、是否需要立即处置
- **乙方应急响应工程师**:到客户现场前快速搞清楚某个事件涉及的 TTPs,准备工具与处置预案
- **安全咨询师**:为客户出威胁通告、漏洞处置建议,需要权威来源 + 结构化输出
- **红蓝队**:HVV 期间快速摸清攻击面相关的漏洞利用情况(EPSS、PoC 是否公开、KEV 状态)

### 1.3 核心价值主张

- **权威优先**:CVE 元数据、KEV 状态、EPSS 分数等可结构化获取的信息,直接调用官方 API,不让 AI 去"猜"
- **结构化输出**:除了人读的 Markdown 报告,还输出 STIX bundle、IOC CSV、Sigma 规则草稿,可机读、可入库、可分发
- **可追溯**:每个事实声明都关联来源 URL,每个 IOC、CVE、技术编号都有置信度标记
- **过程透明**:实时展示 Agent 在做什么、查了哪些源、如何判断,便于分析师验证与学习

### 1.4 v1.0 不在范围内

- 多用户、组织、RBAC(单机部署,信任本地用户)
- 主动扫描、漏洞验证、PoC 执行(纯调研,不发起任何对外攻击性操作)
- 实时告警推送、订阅、邮件通知
- TAXII Server 接口(只导出 STIX 文件,不做服务端推送)
- 与 SIEM/SOAR 的双向集成(只单向导出)
- 商业 TI feed(VirusTotal、AlienVault OTX、Recorded Future 等)的接入,作为 v2.0 候选

---

## 2. 用户故事

| ID | 角色 | 故事 | 优先级 |
|----|------|------|--------|
| US-01 | SOC 分析师 | 输入 CVE 编号,在 5 分钟内得到包含 NVD 元数据、KEV 状态、EPSS 分数、PoC 情况、缓解建议的完整调研报告 | P0 |
| US-02 | SOC 分析师 | 看到报告附带的 IOC 清单(IP/Domain/Hash),可一键导出 CSV 直接导入 SIEM | P0 |
| US-03 | SOC 分析师 | 报告中的攻击技术自动映射到 MITRE ATT&CK 编号,我能一眼看到 tactic 分布 | P0 |
| US-04 | 应急响应工程师 | 输入 APT 组织名(如 APT41),系统识别意图并走 actor 调研路径,输出该组织的 TTPs、历史 IOC、关联恶意软件 | P0 |
| US-05 | 安全咨询师 | 把报告导出为带客户 Logo 与 TLP 标记的 PDF,中文字体正常渲染 | P0 |
| US-06 | SOC 分析师 | 实时看到每个 Agent 在查哪个数据源、找到了什么,而不是盯着 spinner 等待 | P0 |
| US-07 | 红队分析师 | 默认情况下 PoC 链接被遮蔽,我点击"显示风险信息"后才展开,符合最小披露原则 | P0 |
| US-08 | SOC 分析师 | 系统给出 Sigma 检测规则草稿,标注"AI 生成,需人工审核",我能复制到检测平台调整 | P1 |
| US-09 | 安全咨询师 | 历史报告按 query、时间、状态筛选,支持全文搜索 | P1 |
| US-10 | SOC 分析师 | 一份 7 天前的 CVE 报告,我能一键"刷新增量",系统对比 KEV/EPSS/PoC 状态变化并产出 diff | P1 |
| US-11 | SOC 分析师 | 系统显示当月 token 消耗与预估成本,超过预算阈值告警 | P1 |
| US-12 | 安全研究员 | 历史记录可删除、可批量删除、可导出归档 | P2 |

---

## 3. 核心概念与术语

| 术语 | 定义 |
|------|------|
| Intent | 系统对用户输入的分类结果,决定走哪条调研路径(cve / attack_technique / threat_actor / malware / ioc / generic) |
| Authoritative Source | 权威数据源,通过官方 API 调用而非搜索引擎获取(NVD、CISA KEV、EPSS、MITRE ATT&CK) |
| Open Source(此处) | 开放搜索源,通过 web_search 工具获取(技术博客、厂商公告、安全研究报告) |
| Finding | 一条独立的调研发现,包含 claim(声明)、source(来源)、confidence(置信度)三要素 |
| IOC | Indicator of Compromise,攻陷指标,本系统支持 IPv4 / IPv6 / Domain / URL / MD5 / SHA1 / SHA256 / Email / FilePath |
| TLP | Traffic Light Protocol,情报分级标记(WHITE / GREEN / AMBER / AMBER+STRICT / RED) |
| Admiralty Confidence | 简化的置信度评分:High(权威源直查)、Medium(多个开放源交叉验证)、Low(单一来源或 LLM 推理) |
| STIX Bundle | 结构化威胁信息表达 2.1 标准的 JSON 包,可被 MISP、OpenCTI、ThreatConnect 导入 |

---

## 4. 功能需求

### 4.1 输入识别与意图分类(FR-01 至 FR-04)

**FR-01 输入校验**
- 长度:最小 3 字符,最大 1000 字符(放宽自 v1.0 的 500,以容纳事件描述)
- 字符白名单过滤:剥离控制字符(`\x00-\x1f` 除 `\n\r\t`)、零宽字符(`U+200B-U+200D`)
- 提示注入检测:启发式检测包含 "ignore previous instructions"、"system prompt"、"忽略指令" 等模式时,记录到审计日志,但仍允许执行(只是把这部分内容包裹在用户输入定界符内)

**FR-02 意图分类(IntentClassifier)**

按以下顺序优先匹配,**正则命中即终止**,不进入 LLM:

| 意图 | 正则 / 匹配规则 | 示例 |
|------|----------------|------|
| `cve` | `CVE-\d{4}-\d{4,7}` | CVE-2024-21413 |
| `attack_technique` | `T\d{4}(\.\d{3})?` | T1059.001 |
| `cwe` | `CWE-\d{1,4}` | CWE-79 |
| `ioc_hash` | MD5/SHA1/SHA256 正则 | 5d41402abc4b2a76b9719d911017c592 |
| `ioc_ip` | IPv4 / IPv6 严格正则 | 192.0.2.1 |
| `ioc_domain` | 域名正则 + 至少一个点 | malicious.example.com |
| `cpe` | `cpe:2\.3:` 前缀 | cpe:2.3:a:apache:log4j:2.14.1:* |

正则未命中,交由 LLM 分类(走 tool_use schema,见 §8.2),候选意图:`threat_actor`、`malware`、`vulnerability_generic`、`incident_description`、`generic`。

**FR-03 路径分支**

不同意图启用不同的调研路径,每条路径有不同的"权威源调用清单 + 调研子问题模板":

- `cve` → NVD + KEV + EPSS + GHSA + 厂商公告搜索 + PoC 情况
- `attack_technique` → MITRE ATT&CK STIX + 关联组织/软件 + Sigma 规则参考
- `threat_actor` → ATT&CK Groups + 关联 malware/CVE + 公开报告搜索
- `malware` → ATT&CK Software + 已知 IOC + sandbox 报告搜索
- `ioc_*` → AbuseIPDB / MISP feed (v2.0) / VT (v2.0) + 关联事件搜索 (v1.0 仅做开放搜索 + 标注上下文)
- `generic` / 其他 → 通用四维度调研(类似 v1.0 行为)

**FR-04 路径展示**
- 分类完成后,前端时间线第一条显示 "意图识别:CVE 漏洞调研路径",并展示将要调用的数据源列表
- 用户可在 5 秒内点击"切换路径"按钮手动改路径(超时则继续按识别结果执行)

---

### 4.2 数据源调用与权威源策略(FR-05 至 FR-09)

**FR-05 权威源直查**

当意图为 `cve` 时,系统并行调用:
- NVD API 获取 CVSS、CWE、CPE、描述、参考链接
- CISA KEV catalog 检查是否被纳入已知利用清单
- EPSS API 获取利用概率分数与百分位
- GitHub Advisory(GHSA)查关联开源组件

每个源的返回结果落入 `data_source_cache` 表(TTL 见 §7.6),失败时不阻塞,记录失败原因并继续。

**FR-06 开放搜索补充**

权威源覆盖不到的维度(在野利用细节、安全研究分析、修复实战经验),由 ResearchAgent 用 web_search 工具补充。搜索 query 由 LLM 基于权威源结果生成,**避免重复查权威源已经返回的字段**(例:已经从 NVD 拿到 CVSS,就不要再搜 "CVE-XXX CVSS score")。

**FR-07 跨 Agent 共享缓存**

所有 ResearchAgent 共享一个 `SearchCache`,缓存 key 为 normalized query 字符串(小写 + 去标点 + 排序词),命中则直接复用,不重复调用 web_search。同一次分析内 cache TTL = 整个 task 生命周期。

**FR-08 数据源健康检查**

应用启动时和每次分析开始前,对必需的数据源执行健康检查(HEAD 请求或轻量查询),状态写入 `system_status` 表。前端"数据源管理"页面展示绿/黄/红三色状态。某个权威源不可用时:
- NVD 不可用 → 降级到 web_search 查 NVD 网页(标注 "降级源,数据可能滞后")
- KEV 不可用 → 报告中标注 "KEV 状态查询失败,请人工确认"
- EPSS 不可用 → 报告中省略 EPSS 字段,不阻塞
- MITRE ATT&CK 不可用 → 使用本地缓存的 STIX bundle(部署时预下载)

**FR-09 数据源限流遵守**

NVD API 默认 5 req/30s(无 key)或 50 req/30s(有 key)。系统使用 token bucket 限流器,**严格不超**官方限制。多个 Agent 并发调用同一个源时排队。

---

### 4.3 多 Agent 协作流水线(FR-10 至 FR-14)

**FR-10 Agent 角色清单**

| Agent | 输入 | 输出 | 是否流式 |
|-------|------|------|---------|
| IntentClassifier | 用户原始查询 | intent + entities | 否 |
| PlannerAgent | intent + entities | 子问题列表 + 数据源调用计划 | 否 |
| EnrichmentAgent | 数据源调用计划 | 各权威源返回的结构化数据 | 否(并发) |
| ResearchAgent ×N | 子问题 + Enrichment 结果 | findings(claim+source+confidence) | 否(并发) |
| IOCExtractorAgent | 所有 findings 的全文 | IOC 清单 + 上下文 | 否 |
| CriticAgent | 所有 findings + IOC | 异议清单(矛盾/低置信/缺源)+ 修订建议 | 否 |
| SynthesisAgent | 全部上述输出 | 最终 Markdown 报告 + 结构化产物 | **是** |

**FR-11 并发控制**

- EnrichmentAgent 内部 4-6 个数据源调用,asyncio.gather 全并发,各自有限流
- ResearchAgent 数量由 PlannerAgent 决定(2-5 个),并发执行,`return_exceptions=True`
- 同一时刻全局只允许一个分析任务(单用户场景),第二个请求返回 409

**FR-12 中间状态持久化**

每个 Agent 完成后立即把结果落库(`agent_logs` 表 + `findings` 表 + `iocs` 表),**不等到最后统一写**。这样:
- 用户中途停止,已有结果可回看
- 服务崩溃重启,可读取最后状态
- 历史详情页可显示完整轨迹

**FR-13 超时与停止**

- 单次分析全局超时 8 分钟(放宽自 v1.0 的 5 分钟,因为新增了多个权威源调用)
- 每个 Agent 自己的步骤超时:Enrichment 单源 15s、ResearchAgent 单轮搜索 30s、Synthesis 流式 120s
- 用户手动停止:`asyncio.CancelledError` 传播,各 Agent 在 catch 块中执行 cleanup,把当前已完成的部分作为最终结果保存

**FR-14 启动时状态修复**

应用启动时执行:
```sql
UPDATE analyses 
SET status = 'interrupted', 
    updated_at = NOW(),
    error_message = 'Service restarted while task was running'
WHERE status = 'running';
```
"interrupted" 是新增状态,前端显示为"已中断(服务重启)",和"stopped"区分。

---

### 4.4 结构化情报输出(FR-15 至 FR-21)

**FR-15 IOC 提取**

IOCExtractorAgent 用正则 + LLM 双通道提取:
- 正则提取:IPv4/IPv6/MD5/SHA1/SHA256/Domain/URL/Email/FilePath(Windows + Linux)
- LLM 提取:从上下文识别 "C2 服务器"、"投递域名" 等语义 IOC

每个 IOC 关联:`ioc_type`、`ioc_value`、`context`(出现的句子)、`source_agent_id`、`confidence`、`is_defanged`(原文是否已 defang,如 `1[.]2[.]3[.]4`)。

**FR-16 IOC defang/refang 处理**

- 报告默认显示 defang 形式(`malicious[.]example[.]com`、`hxxp://...`、`1[.]2[.]3[.]4`)
- IOC CSV 导出时提供两种格式选择:defanged(默认,适合邮件/文档)、live(适合直接喂给检测系统)

**FR-17 ATT&CK 技术映射**

SynthesisAgent 在生成报告时:
- 提示模型"如果描述了某种攻击行为,标注对应的 ATT&CK 技术编号"
- 生成的编号经过校验:必须存在于本地 ATT&CK STIX bundle,否则丢弃并记录
- 报告中展示:`T1059.001 (PowerShell)`,鼠标悬停显示该技术的 tactic 与简介

**FR-18 检测规则建议**

CriticAgent 完成后,触发可选的 RuleGenerator(LLM 调用):
- 输入:findings + IOCs + ATT&CK 技术
- 输出:Sigma 规则草稿(YAML 格式),最多 3 条
- 每条规则强制带 `description` 字段,内容包含 "AI generated, requires human review"
- 规则不写入数据库,只放在分析结果中,用户主动导出时才生成文件

**FR-19 置信度标注**

每个 finding 的 confidence:
- High:来自权威源直查(NVD/KEV/EPSS/MITRE),或多个独立源(不同域名)交叉验证
- Medium:单一开放源,但来源域名属于已知可信列表(预置 50+ 域名:nist.gov、cisa.gov、microsoft.com、redhat.com、unit42.paloaltonetworks.com 等)
- Low:单一开放源且不在可信列表,或纯 LLM 推理

**FR-20 来源可信度白名单**

应用内置可信域名列表(`trusted_sources.json`),用户可在"设置"页面添加/删除。SynthesisAgent 在引用来源时优先选择可信域。

**FR-21 报告主体结构**

```
# {查询主题} 威胁情报调研报告

## 元信息
- 调研时间:...
- 意图分类:...
- 数据源覆盖:NVD ✅ KEV ✅ EPSS ✅ ATT&CK ✅ 开放搜索 (12 个独立来源)
- TLP 标记:GREEN
- 整体置信度:High

## 执行摘要
3-5 句话,适合管理层

## 关键事实(权威源)
- CVSS 3.1: 9.8 (NVD)
- KEV: 已收录,加入日期 2024-08-15 (CISA)
- EPSS: 0.94 (96th percentile)
- 受影响产品: Microsoft Outlook ≤ 2024.0.x

## 技术细节
...

## 威胁态势
...PoC 信息折叠在"⚠️ 显示利用风险信息"按钮后...

## ATT&CK 映射
| 技术编号 | 名称 | Tactic |
|---------|------|--------|
| T1190 | Exploit Public-Facing Application | Initial Access |

## IOC 清单
(N 条,详见 IOC 表格 / 导出 CSV 查看完整列表)

## 检测规则建议
(Sigma 草稿,需人工审核)

## 缓解建议
...

## 信息缺口
- 暂无在野利用样本公开
- 厂商补丁未发布

## 来源(按置信度排序)
1. [High] NVD - https://nvd.nist.gov/vuln/detail/CVE-...
2. [High] CISA KEV - https://www.cisa.gov/...
3. [Medium] Vendor Advisory - https://...
```

---

### 4.5 实时展示(FR-22 至 FR-26)

**FR-22 时间线(左侧面板)**

按时间顺序展示 Agent 步骤,每条带状态图标、Agent 名、简短描述、时间戳。新增展示:
- 数据源调用项(`NVD 查询: CVE-2024-21413`),命中/未命中/失败用不同图标
- 意图识别结果与数据源调用计划

**FR-23 思考过程(右侧顶部,可折叠)**

展示 Agent 的中间推理(规划阶段、CriticAgent 的争议指出),不展示 token 级流式,只在 Agent 完成后整段追加。

**FR-24 报告流式渲染**

SynthesisAgent 流式生成时:
- 每收到一个 chunk 加入 buffer
- **节流渲染**:`requestAnimationFrame` 调度,最高每 100ms 重新渲染一次,避免 token 级抖动
- 使用 `marked.parse(buffer, { async: false, breaks: true })` 增量渲染
- 渲染区域底部跟随打字机光标

**FR-25 Token 与成本侧栏**

右上角小型组件:
- 当前任务已消耗 token(input + output 分别)
- 当前任务预估成本(USD)
- 当月累计与预算余量(预算从设置读)

**FR-26 实时 IOC 高亮**

报告中渲染出 IOC 时,用 chip 样式标注类型(IP / Hash / Domain),点击 chip 可:
- 复制原值或 defanged 值
- 在新分析中作为输入

---

### 4.6 报告与导出(FR-27 至 FR-32)

**FR-27 Markdown 导出**
- 内容:报告正文 + frontmatter(YAML 元信息块,含 query / intent / TLP / confidence / generated_at)
- 文件名:`ti-{intent}-{slug(query, 30)}-{YYYYMMDD-HHMM}.md`
- slug 函数:小写 + 非字母数字字符替换为 `-` + 连续 `-` 合并 + trim,**白名单字符,无路径注入风险**

**FR-28 PDF 导出**
- 工具:WeasyPrint
- 中文字体:思源黑体(Noto Sans CJK SC)+ 思源宋体(Noto Serif CJK SC),正文用黑体,标题用黑体粗,代码用 JetBrains Mono
- 部署依赖:`apt install fonts-noto-cjk fonts-noto-cjk-extra libpango-1.0-0 libpangoft2-1.0-0 libcairo2`
- PDF 结构:封面(系统名 + query + 生成时间 + TLP 标记 + 整体置信度)、目录、报告正文、附录(完整 IOC 列表 + 完整来源列表)
- 表格、代码块、长 URL 自动换页处理(CSS `break-inside: avoid` 配合分页规则)
- 文件名:同 §FR-27 但扩展名为 pdf

**FR-29 STIX 2.1 Bundle 导出**

按 STIX 2.1 标准生成 JSON bundle:
- 每个 CVE → `vulnerability` SDO
- 每个 ATT&CK 技术 → 引用已知 `attack-pattern` SDO id(从本地 ATT&CK bundle 取)
- 每个 IOC → `indicator` SDO with STIX pattern(`[ipv4-addr:value = '1.2.3.4']`)
- 威胁组织(若识别)→ `threat-actor` SDO
- 用 `relationship` SRO 把这些串起来:threat-actor `uses` attack-pattern;indicator `indicates` malware/vulnerability
- bundle 顶层加 `report` SDO 作为聚合容器

输出文件用 `application/json` 类型下载,文件名:`ti-{slug}-{date}.stix.json`

**FR-30 IOC CSV 导出**
- 字段:`type`、`value`、`value_defanged`、`first_seen`、`context`、`confidence`、`source_url`
- 导出选项:全部 / 仅 High 置信度 / 按类型筛选
- 编码:UTF-8 with BOM(便于 Excel 直接打开)

**FR-31 Sigma 规则导出**
- 多条规则合并为一个 YAML 多文档(`---` 分隔)
- 每条规则前带注释块说明:基于哪些 finding、需要哪些字段、AI 生成提示

**FR-32 一键打包导出**
- "导出全部" 按钮,生成 zip 包含上述所有格式
- 文件名:`ti-{slug}-{date}.zip`

---

### 4.7 历史与版本管理(FR-33 至 FR-37)

**FR-33 历史列表**
- 默认按时间倒序,每页 20 条,支持滚动加载
- 筛选条件:intent 类型(下拉)、状态、时间区间、关键词全文搜索
- 全文搜索:SQLite FTS5 虚拟表索引 query 与 report_md

**FR-34 历史详情**
- 完整展示 Markdown 报告 + 结构化产物 tab(IOC / CVE / ATT&CK / 规则)
- 时间线展示当时的 Agent 调用过程,可折叠

**FR-35 增量刷新(US-10)**
- 详情页"刷新增量"按钮,创建一个新的 analysis 关联到原 analysis(`parent_id` 字段)
- 新 analysis 调研时,prompt 中传入旧报告内容,要求模型只输出"自上次调研以来的变化"
- 详情页提供"对比视图",左旧右新,变化字段高亮(KEV 状态变化 / EPSS 升降 / 新增 PoC 等)

**FR-36 历史归档导出**
- 选中多条历史记录 → "批量导出" → zip,内含每条的 .md / .stix.json / .iocs.csv

**FR-37 历史删除**
- 单条删除带确认,批量删除带二次确认
- 删除联动清理 `agent_logs` / `findings` / `iocs` / `data_source_cache` 中关联记录(外键 ON DELETE CASCADE)
- 进行中的任务不允许删除(返回 409)

---

### 4.8 数据源管理与系统设置(FR-38 至 FR-42)

**FR-38 数据源状态页**
- 列出所有内置数据源:名称、类型(authoritative/open)、URL、状态(绿/黄/红)、最后成功时间、限流配置
- 每个源有"测试连接"按钮
- 显示当日已用配额(NVD 等有限流的源)

**FR-39 API Key 管理**
- 在 UI 内填写 NVD API Key、GitHub Token,加密存储(对称加密,密钥从环境变量读)
- 不在前端任何地方明文回显已保存的 key,只显示 "已配置 (****1234)"

**FR-40 可信源白名单**
- 列表展示 + 增删,源域名格式校验
- 修改后立即生效,影响后续分析的置信度评分

**FR-41 Token 预算**
- 月度预算金额(USD)、单次任务上限 token
- 超过单次上限时任务在 Synthesis 阶段截断,标注 "因预算限制提前结束"
- 超过月度预算时新任务返回 402(Payment Required 语义复用)

**FR-42 ATT&CK 数据更新**
- 设置页"更新 ATT&CK 数据"按钮,从 mitre/cti GitHub 仓库 pull 最新 STIX bundle
- 显示当前版本、最新版本、上次更新时间
- 自动定时更新(每周一次,后台 cron 风格 task)

---

## 5. 技术架构

### 5.1 技术选型

| 层次 | 技术 | 版本要求 | 说明 |
|------|------|---------|------|
| 后端框架 | FastAPI | ≥ 0.110 | async + SSE |
| Python | Python | ≥ 3.11 | match-case 与 TaskGroup |
| 数据库 | SQLite | 内置 | WAL 模式 |
| ORM | SQLAlchemy | ≥ 2.0 | async + 2.0 风格 API |
| 全文搜索 | SQLite FTS5 | 内置 | 用于 query/report_md 搜索 |
| AI SDK | anthropic | ≥ 0.34 | Claude API,需要 tool_use 与 streaming |
| HTTP 客户端 | httpx | ≥ 0.27 | async,用于权威源调用 |
| 限流 | aiolimiter | ≥ 1.1 | token bucket |
| STIX | stix2 | ≥ 3.0 | STIX 2.1 对象构建与序列化 |
| PDF | WeasyPrint | ≥ 61.0 | 中文字体配合 fonts-noto-cjk |
| Markdown | markdown-it-py | ≥ 3.0 | 服务端用于 PDF 渲染 |
| 前端 Markdown | marked.js | 12.x (CDN) | 浏览器渲染 |
| 前端高亮 | highlight.js | 11.x (CDN) | 配合 marked |
| 前端 | 原生 HTML/CSS/JS | — | 不引入框架,组件化用 Web Components |
| 加密 | cryptography | ≥ 42 | API key 加密 |
| 日志 | structlog | ≥ 24 | 结构化 JSON 日志 |
| 进程 | uvicorn | ≥ 0.27 | ASGI |

**为什么不用 Postgres / Redis**:单机单用户场景,SQLite WAL 模式能撑;Queue 用 asyncio.Queue 进程内即可。预留迁移路径(SQLAlchemy 抽象 + 配置化 DATABASE_URL),但 v1.0 不做。

**为什么不用前端框架**:UI 状态简单(列表 + 主区域 + 时间线),用原生 + Web Components 足够;减少构建链条对 Claude Code 的复杂度;部署时 `static/` 目录直接挂载即可。

### 5.2 系统架构

```
┌──────────────────────────────────────────────────────────────────────┐
│  Browser                                                              │
│  ┌──────────────┐ ┌──────────────────────────────────────────────┐   │
│  │ History List │ │  Workspace                                    │   │
│  │ Timeline     │ │  Input → Plan → Enrichment → Research →       │   │
│  │ Source Status│ │  Critic → Synthesis (streaming)               │   │
│  └──────┬───────┘ └────────────────────────┬─────────────────────┘   │
│         │  EventSource (SSE,Last-Event-ID) │  POST /analyze         │
└─────────┼──────────────────────────────────┼────────────────────────┘
          │                                  │
┌─────────┼──────────────────────────────────┼────────────────────────┐
│  FastAPI                                                             │
│  ┌──────▼──────────────────────────────────▼──────────────────────┐ │
│  │  Routers                                                        │ │
│  │  /analyze /stream /history /export /sources /settings /health  │ │
│  └──────────────────────┬─────────────────────────────────────────┘ │
│                         │ asyncio.Queue (maxsize=500, drop policy)   │
│  ┌──────────────────────▼─────────────────────────────────────────┐ │
│  │  Orchestrator                                                  │ │
│  │  ┌────────────┐ ┌──────────────┐ ┌──────────────────────────┐ │ │
│  │  │ Intent     │ │ Planner      │ │  Enrichment              │ │ │
│  │  │ Classifier │→│ Agent        │→│  ┌──────┐┌─────┐┌──────┐ │ │ │
│  │  └────────────┘ └──────────────┘ │  │ NVD  ││ KEV ││EPSS  │ │ │ │
│  │                                  │  └──────┘└─────┘└──────┘ │ │ │
│  │                                  │  ┌──────┐┌──────────────┐│ │ │
│  │                                  │  │ATT&CK││ GHSA / Vendor ││ │ │
│  │                                  │  └──────┘└──────────────┘│ │ │
│  │                                  └────────────┬─────────────┘ │ │
│  │  ┌──────────────────────────┐ ┌──────────────▼─────────────┐ │ │
│  │  │ Research Agents (×N)     │←│  Memory & SearchCache       │ │ │
│  │  │ ReAct + web_search       │ │                              │ │ │
│  │  └────────────┬─────────────┘ └──────────────────────────────┘ │ │
│  │               │                                                 │ │
│  │  ┌────────────▼──────────────┐ ┌──────────────────────────┐   │ │
│  │  │ IOC Extractor (regex+LLM) │ │ Critic Agent             │   │ │
│  │  └────────────┬──────────────┘ └────────┬─────────────────┘   │ │
│  │               │                         │                       │ │
│  │  ┌────────────▼─────────────────────────▼──────────────────┐   │ │
│  │  │ Synthesis Agent (streaming) → Markdown + STIX + Sigma   │   │ │
│  │  └─────────────────────────┬────────────────────────────────┘   │ │
│  └────────────────────────────┼─────────────────────────────────────┘ │
│                               │                                        │
│  ┌────────────────────────────▼──────────────────────────────────┐   │
│  │  Persistence (SQLite WAL)                                     │   │
│  │  analyses / agent_logs / findings / iocs / cve_refs /         │   │
│  │  attack_techniques / sources_used / data_source_cache /       │   │
│  │  audit_logs / settings / sources_health / token_usage /       │   │
│  │  fts_index                                                    │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  Background Workers (asyncio tasks)                          │    │
│  │  - ATT&CK weekly sync                                        │    │
│  │  - KEV daily sync (7am UTC)                                  │    │
│  │  - Health checks (every 5min)                                │    │
│  │  - Token usage aggregation (every 1h)                        │    │
│  └──────────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────────┘
```

### 5.3 关键技术决策(变更记录)

**SSE 而非 WebSocket(保留 v1.0 决策)**
分析过程是单向推送,SSE 实现更简单。但**v2.0 强化使用 Last-Event-ID 实现断连重连**,前端断网恢复或刷新页面后,可重新订阅同一 task_id 的事件流,从最后接收的 event id 之后继续。

**asyncio.Queue 改为有界队列**
v1.0 用无界 Queue,v2.0 改为 `Queue(maxsize=500)`,搭配丢弃策略:`report_chunk` 类型采用 "newer wins" 合并(buffer 累积后批量推),其他类型在满时记录告警日志但不阻塞 Agent。

**Agent 之间用 Memory 对象通信而非 Queue**
v1.0 是 Agent → Queue → SSE 单向流;v2.0 增加共享 `Memory` 对象,Agent 之间通过 Memory 读取彼此结果,Queue 只用于通知 UI。这样 Critic Agent 才能读到所有 finding 进行验证。

**LLM 输出 JSON 改用 tool_use schema**
PlannerAgent、IntentClassifier、IOCExtractor 等需要结构化输出的 Agent,统一用 Anthropic API 的 `tools` 参数定义 schema,模型必须按 schema 调用一个虚拟 tool,我们解析 `tool_use` block 得到结构化结果。比 prompt 里要求 "请返回 JSON" 可靠得多。

**搜索结果共享缓存**
SearchCache 是 task 级别的(不跨 task,避免脏数据),所有 ResearchAgent 共享。

**启动恢复 + 周期性维护任务**
启动时清理僵尸任务、做健康检查;后台 task 每周拉取 ATT&CK、每天拉 KEV、每 5 分钟做健康检查。这些都用 FastAPI 的 lifespan 或 `asyncio.create_task` 启动。

---

## 6. 数据模型

### 6.1 核心表

```sql
-- 主分析表
CREATE TABLE analyses (
    id              TEXT PRIMARY KEY,            -- UUID
    parent_id       TEXT REFERENCES analyses(id),-- 增量刷新场景
    query           TEXT NOT NULL,
    intent          TEXT,                         -- cve/attack_technique/threat_actor/...
    intent_entities TEXT,                         -- JSON {cve_id: "...", ...}
    status          TEXT NOT NULL DEFAULT 'running',
                                                  -- running | completed | stopped | timeout 
                                                  -- | failed | interrupted | budget_exceeded
    error_message   TEXT,
    report_md       TEXT,                         -- 最终 Markdown
    report_meta     TEXT,                         -- JSON,frontmatter
    tlp             TEXT DEFAULT 'GREEN',         -- WHITE/GREEN/AMBER/AMBER+STRICT/RED
    overall_confidence TEXT,                      -- High/Medium/Low
    token_input     INTEGER DEFAULT 0,
    token_output    INTEGER DEFAULT 0,
    cost_usd        REAL DEFAULT 0.0,
    duration_s      INTEGER,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX idx_analyses_created_at ON analyses(created_at DESC);
CREATE INDEX idx_analyses_intent ON analyses(intent);
CREATE INDEX idx_analyses_status ON analyses(status);

-- Agent 步骤日志
CREATE TABLE agent_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id  TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    sequence     INTEGER NOT NULL,                -- 顺序号,用于 SSE Last-Event-ID
    event_type   TEXT NOT NULL,
    agent_name   TEXT,
    payload      TEXT,                            -- JSON
    created_at   TEXT NOT NULL
);

CREATE INDEX idx_agent_logs_analysis ON agent_logs(analysis_id, sequence);

-- 调研发现(每个 finding 一条)
CREATE TABLE findings (
    id           TEXT PRIMARY KEY,                -- UUID
    analysis_id  TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    agent_name   TEXT NOT NULL,
    claim        TEXT NOT NULL,                   -- 一句话事实陈述
    detail       TEXT,
    source_type  TEXT NOT NULL,                   -- authoritative | open | llm_inference
    source_url   TEXT,
    source_name  TEXT,                            -- "NVD" / "Microsoft Security Response Center"
    confidence   TEXT NOT NULL,                   -- High/Medium/Low
    created_at   TEXT NOT NULL
);

CREATE INDEX idx_findings_analysis ON findings(analysis_id);

-- IOC 表
CREATE TABLE iocs (
    id           TEXT PRIMARY KEY,
    analysis_id  TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    ioc_type     TEXT NOT NULL,                   -- ipv4|ipv6|domain|url|md5|sha1|sha256|email|filepath
    value        TEXT NOT NULL,
    value_defanged TEXT NOT NULL,
    context      TEXT,                            -- 出现的上下文句子
    source_finding_id TEXT REFERENCES findings(id),
    confidence   TEXT NOT NULL,
    is_extracted_by TEXT NOT NULL,                -- regex | llm
    created_at   TEXT NOT NULL,
    UNIQUE(analysis_id, ioc_type, value)
);

CREATE INDEX idx_iocs_analysis ON iocs(analysis_id);
CREATE INDEX idx_iocs_value ON iocs(value);

-- CVE 引用表(从权威源获取的结构化 CVE 信息)
CREATE TABLE cve_refs (
    id           TEXT PRIMARY KEY,
    analysis_id  TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    cve_id       TEXT NOT NULL,
    cvss_v3_score REAL,
    cvss_v3_vector TEXT,
    cwe_ids      TEXT,                            -- JSON array
    cpe_matches  TEXT,                            -- JSON array
    nvd_published TEXT,
    nvd_modified TEXT,
    description  TEXT,
    is_in_kev    INTEGER NOT NULL DEFAULT 0,      -- 0/1
    kev_added_date TEXT,
    epss_score   REAL,
    epss_percentile REAL,
    epss_date    TEXT,
    source_payload TEXT,                          -- 原始 JSON,便于审计
    created_at   TEXT NOT NULL
);

CREATE INDEX idx_cve_refs_analysis ON cve_refs(analysis_id);
CREATE INDEX idx_cve_refs_cve_id ON cve_refs(cve_id);

-- ATT&CK 技术映射表
CREATE TABLE attack_techniques (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id  TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    technique_id TEXT NOT NULL,                   -- T1190 / T1059.001
    technique_name TEXT,
    tactic       TEXT,
    confidence   TEXT NOT NULL,
    rationale    TEXT,                            -- 为什么映射到这个技术
    created_at   TEXT NOT NULL
);

CREATE INDEX idx_attack_analysis ON attack_techniques(analysis_id);

-- 来源汇总表(去重后)
CREATE TABLE sources_used (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id  TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    url          TEXT NOT NULL,
    domain       TEXT NOT NULL,
    source_type  TEXT NOT NULL,                   -- authoritative | open
    is_trusted   INTEGER NOT NULL DEFAULT 0,
    accessed_at  TEXT NOT NULL,
    UNIQUE(analysis_id, url)
);
```

### 6.2 缓存与系统表

```sql
-- 数据源缓存(NVD/KEV/EPSS/ATT&CK 查询结果)
CREATE TABLE data_source_cache (
    cache_key    TEXT PRIMARY KEY,                -- "nvd:CVE-2024-21413"
    source       TEXT NOT NULL,                   -- nvd|kev|epss|ghsa|attck
    payload      TEXT NOT NULL,                   -- JSON
    fetched_at   TEXT NOT NULL,
    ttl_seconds  INTEGER NOT NULL,
    expires_at   TEXT NOT NULL
);

CREATE INDEX idx_cache_expires ON data_source_cache(expires_at);

-- 数据源健康状态
CREATE TABLE sources_health (
    source_name  TEXT PRIMARY KEY,
    status       TEXT NOT NULL,                   -- ok | degraded | down
    last_check_at TEXT NOT NULL,
    last_success_at TEXT,
    last_error   TEXT,
    response_time_ms INTEGER
);

-- 系统设置(KV 存储)
CREATE TABLE settings (
    key          TEXT PRIMARY KEY,
    value        TEXT NOT NULL,                   -- 加密的存 base64,明文的直接存
    is_encrypted INTEGER NOT NULL DEFAULT 0,
    updated_at   TEXT NOT NULL
);

-- 可信源白名单
CREATE TABLE trusted_sources (
    domain       TEXT PRIMARY KEY,
    note         TEXT,
    added_at     TEXT NOT NULL
);

-- 审计日志
CREATE TABLE audit_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type   TEXT NOT NULL,                   -- analysis_started/exported/deleted/setting_changed/...
    detail       TEXT,                            -- JSON
    created_at   TEXT NOT NULL
);

CREATE INDEX idx_audit_created ON audit_logs(created_at DESC);

-- Token 使用按月聚合
CREATE TABLE token_usage_monthly (
    year_month   TEXT PRIMARY KEY,                -- "2026-05"
    total_input  INTEGER NOT NULL DEFAULT 0,
    total_output INTEGER NOT NULL DEFAULT 0,
    total_cost_usd REAL NOT NULL DEFAULT 0.0,
    analysis_count INTEGER NOT NULL DEFAULT 0,
    updated_at   TEXT NOT NULL
);

-- 全文搜索虚拟表
CREATE VIRTUAL TABLE analyses_fts USING fts5(
    id UNINDEXED,
    query,
    report_md,
    content=''
);
```

### 6.3 状态流转

```
created → running → completed
                  → stopped         (用户手动停止)
                  → timeout         (超过 8 分钟)
                  → failed          (未捕获异常)
                  → interrupted     (服务重启)
                  → budget_exceeded (超过单次或月度预算)
```

---

## 7. 数据源对接规范

### 7.1 NVD API 2.0

**端点**:`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}`  
**鉴权**:可选 API Key,通过 header `apiKey: xxx`  
**限流**:无 key 5 req/30s,有 key 50 req/30s,系统配置 token bucket 比官方略保守(4/30 或 40/30)  
**重试**:429/503 指数退避(1s, 2s, 4s),最多 3 次  
**字段提取**:
- `vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore` → cvss_v3_score
- `vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.vectorString` → cvss_v3_vector
- `vulnerabilities[0].cve.weaknesses[].description[0].value` → cwe_ids
- `vulnerabilities[0].cve.configurations[].nodes[].cpeMatch[].criteria` → cpe_matches
- `vulnerabilities[0].cve.descriptions[?(@.lang=='en')].value` → description
- `vulnerabilities[0].cve.published` / `lastModified`

**缓存 TTL**:24 小时(NVD 数据日级更新)

### 7.2 CISA KEV

**端点**:`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`  
**鉴权**:无  
**模式**:全量下载,本地索引按 cveID 查询  
**更新策略**:后台 task 每日 07:00 UTC 拉取一次,失败时保留旧缓存继续服务  
**缓存 TTL**:24 小时  
**字段提取**:`vulnerabilities[?cveID=='CVE-XXX']` → 整条记录(含 dateAdded、vendorProject、product、shortDescription、knownRansomwareCampaignUse 等)

### 7.3 EPSS

**端点**:`https://api.first.org/data/v1/epss?cve={cve_id}`  
**鉴权**:无  
**限流**:宽松,但仍设 10 req/s 上限  
**字段提取**:`data[0].epss` / `percentile` / `date`  
**缓存 TTL**:6 小时(EPSS 每日更新但分数日内不变)

### 7.4 MITRE ATT&CK

**模式**:本地 STIX bundle,不走运行时 API  
**数据源**:`https://github.com/mitre/cti/blob/master/enterprise-attack/enterprise-attack.json`  
**更新策略**:首次启动下载到 `data/attck/enterprise-attack-vX.Y.json`,之后每周一次后台任务检查更新  
**查询接口**:启动时加载到内存 dict 索引,by technique_id / by group_id / by software_id  
**用途**:
- 校验 SynthesisAgent 输出的 T 编号是否真实存在
- 在报告中补充技术名称、tactic、检测建议
- 生成 STIX bundle 时引用 ATT&CK 对象 id

### 7.5 GitHub Advisory Database

**端点**:GraphQL `https://api.github.com/graphql`  
**鉴权**:GITHUB_TOKEN(PAT,scope: public_repo)  
**用途**:开源生态漏洞补充(npm/pypi/maven/golang/...)  
**缓存 TTL**:24 小时

### 7.6 缓存与降级策略

| 源 | TTL | 降级策略 |
|----|-----|---------|
| NVD | 24h | web_search "CVE-XXX site:nvd.nist.gov" + 标注 "降级源" |
| KEV | 24h | 用最后一次成功缓存,标注缓存日期 |
| EPSS | 6h | 跳过,报告中省略 EPSS 字段 |
| ATT&CK | 7d | 用本地最后一次缓存 |
| GHSA | 24h | 跳过,报告中标注 "GHSA 查询失败" |

所有缓存命中事件 emit `data_source_hit`(cache),未命中时 emit `data_source_miss` 并触发实际请求。

---

## 8. Agent 流水线规范

### 8.1 总体流程

```
用户输入
  └→ IntentClassifier (regex first, LLM fallback)
       └→ PlannerAgent (生成调研计划:子问题 + 数据源调用清单)
            ├→ EnrichmentAgent (并发调用权威源)
            │     ├→ NVD
            │     ├→ KEV
            │     ├→ EPSS
            │     ├→ MITRE ATT&CK (本地)
            │     ├→ GHSA (条件)
            │     └→ 厂商公告搜索
            ├→ ResearchAgent ×N (并发,共享 SearchCache)
            │     └→ ReAct loop with web_search
            └→ (上述完成后)
                 ├→ IOCExtractor (regex + LLM)
                 ├→ CriticAgent (审查 findings,标注异议)
                 └→ SynthesisAgent (流式生成 Markdown 报告)
                      └→ 副产物:STIX bundle / Sigma 草稿 / IOC CSV
```

### 8.2 IntentClassifier

**输入**:用户原始 query  
**输出 schema**(tool_use):
```json
{
  "intent": "cve|attack_technique|threat_actor|malware|ioc_ip|ioc_domain|ioc_hash|cwe|cpe|generic",
  "entities": {
    "cve_ids": ["CVE-2024-21413"],
    "technique_ids": ["T1059.001"],
    "actor_names": [],
    "malware_names": [],
    "iocs": [],
    "keywords": []
  },
  "confidence": 0.0-1.0,
  "reasoning_brief": "..."
}
```

**实现顺序**:
1. 优先正则匹配,命中即直接构造结果(confidence=1.0,reasoning_brief="regex match")
2. 未命中或正则匹配出多种类型时,调用 Claude API with tool_use
3. emit `intent_classified` 事件

### 8.3 PlannerAgent

**输入**:intent + entities + 用户 query  
**职责**:
- 根据意图选择"调研计划模板"(预置 6 套,见 §4.1 FR-03)
- 决定 ResearchAgent 数量(2-5 个)与各自的子问题
- 输出数据源调用清单(authoritative_sources 列表)

**输出 schema**(tool_use):
```json
{
  "research_questions": [
    "质问 1...",
    "质问 2..."
  ],
  "authoritative_sources": ["nvd", "kev", "epss", "ghsa"],
  "rationale": "选择这些方向的原因"
}
```

**回退**:tool_use 解析失败时,根据 intent 用预置 fallback 模板(见 `agents/plans/*.json`)

### 8.4 EnrichmentAgent

**输入**:intent + entities + authoritative_sources 清单  
**实现**:每个权威源对应一个 `EnrichmentSource` 子类(NvdSource、KevSource、EpssSource、AttckSource、GhsaSource),都实现 `async def fetch(entity) -> SourceResult`  
**并发**:`asyncio.gather` 全部并发,每个源各自有限流  
**事件**:每个源 emit `data_source_query` → `data_source_hit/miss/error`  
**结果**:写入 Memory.enrichment 字典,key=source_name  
**注意**:不调用 LLM,纯 HTTP 调用 + JSON 解析

### 8.5 ResearchAgent

**输入**:子问题 + Memory.enrichment(可读)+ SearchCache(共享)  
**System Prompt 增强(相对 v1.0)**:
- 明确告知"以下信息已经从权威源获取,无需重复查询",并附上 enrichment 摘要
- 要求每个 finding 必须附带 source URL,否则丢弃
- 要求标注 confidence(High/Medium/Low),并解释依据

**输出 schema**(tool_use,在 ReAct 最后一轮调用 `submit_findings`):
```json
{
  "findings": [
    {
      "claim": "事实陈述",
      "detail": "更详细描述",
      "source_url": "https://...",
      "source_name": "...",
      "confidence": "High|Medium|Low"
    }
  ],
  "info_gaps": ["未能找到的信息维度"],
  "rounds_used": 2
}
```

**ReAct 循环**:
- 最多 3 轮搜索
- 每轮搜索前先查 SearchCache,命中则跳过 web_search
- emit `searching` / `found` / `thinking`
- 第 3 轮强制要求模型调用 `submit_findings` tool 提交结果

### 8.6 IOCExtractorAgent

**输入**:Memory 中所有 findings 的 detail 文本拼接  
**步骤**:
1. **正则提取**:用预编译正则提取 IPv4/IPv6/MD5/SHA1/SHA256/Domain/URL/Email
   - 注意去除明显误报:RFC1918 内网地址(可选保留,标注)、example.com 系列、版本号被误识别为 IP(`1.2.3.4` 上下文判断)
2. **LLM 语义提取**(tool_use):识别 "C2:xxx"、"投递域名:xxx" 这种结构化提及
3. 合并去重,defang 处理

**输出**:`List[IOC]`,每个 IOC 包含 type/value/value_defanged/context/confidence

### 8.7 CriticAgent

**输入**:Memory.findings + Memory.iocs + Memory.attck_techniques + Memory.cve_refs  
**职责**:
- 检查每个 finding 是否有 source(无源 → 降为 Low confidence 或丢弃)
- 检查跨 finding 的事实矛盾(如 CVSS 分数不一致),标注异议
- 检查关键技术参数与权威源是否一致(report 说 CVSS 9.8,NVD 也说 9.8 → 一致;不一致以权威源为准)
- 校验 ATT&CK 编号是否在本地 bundle 中存在,不存在的丢弃
- 输出 `critic_review` 事件,前端在思考过程中展示

**输出 schema**:
```json
{
  "issues": [
    {"type": "missing_source|conflict|invalid_attck|low_confidence", 
     "finding_id": "...", 
     "description": "..."}
  ],
  "actions": [
    {"action": "drop|downgrade_confidence|flag_in_report", 
     "target_id": "...", 
     "reason": "..."}
  ],
  "overall_assessment": "High|Medium|Low"
}
```

CriticAgent 的 actions 由 Orchestrator 应用到 Memory 后,再交给 Synthesis。

### 8.8 SynthesisAgent

**输入**:整个 Memory(已被 Critic 修正过)  
**输出**:Markdown 报告 + 副产物(STIX/Sigma/IOC CSV)

**System Prompt**(节选):
```
你是一名资深威胁情报分析师,负责将多源调研结果整合为一份可被 SOC 直接使用的情报报告。

输出要求:
1. 严格按照给定章节结构组织(执行摘要、关键事实、技术细节、威胁态势、ATT&CK 映射、IOC 清单、检测规则建议、缓解建议、信息缺口、来源)
2. 每个事实声明必须能追溯到上下文中提供的来源,禁止编造来源
3. 使用中文,但 CVE 编号、ATT&CK 编号、英文产品名保持原文
4. PoC 链接放在 ⚠️ 利用风险信息折叠区(用 HTML <details> 标签实现折叠)
5. ATT&CK 编号格式严格为 T1234 或 T1234.001,使用上下文中提供的列表,禁止杜撰
6. 整体置信度:[High/Medium/Low,由 Critic 给出]
7. TLP 标记:[GREEN,默认]

不要做的事:
- 不要重复 NVD/KEV/EPSS 章节已有的字段(如已经在"关键事实"列出 CVSS,后文不要再次列出)
- 不要在没有来源支持的情况下做"建议性陈述"
- 不要使用 "据称"、"据传"、"业内人士透露" 这类无源表达
```

**流式调用**:
```python
async with claude.messages.stream(...) as stream:
    async for text_chunk in stream.text_stream:
        await self.emit_throttled("report_chunk", {"content": text_chunk})
```

**节流策略**:Synthesis 端不做节流,前端 JS 做(见 §11.2 实现要点)。

### 8.9 Memory 与 SearchCache

```python
class Memory:
    intent: IntentResult
    plan: ResearchPlan
    enrichment: dict[str, SourceResult]   # nvd/kev/epss/...
    findings: list[Finding]
    iocs: list[IOC]
    cve_refs: list[CVERef]
    attck_techniques: list[AttckMapping]
    sources_used: set[str]
    
    def to_synthesis_context(self) -> str:
        """生成传给 Synthesis 的结构化上下文"""

class SearchCache:
    """task 级别共享的 web_search 结果缓存"""
    def __init__(self):
        self._cache: dict[str, list[SearchResult]] = {}
    
    def normalize(self, query: str) -> str:
        return ' '.join(sorted(query.lower().split()))
    
    async def get_or_fetch(self, query, fetcher):
        key = self.normalize(query)
        if key in self._cache:
            return self._cache[key]
        result = await fetcher(query)
        self._cache[key] = result
        return result
```

---

## 9. API 接口规范

所有接口根路径 `http://localhost:8000`,响应 JSON UTF-8 编码。

### 9.1 分析相关

#### POST /analyze
启动分析。Body: `{"query": "...", "tlp": "GREEN", "force_intent": null}`  
返回 `{"task_id": "uuid", "status": "running", "intent_preview": "cve"}`  
错误码:400(参数错误)、409(已有任务运行中)、402(超月度预算)

#### GET /stream/{task_id}
SSE 长连接,支持 `Last-Event-ID` 头部,从指定 sequence 之后继续推送。  
Headers: `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no`  
事件格式:`id: <sequence>\nevent: <type>\ndata: <JSON>\n\n`

#### POST /analyze/{task_id}/stop
停止任务,返回 `{"task_id": "...", "status": "stopped"}`。  
错误码:404(不存在)、400(已结束)

#### POST /analyze/{task_id}/refresh
基于已有分析做增量刷新,创建新分析关联 parent_id。  
返回新 task_id。

#### POST /analyze/{task_id}/switch_intent
在 5s 决策窗口内手动切换意图。Body: `{"intent": "threat_actor"}`  
错误码:400(超时)、409(任务已进入下一阶段)

### 9.2 历史相关

#### GET /history
查询参数:`limit`、`offset`、`intent`、`status`、`q`(全文搜索)、`from`、`to`(ISO 时间)  
返回:`{"total": N, "items": [...]}`

#### GET /history/{id}
返回完整记录,包含 report_md、agent_logs、findings、iocs、cve_refs、attack_techniques、sources_used。

#### GET /history/{id}/diff/{compare_id}
对比两次分析,返回字段级 diff(用于增量刷新展示)。

#### DELETE /history/{id}
单条删除。

#### POST /history/batch_delete
Body: `{"ids": [...]}`,批量删除。

### 9.3 导出相关

#### GET /export/md/{id}
下载 Markdown,文件名 `ti-{intent}-{slug}-{date}.md`

#### GET /export/pdf/{id}
下载 PDF。

#### GET /export/stix/{id}
下载 STIX 2.1 bundle JSON,Content-Type `application/json`,文件名 `.stix.json`

#### GET /export/iocs/{id}?format=csv&defanged=true&min_confidence=Medium
下载 IOC CSV。

#### GET /export/sigma/{id}
下载 Sigma 规则 YAML。

#### GET /export/zip/{id}
打包导出全部格式。

#### POST /export/batch
Body: `{"ids": [...]}`,打包多个分析为 zip。

### 9.4 数据源管理

#### GET /sources/health
返回所有数据源状态。

#### POST /sources/test/{source_name}
触发单个源的连接测试。

#### POST /sources/refresh_attck
触发 ATT&CK 数据更新。

#### POST /sources/refresh_kev
触发 KEV 同步。

### 9.5 设置

#### GET /settings
返回非敏感设置(API key 字段返回 `"****1234"` 格式)。

#### PUT /settings
Body: `{"nvd_api_key": "...", "github_token": "...", "monthly_budget_usd": 50, "researcher_count_default": 4, "tlp_default": "GREEN"}`

#### GET /settings/trusted_sources
返回可信源列表。

#### POST /settings/trusted_sources
添加。Body: `{"domain": "...", "note": "..."}`

#### DELETE /settings/trusted_sources/{domain}
删除。

### 9.6 系统状态

#### GET /health
轻量健康检查(DB + 关键源),返回 200 或 503。

#### GET /stats
返回 token 使用统计、本月分析次数、平均耗时等。

#### GET /audit_logs
查询审计日志。

---

## 10. SSE 事件规范

每条事件:
```
id: <sequence>
event: <event_type>
data: <JSON 一行>

```

**事件类型清单**(相对 v1.0 新增项以 `[NEW]` 标注):

| event | 阶段 | 关键字段 |
|-------|------|---------|
| `intent_classifying` [NEW] | 意图识别 | content |
| `intent_classified` [NEW] | 意图识别完成 | intent, entities, confidence, suggested_path |
| `planning` | 规划 | content |
| `plan_result` | 规划完成 | research_questions, authoritative_sources |
| `data_source_query` [NEW] | 权威源查询开始 | source, entity |
| `data_source_hit` [NEW] | 权威源命中 | source, entity, from_cache: bool |
| `data_source_miss` [NEW] | 权威源未命中 | source, entity, reason |
| `data_source_error` [NEW] | 权威源失败 | source, error |
| `enrichment_done` [NEW] | 全部权威源完成 | summary |
| `agent_start` | Research 开始 | agent_id, question |
| `searching` | Research 搜索中 | agent_id, query, round, cache_hit: bool |
| `thinking` | Research 思考 | agent_id, content |
| `found` | Research 一轮完成 | agent_id, source_count, round |
| `agent_done` | Research 结束 | agent_id, rounds, findings_count |
| `agent_error` | Research 失败 | agent_id, message |
| `ioc_extracting` [NEW] | IOC 提取中 | content |
| `ioc_extracted` [NEW] | IOC 提取完成 | ioc_count, by_type: {ipv4: 3, sha256: 5, ...} |
| `critic_review` [NEW] | Critic 审查中 | content |
| `critic_done` [NEW] | Critic 完成 | issues_count, actions_taken, overall_confidence |
| `synthesizing` | Synthesis 开始 | content |
| `report_chunk` | Synthesis 流式 | content |
| `done` | 全部完成 | analysis_id, duration_s, token_usage, cost_usd |
| `error` | 异常 | message, error_code |
| `stopped` | 用户停止 | partial_completed: bool |
| `timeout` | 超时 | message |
| `budget_exceeded` [NEW] | 预算超限 | reason, used_token, limit_token |

---

## 11. 前端规范(含 Claude Design 协作约定)

### 11.1 Claude Design 与 Claude Code 职责划分

**Claude Design 负责(交付高保真 UI):**

考虑额度,设计 **2 个核心页面 + 1 套设计系统**:

1. **页面 A:Workspace 主分析页**(包含完整状态展示)
   - 输入区(输入框 + intent preview + 提交/停止按钮 + token 计量小组件)
   - 左侧面板上半:历史记录列表(含搜索、筛选、状态标签)
   - 左侧面板下半:Agent 时间线(含意图识别、数据源调用、Research 各阶段、Critic、Synthesis)
   - 右侧主区域:思考过程折叠块 + 流式报告渲染区(含打字机光标、IOC chip 高亮、ATT&CK 编号高亮)
   - 顶部:导出按钮组(MD / PDF / STIX / Sigma / 打包)
   - 必须给出 light + dark 双主题

2. **页面 B:报告详情页**(结构化展示)
   - 顶部:元信息条(意图、TLP、整体置信度、数据源覆盖徽章组)
   - Tab 切换:Markdown 报告 / IOC 列表 / CVE 详情 / ATT&CK 矩阵视图 / Sigma 规则 / 调研轨迹
   - IOC 列表:类型分组、defang 切换开关、批量复制、置信度过滤
   - ATT&CK 矩阵视图:小型 ATT&CK Navigator 风格热力图,点击技术卡片展开详情
   - 底部:导出按钮组、刷新增量按钮、删除按钮

3. **设计系统(Design Tokens + 核心组件)**
   - 色彩 token(完整定义 light/dark 两套):`--bg-base`、`--bg-elevated`、`--text-primary`、`--text-secondary`、`--accent-primary`、`--success`、`--warning`、`--error`、`--info`、`--border-default`、`--confidence-high`、`--confidence-medium`、`--confidence-low`、`--tlp-white/green/amber/red`
   - 字体 token:`--font-sans`、`--font-mono`、`--font-cjk`、`--text-xs/sm/base/lg/xl/2xl/3xl`
   - 间距 token:`--space-1` 至 `--space-12`(基于 4px 网格)
   - 圆角:`--radius-sm/md/lg/full`
   - 阴影:`--shadow-sm/md/lg`
   - 核心组件 HTML/CSS:Button(primary/secondary/danger/ghost)、Input、Textarea、Card、Badge(含 confidence/TLP 变体)、Chip(IOC 类型变体)、Tag、StatusDot(运行中/完成/失败/等待)、Tooltip、Modal、ConfirmDialog、Toast、SkeletonLoader

**Claude Code 负责(基于上述设计 token 与组件扩展):**

4. 历史列表全屏页(用列表组件 + 筛选栏组件组合)
5. 数据源管理页(用 Card + Badge + Button 组合,展示各源健康状态、限流配额条)
6. 设置页(分组表单:基本设置 / API Keys / 可信源管理 / 预算 / ATT&CK 数据)
7. 错误边界页面(404 / 500 / 网络错误)
8. 空状态(无历史时的引导插图区,Claude Code 用 SVG 占位即可)
9. 首次启动引导(3 步:选择主题 / 配置 NVD API Key / 完成)
10. PDF 模板(WeasyPrint HTML + CSS,基于设计 token 调整字体与分页)

### 11.2 前端文件组织

```
static/
├── index.html                  # SPA 入口,包含路由占位
├── assets/
│   ├── tokens.css              # 设计 token(由 Claude Design 提供)
│   ├── components.css          # 核心组件样式(由 Claude Design 提供)
│   └── app.css                 # 应用级样式(由 Claude Code 撰写)
├── components/                 # Web Components,Claude Code 实现
│   ├── ti-button.js
│   ├── ti-card.js
│   ├── ti-badge.js
│   ├── ti-chip.js              # IOC chip,带类型变体
│   ├── ti-status-dot.js
│   ├── ti-timeline.js          # 复合组件
│   ├── ti-history-list.js
│   ├── ti-thinking-block.js
│   ├── ti-report-stream.js     # 流式渲染容器,内含节流逻辑
│   ├── ti-attck-matrix.js
│   └── ti-ioc-table.js
├── pages/                      # 页面级模块,Claude Code 实现
│   ├── workspace.js
│   ├── history-detail.js
│   ├── history-list.js
│   ├── settings.js
│   ├── sources.js
│   └── error.js
├── lib/
│   ├── api.js                  # API 客户端封装
│   ├── sse.js                  # SSE 客户端,含 Last-Event-ID 重连
│   ├── markdown.js             # marked.js 配置 + IOC/T 编号增强渲染
│   ├── router.js               # 简易 hash router
│   ├── store.js                # 简易状态管理(EventTarget 模式)
│   └── utils.js                # defang/refang、格式化、复制等
└── vendor/                     # CDN fallback,Claude Code 决定是否本地化
    ├── marked.min.js
    └── highlight.min.js
```

### 11.3 流式渲染节流要点(Claude Code 实现)

```js
// ti-report-stream.js 关键逻辑(伪代码示意,Claude Code 按设计实现)
class TIReportStream extends HTMLElement {
  constructor() { 
    super();
    this._buffer = '';
    this._dirty = false;
    this._raf = null;
  }
  
  appendChunk(text) {
    this._buffer += text;
    this._dirty = true;
    if (!this._raf) {
      this._raf = requestAnimationFrame(() => this._render());
    }
  }
  
  _render() {
    if (!this._dirty) return;
    this._dirty = false;
    this._raf = null;
    
    // 100ms 节流:用 setTimeout 实现 trailing edge
    if (Date.now() - this._lastRender < 100) {
      this._raf = requestAnimationFrame(() => this._render());
      return;
    }
    this._lastRender = Date.now();
    
    // 增量渲染:只重渲最后两个段落,前面的保持不变
    this._renderIncremental(this._buffer);
  }
}
```

### 11.4 SSE 客户端要点(Claude Code 实现)

```js
// sse.js 关键逻辑
class TIEventSource {
  constructor(taskId) {
    this.taskId = taskId;
    this.lastEventId = null;
    this.reconnectAttempts = 0;
    this._connect();
  }
  
  _connect() {
    const url = `/stream/${this.taskId}`;
    const opts = this.lastEventId 
      ? { headers: { 'Last-Event-ID': this.lastEventId } }
      : {};
    // EventSource 原生不支持自定义 header,改用 fetch + ReadableStream 实现
    // 或在 URL 上拼 ?last_event_id=xxx,服务端两种都支持
    ...
  }
  
  onMessage(event) {
    if (event.lastEventId) this.lastEventId = event.lastEventId;
    ...
  }
  
  // 断开自动重连,指数退避
}
```

---

## 12. 输出格式规范

### 12.1 Markdown 报告(参见 §4.4 FR-21 结构)

带 YAML frontmatter:
```yaml
---
title: "CVE-2024-21413 威胁情报调研报告"
query: "CVE-2024-21413"
intent: "cve"
generated_at: "2026-05-05T10:30:00Z"
tlp: "GREEN"
overall_confidence: "High"
analysis_id: "550e8400-..."
sources_count: 14
ioc_count: 3
attck_count: 2
generator: "Threat Intel Agent v2.0"
---
```

### 12.2 STIX 2.1 Bundle

最简结构示例(实际由 stix2 库构造):
```json
{
  "type": "bundle",
  "id": "bundle--<uuid>",
  "objects": [
    {
      "type": "report",
      "id": "report--<uuid>",
      "spec_version": "2.1",
      "created": "2026-05-05T10:30:00Z",
      "name": "CVE-2024-21413 Threat Intel Report",
      "report_types": ["vulnerability"],
      "object_refs": ["vulnerability--...", "indicator--...", "attack-pattern--..."]
    },
    {
      "type": "vulnerability",
      "id": "vulnerability--<uuid>",
      "name": "CVE-2024-21413",
      "external_references": [{"source_name": "cve", "external_id": "CVE-2024-21413"}]
    },
    {
      "type": "indicator",
      "id": "indicator--<uuid>",
      "pattern": "[ipv4-addr:value = '192.0.2.1']",
      "pattern_type": "stix",
      "valid_from": "2026-05-05T10:30:00Z"
    }
  ]
}
```

### 12.3 Sigma 规则草稿

```yaml
title: Suspicious PowerShell Execution Related to CVE-2024-21413
id: <uuid>
status: experimental
description: |
  AI-GENERATED DRAFT - REQUIRES HUMAN REVIEW.
  Detection logic derived from threat intel analysis of CVE-2024-21413.
  Source findings: [analysis_id]
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-21413
author: Threat Intel Agent (AI-generated)
date: 2026/05/05
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - 'IEX'
  condition: selection
falsepositives:
  - Legitimate administrative scripts
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

### 12.4 IOC CSV

```csv
type,value,value_defanged,confidence,context,source_url
ipv4,192.0.2.1,192[.]0[.]2[.]1,High,"C2 server observed in incident report",https://example.com/report
sha256,abc...,abc...,Medium,"Dropper hash from sandbox analysis",https://...
domain,malicious.example.com,malicious[.]example[.]com,High,"Phishing infrastructure",https://...
```

### 12.5 PDF 报告

- 封面:系统名 / 查询 / 生成时间 / TLP 横幅(对应颜色背景:WHITE 灰、GREEN 绿、AMBER 橙、RED 红)/ 整体置信度
- 目录(自动生成,2 级)
- 正文
- 附录:完整 IOC 表格、完整来源列表
- 页眉:报告标题缩写
- 页脚:TLP 标记 + 页码 + 生成器版本

---

## 13. 可靠性与容错

### 13.1 启动恢复

应用启动 lifespan startup hook 中执行:
```python
async def startup_recovery(db):
    # 1. 标记僵尸任务为 interrupted
    await db.execute(
        "UPDATE analyses SET status='interrupted', "
        "error_message='Service restarted while running', "
        "updated_at=:now WHERE status='running'",
        {"now": now_iso()}
    )
    # 2. 健康检查
    await check_all_sources_health(db)
    # 3. 启动后台 worker
    create_task(periodic_attck_sync())
    create_task(periodic_kev_sync())
    create_task(periodic_health_check())
    create_task(cache_cleanup_loop())
```

### 13.2 SSE 断连重连

- 服务端:`/stream/{task_id}` 支持 `Last-Event-ID` header 与 `?last_event_id=` 查询参数,从 `agent_logs.sequence > last_event_id` 开始推送历史事件,然后继续 live 推送
- 客户端:断开后指数退避重连(1s, 2s, 4s, 8s, 30s 上限),携带最后接收的 sequence
- 任务结束后,SSE 端点检测到 status != running 立即关闭连接

### 13.3 限流与重试

- HTTP 请求:`tenacity` 库装饰,5xx 与 429 重试,4xx 不重试
- LLM 调用:Anthropic SDK 自带重试,额外加全局 token bucket(避免突发)
- 数据源:每个源独立限流器,配置文件可调

### 13.4 Queue 背压

- `asyncio.Queue(maxsize=500)`
- 生产者(Agent)写入超时 5s,超时则记录 warning 但不阻塞
- `report_chunk` 类型在 Queue 满时,与最后一条 `report_chunk` 合并(累加 content)

### 13.5 部分失败处理

- ResearchAgent 单个失败:记录 `agent_error`,Memory 中标记该子问题失败,Synthesis 阶段在"信息缺口"章节明确说明
- EnrichmentAgent 部分源失败:报告中明确标注 "X 源查询失败,数据可能不完整"
- IOCExtractor 失败:跳过 IOC 章节,报告其他部分正常生成
- Critic 失败:跳过审查,Synthesis 直接基于原始 findings 生成,在元信息标注 "未经过 Critic 审查"
- Synthesis 流式中断:已生成内容保存,状态标记为 `completed_partial`

---

## 14. 安全与合规

### 14.1 输入验证与注入防护

- Query 长度、字符白名单(剥离控制字符)
- Prompt injection 启发式检测,可疑输入用 `<<<USER_INPUT>>>` 定界符在 system prompt 中明确隔离
- API 参数全部 Pydantic 校验
- 文件名 slug 白名单字符,杜绝路径穿越
- SQL 全部参数化(SQLAlchemy ORM)

### 14.2 PoC / 敏感信息处理

- 报告中 PoC 链接默认折叠(HTML `<details>`),用户主动展开才显示
- PoC 代码片段不直接展示,只列出来源链接
- 在野利用细节默认折叠

### 14.3 TLP 标记

- 默认 GREEN,用户可在分析时指定
- TLP 标记同步到 PDF 封面、Markdown frontmatter、STIX bundle 的 marking-definition

### 14.4 审计日志

记录的事件类型:
- 分析启动 / 完成 / 停止 / 删除
- 报告导出(记录格式与目标文件名)
- 设置变更(API Key 等敏感字段只记录 "changed",不记录值)
- 数据源 API Key 配置变更
- ATT&CK / KEV 数据更新

保留 90 天(可配置),前端"审计日志"页面查看(挂在设置页内)。

### 14.5 数据源 License 合规

- NVD:public domain,无限制
- CISA KEV:U.S. Government work,public domain
- EPSS:CC0,使用时建议引用
- MITRE ATT&CK:LICENSE.txt 在缓存目录保留,STIX bundle 包含原始版权
- GHSA:GitHub ToS,标注来源
- web_search 结果:仅作为线索,引用时给出原 URL,不全文存储

---

## 15. 性能与成本

### 15.1 性能目标

- 单次分析 P50 < 90s,P90 < 4 分钟
- 历史列表 P95 < 200ms
- 历史详情 P95 < 500ms
- PDF 导出 P95 < 15s
- STIX 导出 P95 < 1s
- 全文搜索 P95 < 500ms(SQLite FTS5)

### 15.2 Token 成本控制

- 默认配置(2026 年价格基线):
  - PlannerAgent: ~2K input + 1K output ≈ $0.02
  - 4 × ResearchAgent: ~8K input + 4K output ≈ $0.10
  - IOCExtractor: ~3K input + 1K output ≈ $0.02
  - CriticAgent: ~6K input + 1K output ≈ $0.04
  - SynthesisAgent: ~12K input + 4K output ≈ $0.10
  - **单次分析预估总成本:$0.25 - $0.50**(随复杂度浮动)
- 月度预算默认 $50,可配置
- 单次任务硬上限默认 200K token(input + output),超过强制截断
- token 使用按 Anthropic 返回的 usage 对象准确记录,不估算

### 15.3 缓存策略

- 数据源缓存(DB):TTL 见 §7.6
- SearchCache:任务级内存
- ATT&CK STIX:进程级单例,重载需 ATT&CK 同步任务通知
- 静态资源:HTTP `Cache-Control: public, max-age=86400`

### 15.4 并发与限流

- 全局 1 个分析任务(单用户)
- Enrichment 并发上限 6
- ResearchAgent 并发上限 5
- web_search 全局 token bucket:10 req/s

---

## 16. 部署与运维

### 16.1 系统依赖

```bash
# Debian 12 / Ubuntu 22.04 / 24.04
apt-get install -y \
    python3.11 python3.11-venv \
    fonts-noto-cjk fonts-noto-cjk-extra fonts-jetbrains-mono \
    libpango-1.0-0 libpangoft2-1.0-0 \
    libcairo2 libffi-dev \
    sqlite3 \
    git
```

### 16.2 Python 依赖(requirements.txt 关键项)

```
fastapi>=0.110
uvicorn[standard]>=0.27
sqlalchemy[asyncio]>=2.0
aiosqlite>=0.19
anthropic>=0.34
httpx>=0.27
aiolimiter>=1.1
stix2>=3.0
weasyprint>=61.0
markdown-it-py>=3.0
pydantic>=2.5
pydantic-settings>=2.1
python-dotenv>=1.0
cryptography>=42
structlog>=24
tenacity>=8.2
pyyaml>=6.0
```

### 16.3 环境变量(.env.example)

```bash
# 必填
ANTHROPIC_API_KEY=sk-ant-...

# 可选
NVD_API_KEY=                   # 强烈建议申请,显著提升限流额度
GITHUB_TOKEN=                  # 用于 GHSA 查询

# 数据库
DATABASE_URL=sqlite+aiosqlite:///./data/ti.db

# 加密密钥(用于设置中的 API key 加密),首次启动自动生成
SECRETS_ENCRYPTION_KEY=

# 模型与成本
ANTHROPIC_MODEL=claude-opus-4-7
MONTHLY_BUDGET_USD=50
SINGLE_TASK_TOKEN_LIMIT=200000

# Agent 配置
RESEARCHER_COUNT_DEFAULT=4
RESEARCH_MAX_ROUNDS=3
ENRICHMENT_TIMEOUT_S=15
SYNTHESIS_TIMEOUT_S=120
ANALYSIS_TIMEOUT_S=480

# 数据目录
DATA_DIR=./data
ATTCK_BUNDLE_PATH=./data/attck/enterprise-attack.json

# 日志
LOG_LEVEL=INFO
LOG_FORMAT=json                # json | console

# 服务
HOST=127.0.0.1
PORT=8000
```

### 16.4 启动命令

```bash
# 首次部署
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# 编辑 .env 填入 ANTHROPIC_API_KEY

# 初始化(下载 ATT&CK / 创建数据库)
python -m app.scripts.init

# 运行
uvicorn app.main:app --host 127.0.0.1 --port 8000

# 生产建议
uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1 --loop uvloop
# 注意:单用户场景固定 workers=1,多 worker 会破坏 asyncio.Queue 跨进程
```

### 16.5 监控指标

通过 `/stats` 暴露以下指标(Prometheus 风格命名,可由 Claude Code 决定是否输出 `/metrics` 端点):

- `ti_analyses_total{status}`(running/completed/failed/...)
- `ti_analysis_duration_seconds`(histogram)
- `ti_token_usage_total{model,kind}`(input/output)
- `ti_cost_usd_total`
- `ti_data_source_calls_total{source,result}`(hit/miss/error)
- `ti_data_source_latency_seconds{source}`(histogram)
- `ti_active_tasks`
- `ti_queue_depth{task_id}`
- `ti_sse_connections`

---

## 17. 测试策略

### 17.1 单元测试

- 覆盖 Agent 的纯函数部分(IOC 提取正则、defang/refang、JSON 解析、prompt 模板渲染、slug 生成)
- 覆盖数据源客户端(用 `respx` mock httpx)
- 覆盖 STIX bundle 构造(给定 fixture findings,断言生成的 bundle 通过 `stix2` 验证)
- 覆盖 Sigma 模板填充
- 目标行覆盖率 80%

### 17.2 集成测试

- FastAPI 路由集成测试(用 `httpx.AsyncClient` + `ASGITransport`,不起真实端口)
- SQLite 临时数据库 + fixtures
- 数据源调用全部 mock

### 17.3 Agent 行为测试

- **Mock Anthropic Client**:封装一层 `LLMClient`,测试时注入 mock 实现,用预录的响应播放
- **VCR 模式**:`pytest-recording` 录制真实 API 响应一次,后续重放,极大降低测试成本
- **Snapshot 测试**:对给定输入,Agent 输出 JSON 与基线 snapshot 对比

### 17.4 端到端测试

- 一个固定的 CVE(选 CVE-2024-21413 或其他稳定的)作为 E2E 用例
- 使用真实 API 跑(每次 CI 跑成本可控,$0.5 内)
- 断言关键字段:报告包含 CVSS、KEV 字段、IOC 数量、ATT&CK 数量大于 0
- 仅在 PR 合并到 main 时触发,日常开发用 mock

---

## 18. 目录结构

```
threat-intel-agent/
├── app/
│   ├── __init__.py
│   ├── main.py                         # FastAPI 实例 + lifespan
│   ├── config.py                       # Settings(pydantic-settings)
│   ├── deps.py                         # 依赖注入(DB session、设置等)
│   │
│   ├── db/
│   │   ├── __init__.py
│   │   ├── engine.py                   # async engine + session factory
│   │   ├── models.py                   # 所有 ORM 模型
│   │   ├── migrations/                 # 简易 schema 迁移(v1.0 用 SQL 文件)
│   │   │   ├── 001_init.sql
│   │   │   └── 002_fts.sql
│   │   └── repositories/               # 仓储层
│   │       ├── analyses.py
│   │       ├── findings.py
│   │       ├── iocs.py
│   │       ├── cve_refs.py
│   │       ├── attack_techniques.py
│   │       ├── audit.py
│   │       └── settings.py
│   │
│   ├── schemas/                        # Pydantic schemas
│   │   ├── analyze.py
│   │   ├── history.py
│   │   ├── settings.py
│   │   ├── events.py                   # SSE 事件 schema
│   │   └── outputs.py                  # findings/iocs/cve/attck schema
│   │
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── base.py                     # BaseAgent + emit + LLMClient 注入
│   │   ├── llm_client.py               # 封装 Anthropic,统一计 token / 成本
│   │   ├── intent_classifier.py
│   │   ├── planner.py
│   │   ├── enrichment/
│   │   │   ├── __init__.py
│   │   │   ├── orchestrator.py
│   │   │   ├── nvd.py
│   │   │   ├── kev.py
│   │   │   ├── epss.py
│   │   │   ├── attck.py
│   │   │   └── ghsa.py
│   │   ├── researcher.py
│   │   ├── ioc_extractor.py
│   │   ├── critic.py
│   │   ├── synthesis.py
│   │   ├── memory.py
│   │   ├── search_cache.py
│   │   ├── orchestrator.py             # 编排全流程
│   │   ├── plans/                      # 调研计划模板
│   │   │   ├── cve.json
│   │   │   ├── attack_technique.json
│   │   │   ├── threat_actor.json
│   │   │   ├── malware.json
│   │   │   ├── ioc.json
│   │   │   └── generic.json
│   │   └── prompts/                    # System prompts
│   │       ├── intent.md
│   │       ├── planner.md
│   │       ├── researcher.md
│   │       ├── ioc_extractor.md
│   │       ├── critic.md
│   │       └── synthesis.md
│   │
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── analyze.py
│   │   ├── stream.py
│   │   ├── history.py
│   │   ├── export.py
│   │   ├── sources.py
│   │   ├── settings.py
│   │   └── system.py                   # /health /stats /audit_logs
│   │
│   ├── exporters/
│   │   ├── __init__.py
│   │   ├── markdown.py                 # 含 frontmatter
│   │   ├── pdf.py                      # WeasyPrint
│   │   ├── stix.py                     # STIX 2.1 bundle
│   │   ├── ioc_csv.py
│   │   ├── sigma.py
│   │   └── zip_bundle.py
│   │
│   ├── workers/
│   │   ├── __init__.py
│   │   ├── attck_sync.py
│   │   ├── kev_sync.py
│   │   ├── health_check.py
│   │   ├── cache_cleanup.py
│   │   └── token_aggregator.py
│   │
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── ioc_regex.py                # 编译好的正则
│   │   ├── defang.py
│   │   ├── slug.py
│   │   ├── crypto.py                   # API key 加密
│   │   ├── time.py
│   │   ├── attck_loader.py             # 加载本地 ATT&CK STIX
│   │   └── cost_calc.py
│   │
│   ├── task_manager.py                 # 进程内任务注册表
│   └── scripts/
│       ├── __init__.py
│       └── init.py                     # 初始化数据库 / 下载 ATT&CK
│
├── static/                             # 前端(见 §11.2)
│   ├── index.html
│   ├── assets/
│   ├── components/
│   ├── pages/
│   ├── lib/
│   └── vendor/
│
├── templates/
│   └── pdf/
│       ├── report.html                 # PDF HTML 模板
│       └── report.css
│
├── data/                               # 运行时数据(gitignore)
│   ├── ti.db
│   └── attck/
│       └── enterprise-attack.json
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── agent/
│   ├── e2e/
│   └── fixtures/
│       ├── nvd/
│       ├── kev/
│       ├── epss/
│       └── llm_responses/
│
├── docs/
│   ├── deployment.md
│   ├── data_sources.md
│   ├── design_system.md                # Claude Design 交付的 token 与组件文档
│   └── prompt_engineering.md           # prompt 调优记录
│
├── .env.example
├── pyproject.toml                      # 推荐用 pyproject 而非 requirements.txt
├── requirements.txt                    # 兼容工具链生成
├── README.md
└── LICENSE
```

---

## 19. 开发任务拆分(Claude Code 实施视角)

每个任务标注:**输入**(Claude Code 需要读哪些 PRD 章节)、**输出**(产出文件清单)、**验收**(可执行命令或接口)。

### 阶段 0:Claude Design 交付前置(用户操作,不在 Claude Code 任务内)

- 用户向 Claude Design 提需求,产出:
  - `docs/design_system.md`(token + 组件规范)
  - `static/assets/tokens.css`(完整 token CSS)
  - `static/assets/components.css`(核心组件样式)
  - `docs/screens/workspace.png` + `docs/screens/workspace.html`(主分析页 HTML 参考)
  - `docs/screens/report-detail.png` + `docs/screens/report-detail.html`(报告详情页 HTML 参考)

Claude Code 后续阶段以这些文件为前端基线。

---

### 阶段 1:工程骨架与配置(预计 2-3 小时)

**输入**:§5.1、§16、§18  
**输出**:
- `pyproject.toml` / `requirements.txt`
- `.env.example`、`README.md`(启动说明)
- `app/main.py`(FastAPI 实例 + lifespan)
- `app/config.py`(Settings)
- `app/deps.py`
- `app/utils/{time.py, slug.py, crypto.py}`
- `app/db/engine.py`、`app/db/models.py`、`app/db/migrations/001_init.sql`、`002_fts.sql`
- `app/scripts/init.py`(创建数据库 + 下载 ATT&CK STIX)
- `app/routers/system.py`(/health 路由)
- 简单的根路由占位返回 `{"name": "ti-agent", "version": "2.0"}`
- `tests/unit/test_slug.py`、`tests/unit/test_crypto.py`、`tests/unit/test_db_init.py`

**验收**:
```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # 填入 ANTHROPIC_API_KEY
python -m app.scripts.init
uvicorn app.main:app --reload
curl http://localhost:8000/health  # 返回 200 ok
curl http://localhost:8000/docs    # 可访问
pytest tests/unit  # 全部通过
```

---

### 阶段 2:数据源层(预计 4-5 小时)

**输入**:§7、§5.1、§13.3  
**输出**:
- `app/agents/enrichment/nvd.py`、`kev.py`、`epss.py`、`ghsa.py`、`attck.py`
- `app/agents/enrichment/orchestrator.py`(并发协调 + 限流)
- `app/utils/attck_loader.py`(加载本地 STIX bundle 到内存索引)
- `app/db/repositories/{cache.py, sources_health.py}`
- `app/workers/{attck_sync.py, kev_sync.py, health_check.py, cache_cleanup.py}`
- `app/routers/sources.py`(/sources/health、/sources/test、/sources/refresh_*)
- `tests/unit/test_data_sources.py`(用 respx mock)
- `tests/fixtures/nvd/cve_2024_21413.json`、`kev/snapshot.json`、`epss/cve_2024_21413.json`

**验收**:
```bash
# 单元测试
pytest tests/unit/test_data_sources.py
# 接口测试
curl http://localhost:8000/sources/health
curl -X POST http://localhost:8000/sources/test/nvd
# 后台任务自动跑(查日志)
```

---

### 阶段 3:Agent 流水线(预计 6-8 小时)

**输入**:§4.3、§8、§3、§6  
**输出**:
- `app/agents/base.py`、`app/agents/llm_client.py`(含 token 计量)
- `app/agents/intent_classifier.py`
- `app/agents/planner.py`(含 plans/*.json fallback)
- `app/agents/researcher.py`(ReAct + tool_use submit_findings)
- `app/agents/ioc_extractor.py`(regex + LLM)
- `app/agents/critic.py`
- `app/agents/synthesis.py`(流式)
- `app/agents/memory.py`、`app/agents/search_cache.py`
- `app/agents/orchestrator.py`(完整编排)
- `app/agents/prompts/*.md`
- `app/utils/{ioc_regex.py, defang.py, cost_calc.py}`
- `app/db/repositories/{findings.py, iocs.py, cve_refs.py, attack_techniques.py}`
- `app/task_manager.py`
- `tests/agent/test_intent_classifier.py`(regex 测试 + LLM mock)
- `tests/agent/test_ioc_extractor.py`
- `tests/agent/test_critic.py`
- `tests/agent/test_orchestrator_mock.py`(全 mock 跑通流程)

**验收**:
```bash
pytest tests/agent
# 在 Python REPL 中直接调用 orchestrator(用 mock LLM 客户端)
python -c "import asyncio; from app.agents.orchestrator import run_analysis_mock; asyncio.run(run_analysis_mock('CVE-2024-21413'))"
```

---

### 阶段 4:API 与 SSE 层(预计 3-4 小时)

**输入**:§9、§10、§13.1、§13.2、§13.4  
**输出**:
- `app/routers/analyze.py`(POST /analyze、/stop、/refresh、/switch_intent)
- `app/routers/stream.py`(SSE,支持 Last-Event-ID)
- `app/routers/history.py`
- `app/db/repositories/audit.py`
- `app/schemas/{analyze.py, events.py, history.py}`
- 启动恢复逻辑(在 main.py lifespan 中调用)
- `tests/integration/test_analyze_flow.py`(用 ASGITransport)
- `tests/integration/test_sse_resume.py`

**验收**:
```bash
# 启动后
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"query": "CVE-2024-21413"}'

# SSE 监听(另一终端)
curl -N http://localhost:8000/stream/<task_id>

# 历史
curl http://localhost:8000/history

# 模拟断连重连(手动 Ctrl+C 然后带 last_event_id 重新请求)
curl -N http://localhost:8000/stream/<task_id>?last_event_id=10

pytest tests/integration
```

---

### 阶段 5:导出与设置(预计 4-5 小时)

**输入**:§4.6、§9.3、§9.5、§12、§14.5  
**输出**:
- `app/exporters/{markdown.py, pdf.py, stix.py, ioc_csv.py, sigma.py, zip_bundle.py}`
- `templates/pdf/report.html`、`report.css`(中文字体配置完整)
- `app/routers/export.py`
- `app/routers/settings.py`
- `app/db/repositories/settings.py`(含加密)
- 默认 trusted_sources.json 种子数据
- `tests/unit/test_exporters.py`(给定 fixture analysis,生成所有格式并校验)
- `tests/integration/test_export_routes.py`

**验收**:
```bash
# 完整跑一次分析后(假设 task_id=abc)
curl http://localhost:8000/export/md/abc -o report.md
curl http://localhost:8000/export/pdf/abc -o report.pdf
curl http://localhost:8000/export/stix/abc -o report.stix.json
curl http://localhost:8000/export/iocs/abc?format=csv -o iocs.csv
curl http://localhost:8000/export/sigma/abc -o rules.yml
curl http://localhost:8000/export/zip/abc -o bundle.zip

# 检查 PDF 中文渲染正常
xdg-open report.pdf  # 或 evince/okular

# 检查 STIX 通过验证
python -c "import stix2; bundle = stix2.parse(open('report.stix.json').read()); print(bundle)"

pytest tests/unit/test_exporters.py
```

---

### 阶段 6:前端集成(预计 5-7 小时)

**输入**:§11、阶段 0 交付物  
**输出**:
- `static/index.html`(SPA 入口)
- `static/lib/{api.js, sse.js, markdown.js, router.js, store.js, utils.js}`
- `static/components/ti-*.js`(根据设计交付物实现 Web Components)
- `static/pages/{workspace.js, history-list.js, history-detail.js, settings.js, sources.js, error.js}`
- `static/assets/app.css`(应用级样式,基于 token)
- 在 `app/main.py` 中挂载 `app.mount("/", StaticFiles(directory="static", html=True))`

**验收**:
- 浏览器访问 `http://localhost:8000`
- 完整跑通一次 CVE 分析,实时看到时间线 / 思考 / 报告流式
- 报告中 IOC 被高亮为 chip,T 编号悬停显示 tooltip
- 切换历史详情页,IOC tab、ATT&CK 矩阵、Sigma tab 正常
- 设置页配置 NVD API Key,刷新后重新加载生效
- light/dark 主题切换流畅

---

### 阶段 7:收尾与硬化(预计 3-4 小时)

**输入**:§13、§14、§15、§17  
**输出**:
- 错误页面与全局异常处理
- 引导页(首次启动)
- token 预算超限的全链路处理
- 增量刷新功能(/analyze/{id}/refresh + 详情页对比视图)
- 批量删除 / 批量导出
- 审计日志页面
- README 完整化(部署、配置、常见问题)
- 端到端测试(真实 API,1 个 CVE)

**验收**:
```bash
# 完整走通 12 项验收标准(见 §21)
pytest tests/e2e --runxfail  # 真实 API,慎用
```

---

## 20. Claude Design 协作清单(交付物详单)

### 20.1 必须由 Claude Design 完成的(2 页面 + 1 设计系统)

| 项目 | 交付内容 | 文件位置 |
|------|---------|---------|
| 设计 token | 色彩 / 字体 / 间距 / 圆角 / 阴影,light + dark | `static/assets/tokens.css` |
| 核心组件 | Button / Input / Textarea / Card / Badge / Chip / StatusDot / Tag / Tooltip / Modal / Toast / SkeletonLoader 的 HTML + CSS | `static/assets/components.css` + `docs/design_system.md`(用法说明) |
| 主分析页 | 完整 HTML + 内嵌交互注释,light/dark 双主题 | `docs/screens/workspace.html` |
| 报告详情页 | 完整 HTML + Tab 切换 + ATT&CK 矩阵视图样式 | `docs/screens/report-detail.html` |

### 20.2 设计文档应包含的关键说明

- 色彩使用规范(何时用 accent / 何时用 secondary / confidence 三色对应映射)
- 间距阶梯(8px 网格说明)
- 字体阶梯(中英文搭配规则,代码字体)
- 状态语义(running 蓝 / 完成绿 / 失败红 / 等待灰 / 警告橙)
- TLP 标记色(WHITE / GREEN / AMBER / RED 的视觉规范)
- 信息密度规则(列表 / 卡片 / 表格三级密度)

### 20.3 Claude Code 在阶段 6 的工作边界

Claude Code **不**在以下事项上自主决策:
- 重新设计任何核心页面
- 调整设计 token
- 创造新的组件视觉变体
- 修改字体、色彩、间距规范

Claude Code **可以**:
- 基于既有 token 与组件,组合实现衍生页面(历史列表、设置、错误页等)
- 增加交互细节(键盘快捷键、复制提示、loading 微动画)
- 调整布局适配(响应式断点)
- 性能优化(虚拟滚动、节流、懒加载)

### 20.4 衔接确认机制

阶段 1 完成后,先把 `static/assets/tokens.css` + `static/assets/components.css` 与一个最小 demo 页面合并跑通,验证 Claude Design 交付的设计系统在 FastAPI 静态目录中能正常加载。如果有 CSS 变量未定义、字体加载失败等问题,在阶段 2 启动前修复。

---

## 21. 验收标准

| 编号 | 验收项 | 通过条件 |
|------|--------|---------|
| AC-01 | CVE 调研基础流程 | 输入 CVE-2024-21413,5 分钟内生成报告,关键事实包含 NVD CVSS、KEV 状态、EPSS 分数 |
| AC-02 | 意图识别 | 输入 "T1059.001"、"APT41"、"5d41402abc4b2a76b9719d911017c592"、"CVE-2024-21413" 四种,各自识别正确 |
| AC-03 | 数据源直查 | 时间线显示 NVD/KEV/EPSS 三个 data_source_query 事件,响应正确 |
| AC-04 | 数据源降级 | 模拟 NVD 不可达,系统降级到 web_search 并标注 "降级源",分析正常完成 |
| AC-05 | 实时展示 | 时间线按顺序展示意图识别 → 规划 → 权威源调用 → Research × N → IOC 提取 → Critic → Synthesis |
| AC-06 | 流式渲染 | 报告内容流式追加,无明显抖动卡顿,Markdown 正确渲染,IOC chip 与 T 编号高亮 |
| AC-07 | IOC 提取 | 包含 IP / Hash / Domain 的报告中,IOC 表格正确列出全部条目,defang 正确 |
| AC-08 | ATT&CK 映射 | 报告映射到至少 1 个 T 编号,编号校验通过(存在于本地 bundle) |
| AC-09 | MD/PDF 导出 | 两种格式内容一致,PDF 中文正常,封面包含 TLP 标记 |
| AC-10 | STIX 导出 | 生成的 STIX bundle 通过 stix2 库 strict 解析 |
| AC-11 | Sigma 导出 | 生成 1-3 条规则,YAML 合法,description 包含 "AI generated, requires human review" |
| AC-12 | IOC CSV 导出 | 字段完整,defanged/live 两种模式可切换,UTF-8 BOM |
| AC-13 | 增量刷新 | 对历史报告执行刷新,新分析关联 parent_id,对比视图显示 KEV/EPSS 等字段变化 |
| AC-14 | 历史持久化 | 服务重启后历史完整,运行中任务标记为 interrupted |
| AC-15 | SSE 重连 | 分析进行中刷新页面,可恢复显示当前状态(从 last_event_id 续传) |
| AC-16 | 手动停止 | 分析中点击停止,任务终止,部分内容保留 |
| AC-17 | 全局超时 | 模拟慢 Agent,8 分钟后自动 timeout |
| AC-18 | 数据源限流遵守 | 连续触发多个分析,日志显示 NVD 调用未超过 5/30s |
| AC-19 | Token 预算 | 设置月度预算 $1,触发分析后系统在 budget_exceeded 状态终止 |
| AC-20 | 错误处理 | 错误 API Key 时 UI 显示明确错误而非白屏;权威源全部失败时 UI 显示降级提示 |
| AC-21 | 并发控制 | 任务运行中再次提交返回 409 |
| AC-22 | 数据源管理 UI | "数据源管理"页面显示各源状态,可手动测试与刷新 |
| AC-23 | 设置 API Key 加密 | 数据库中 nvd_api_key 字段为加密 base64,前端只显示 "****1234" |
| AC-24 | 全文搜索 | 历史搜索关键字 "Outlook" 命中所有相关报告 |
| AC-25 | 主题切换 | light/dark 切换流畅,所有页面与组件正确响应 |
| AC-26 | 设计基线一致 | 主分析页与报告详情页与 Claude Design 交付的 HTML 视觉完全一致 |

---

## 22. 不在范围内(v1.0)与未来路线

### 22.1 v1.0 显式不做

- 多用户、RBAC、SSO
- 主动扫描、PoC 执行、漏洞验证
- TAXII Server / Client(只导出 STIX 文件)
- 与 SIEM/SOAR 双向集成(只提供导出格式)
- 商业 TI Feed 接入(VirusTotal、AlienVault OTX、Recorded Future)
- 中文威胁情报源专门接入(国家漏洞库 CNNVD、CNVD)
- 自动告警与订阅
- 多语言界面(只中文)

### 22.2 v2.x 候选清单(按优先级)

- VirusTotal / OTX 接入(IOC 富化与历史关联)
- CNNVD / CNVD 接入(配合国内合规需求)
- TAXII 2.1 Server 端(为下游消费者提供推送)
- MISP 集成(把分析结果直接推送到 MISP 实例)
- 多用户与团队空间(配合 RBAC)
- 订阅与告警(关键 CVE / 关注 actor 的状态变化推送)
- 插件机制(数据源插件 + Agent 插件)
- 中文 LLM 备选(国产模型作为 cost-saving 选项)

---

## 附录 A:参考资源链接

- NVD API 2.0:https://nvd.nist.gov/developers/vulnerabilities
- CISA KEV Catalog:https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- EPSS API:https://www.first.org/epss/api
- MITRE ATT&CK CTI:https://github.com/mitre/cti
- STIX 2.1 规范:https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- Sigma 规则规范:https://github.com/SigmaHQ/sigma
- Anthropic API:https://docs.claude.com
- TLP 2.0:https://www.first.org/tlp/

---

## 附录 B:Prompt 调优建议

Prompt 不属于代码,但属于产品的核心资产。建议:

1. 把 `app/agents/prompts/*.md` 视为版本控制的一等公民,每次重要修改记录在 `docs/prompt_engineering.md`
2. 维护一个 prompt 黄金测试集(`tests/fixtures/golden/`),内含 5-10 个真实 CVE 与对应的预期产出关键字段,用于回归对比
3. Prompt 的迭代循环:改 prompt → 跑黄金测试 → 对比关键字段命中率 → 决定是否合入
4. 不要让 Claude Code 自主修改 prompts/*.md,每次调优由人工评审

---

*文档结束*
