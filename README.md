# vecmap

**Vector database attack-surface assessment framework** — 面向 AI / RAG / 向量检索基础设施的攻击面评估框架。

vecmap 是一个本地运行的 Go CLI 工具，用于对授权范围内的向量数据库与检索基础设施执行
sqlmap 风格的深度侦察：指纹识别、gRPC/REST 只读探测、模式枚举、记录提取、
CVE/CNVD 关联与 MITRE ATT&CK 报告。所有证据与提取数据持久化到本地 SQLite，
可离线复现与导出报告。

## 功能

- **厂商适配器**：Qdrant、Milvus、Weaviate、Chroma、Redis/RediSearch、
  Elasticsearch、OpenSearch、PostgreSQL pgvector、Typesense、Pinecone、Vespa。
- **真实协议实现**：
  - REST：证据记录（请求/响应/哈希/耗时）、限速、脱敏、TLS。
  - gRPC：健康检查（grpc_health_v1）、v1alpha 服务反射、描述符驱动的动态调用
    （dynamicpb + protojson），以及反射不可用时的原始 protobuf wire 回退。
  - Redis RESP 客户端：INFO / MODULE LIST / FT._LIST / FT.INFO / FT.SEARCH。
  - PostgreSQL 线协议（pgx）枚举 pgvector 扩展、向量列、索引与行样本。
- **攻击面探测**：只读端点目录（GET/HEAD/OPTIONS + 只读 POST），
  破坏性路径硬拒绝（/management/stop、/delete、/drop、/upsert 等永不执行）。
- **深度提取**：集合模式、维度、度量、索引类型、点数量、字段定义、
  记录负载与向量采样（可配置上限）。
- **漏洞关联**：内置经在线核验的 CVE/CNVD 公告目录，按识别到的产品版本做区间匹配，
  不虚构编号、区间或数据；不支持远程证明的条目（如 Log4j 打包依赖）只收录不自动匹配。
- **风险分析**：未授权枚举/提取、metrics/docs/快照暴露、宽松 CORS、
  gRPC 反射、明文管理端点等发现，全部带 MITRE ATT&CK 映射与双语文本。
- **报告**：Markdown / JSON / HTML，含风险汇总、MITRE 覆盖表与证据附录。
- **本地优先**：SQLite（WAL）持久化，无 AI/LLM 调用、无 SaaS 依赖、无破坏性动作。

## 安装

```bash
go build -o bin/vecmap ./cmd/vecmap
```

要求 Go 1.27+；CGO 开启（SQLite 驱动需要）。

## 使用

```bash
# 帮助（ASCII banner + 彩色终端输出；NO_COLOR=1 关闭彩色）
./bin/vecmap help
./bin/vecmap help scan            # 单条命令的完整参数说明
./bin/vecmap scan --help          # 等价用法
./bin/vecmap scan --usage         # 仅输出语法（或顶层 vecmap --usage）
./bin/vecmap --version            # 或 vecmap version

# 手册页（roff，可管道给 man）
./bin/vecmap man | man -l -
make manpage                      # 同步 docs/vecmap.1，可安装到 /usr/share/man/man1/

# Shell 补全
source <(./bin/vecmap completion bash)   # bash
./bin/vecmap completion zsh > _vecmap    # zsh

# 标准扫描（指纹、只读探测、CVE 关联）
./bin/vecmap scan --authorize \
  --scope-cidr 10.0.0.0/24 \
  http://10.0.0.5:6333

# 深度扫描（模式枚举 + 记录/向量提取）
./bin/vecmap dump --authorize --vectors --max-records 500 \
  --scope-cidr 10.0.0.0/24 \
  http://10.0.0.5:6333

# 端口发现
./bin/vecmap discover --authorize --scope-cidr 10.0.0.0/24 10.0.0.0/24

# 列表会话 / 导出报告
./bin/vecmap sessions
./bin/vecmap report --session <session-id> --format markdown --output report.md
./bin/vecmap report --session <session-id> --format html    --output report.html

# 公告目录
./bin/vecmap advisories
```

### 退出码与环境变量

| 退出码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 运行期错误（网络、数据库、适配器） |
| 2 | 用法错误（未知命令、缺少必填参数、缺少 `--authorize`） |

| 环境变量 | 作用 |
|---|---|
| `VECMAP_DB` | 默认数据库路径（覆盖 `~/.vecmap/vecmap.db`） |
| `VECMAP_LANG` | 默认界面语言（`en`/`zh`） |
| `NO_COLOR` | 关闭彩色输出 |
| `HTTP_PROXY` / `HTTPS_PROXY` | 未指定 `--proxy` 时由 HTTP 客户端使用 |

### 本地化

- 帮助、错误提示、会话/公告表格、扫描报告卡与报告（Markdown/HTML/JSON）均支持中英双语。
- 语言优先级：`--lang` 参数 > `VECMAP_LANG` 环境变量 > 系统 locale（`LANG`/`LC_ALL`/`LC_MESSAGES` 含 `zh` 自动用中文）> 英文。
- 示例：`LANG=zh_CN.UTF-8 vecmap help` 直接输出全中文帮助；`vecmap help --lang en` 切回英文。

### 终端体验

- 扫描启动时打印彩色 ASCII banner，风险发现按严重度着色
  （严重=红、高危=橙、中危=黄、低危=绿），会话状态同样着色
- `sessions` / `advisories` 表格列着色
- 用法错误（退出码 2）会在 stderr 输出对应命令的 SYNOPSIS 提示
- 全部彩色输出遵守 `NO_COLOR` 约定，管道/非 TTY 自动降级

### 目标格式

- URL：`http://host:6333`、`https://host`、`redis://host:6379`、`postgres://user:pass@host/db`、`grpc://host:19530`
- 主机/端口：`10.0.0.5:6333`
- 网段：`10.0.0.0/24`（配合 `--ports` 展开）

### 认证

| 参数 | 说明 |
|---|---|
| `--api-key KEY` | 按厂商自动选择头（Qdrant `api-key`、Typesense `X-TYPESENSE-API-KEY`、Pinecone `Api-Key`、ES/OpenSearch `ApiKey`） |
| `--bearer TOKEN` | `Authorization: Bearer` |
| `--user / --pass` | HTTP Basic |
| `--dsn` | PostgreSQL 连接串 |
| `--database` | 数据库名 / Redis 库号 / Chroma 租户路径 |

### 范围与授权

- `--authorize` 必填：使用前必须获得目标范围的书面授权。
- `--scope-cidr`、`--scope-domain`：允许范围（可重复）；配置后未命中即拒绝。
- `--exclude-cidr`、`--exclude-domain`：排除范围；仅配置排除项时默认宽松。
- `--scope-port`：端口白名单。
- 仅执行只读操作；破坏性接口一律拒绝执行，`/management/stop` 只做版本关联。

### 自定义公告

`--advisories path.json` 加载外部公告（数组或 `{"advisories": [...]}`）。
外部条目必须通过基础校验（标识、标题、厂商、参考链接），且默认 `Verified=false`，
仅作目录引用，不参与自动版本匹配。

### 公告数据来源

内置公告**不做任何 Go 源码硬编码**，全部来自内嵌数据文件
（`internal/constant/data/advisories/`，通过 `go:embed` 打入二进制）：

| 文件 | 内容 |
|---|---|
| `GHSA-*.json` | GitHub Advisory API 原始记录（官方数据快照） |
| `extra.json` | 无公开 GHSA JSON 的补充条目（CVE-2026-69111、CVE-2026-92782、Typesense 两条），字段同 GHSA 模式，来源 NVD/CVE.org/VulnCheck |
| `meta.json` | 中文本地化、厂商归属、CVE↔CNVD 关联、MITRE 映射、匹配策略（matchable）与影响区间校正 |

更新快照：`bash scripts/refresh_advisories.sh`（重新拉取 GHSA，不覆盖 meta/extra）。

## 数据与报告

- 本地数据库默认 `~/.vecmap/vecmap.db`（`--db` 可改），WAL + busy_timeout，
  目录与文件权限自动收紧为 0700/0600。
- 会话聚合目标、步骤、探测结果、集合、记录、发现与 HTTP 证据；
  `sessions` / `report` 命令离线复现。
- 报告内建 MITRE ATT&CK 技术目录；发现自带 T1595/T1046/T1213/T1567 等映射。

## 开发

```bash
make build   # 构建 bin/vecmap
make test    # go test ./...
make vet     # go vet ./...
make fmt     # gofmt -l .
```

测试位于 `test/`（package `test`），覆盖版本区间、范围校验、wire 编解码、
公告目录、数据库/WAL、脱敏、RESP 解析、探测目录安全性与报告渲染。

## 免责声明

vecmap 仅用于**已获授权的安全评估**。使用者必须取得目标资产的书面授权，
并对自身行为负责。工具不包含任何漏洞利用、拒绝服务或数据破坏功能。
