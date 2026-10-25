<div align="center">

# vecmap

**向量数据库攻击面评估框架** — Vector database attack-surface assessment framework

sqlmap 风格的 AI / RAG / 向量检索基础设施深度侦察工具

[English](README.en.md) | 简体中文

</div>

---

## 简介

vecmap 是一个**本地运行**的 Go CLI 工具，用于对**已获授权**的向量数据库与检索
基础设施执行 sqlmap 风格的深度侦察：指纹识别、gRPC/REST 只读探测、模式枚举、
记录提取、CVE/CNVD 关联与 MITRE ATT&CK 报告。所有证据与提取数据持久化到本地
SQLite（WAL），可离线复现与导出报告。

**无 AI/LLM 调用、无 SaaS 依赖、无破坏性动作。** 所有探测严格只读
（GET/HEAD/OPTIONS 与只读 POST）；`/management/stop`、`/delete`、`/drop`、
`/upsert` 等破坏性接口硬性拒绝、永不执行。

## 特性

| 能力 | 说明 |
|---|---|
| 厂商适配器 | Qdrant、Milvus、Weaviate、Chroma、Redis/RediSearch、Elasticsearch、OpenSearch、PostgreSQL pgvector、Typesense、Pinecone、Vespa |
| 指纹识别 | REST 端点指纹、gRPC 健康检查 + 服务反射、原始 protobuf 字符串提取 |
| 真实协议 | gRPC 反射驱动动态调用（dynamicpb+protojson）、raw wire 回退、Redis RESP、PostgreSQL 线协议（pgx） |
| 只读探测 | 厂商探测目录 + 破坏性路径硬拒绝 + 宽松 CORS 检测 |
| 深度提取 | 集合模式、维度、度量、索引类型、点数量、字段定义、记录负载与向量采样 |
| 漏洞关联 | 内嵌 GitHub Security Advisory 快照（数据驱动，零 Go 硬编码），版本区间匹配 CVE/CNVD |
| 风险分析 | 未授权枚举/提取、metrics/docs/快照暴露、CORS、gRPC 反射、明文端点等，双语 + MITRE 映射 |
| 报告 | Markdown / JSON / HTML，风险汇总、MITRE 覆盖表、证据附录 |
| 持久化 | SQLite WAL（`~/.vecmap/vecmap.db`，目录 0700 / 文件 0600） |
| 本地化 | 全输出中英双语，默认跟随设备系统语言（macOS 系统语言设置） |
| CLI 体验 | ASCII banner、彩色 TUI、`help`/`--usage`/`man` 手册页、bash/zsh 补全、标准退出码 |

## 安装

### go install 一键安装（无需 clone）

```bash
go install github.com/ctkqiang/vecmap/cmd/vecmap@latest
```

二进制安装到 `$(go env GOPATH)/bin/vecmap`，请确保该目录在 `PATH` 中。
要求 Go 1.27+ 且 CGO 开启（SQLite 驱动）。未发布 tag 时可先用 `@main`；
推送 `v1.0.0` 之类的版本 tag 后 `@latest` 即可解析。

### 源码构建

```bash
go build -o build/vecmap ./cmd/vecmap
```

## 快速开始

```bash
# 帮助（中文设备自动输出中文；--lang=en 切英文）
./build/vecmap help
./build/vecmap help scan            # 单条命令完整参数
./build/vecmap scan --usage         # 仅语法

# 标准扫描：指纹、只读探测、CVE 关联
./build/vecmap scan --authorize \
  --scope-cidr 10.0.0.0/24 \
  http://10.0.0.5:6333

# 深度扫描：枚举集合 + 提取记录与向量
./build/vecmap dump --authorize --vectors --max-records 500 \
  --scope-cidr 10.0.0.0/24 \
  http://10.0.0.5:6333

# 端口发现
./build/vecmap discover --authorize --scope-cidr 10.0.0.0/24 10.0.0.0/24

# 会话与报告
./build/vecmap sessions
./build/vecmap report --session <id> --format markdown --output report.md

# 手册页与补全
./build/vecmap man | man -l -
source <(./build/vecmap completion bash)
```

## 帮助输出示例

`./build/vecmap help`（中文设备默认）输出：

```
__     __ _____ _____ __  __    _    ____  
\ \   / // ____/ ____|  \/  |  / \  |  _ \ 
 \ \ / /| |   | |    | |\/| | / _ \ | |_) |
  \ V / | |___| |____| |  | |/ ___ \|  __/ 
   \_/  |______\______|_|  |_/_/   \_\_|    
vecmap v1.0.0 — 向量数据库攻击面评估框架
用法
  vecmap <command> [options]
  vecmap <command> --help

说明
  vecmap 是一个本地运行、sqlmap 风格的攻击面评估框架，面向
  向量数据库与检索基础设施（Qdrant、Milvus、Weaviate、Chroma、
  Redis、Elasticsearch、OpenSearch、pgvector、Typesense、Pinecone、Vespa）。
  所有探测严格只读，破坏性接口一律不执行。

命令
  scan 向量数据库攻击面扫描：产品指纹识别、只读暴露面探测、CVE/CNVD 关联与风险发现。使用 --mode deep（或 --extract）可枚举集合并提取记录。
  discover 对主机或网段执行 TCP/HTTP/TLS/gRPC/RESP 并发端口发现，开放端口作为会话目标持久化。
  dump 深度枚举与记录提取（等价于 --mode deep --extract）。可用 --collection、--namespace 限定范围。
  sessions 列出本地持久化的会话，按时间倒序。
  report 离线生成会话报告。未指定 --output 时输出到标准输出。
  advisories 列出内置公告目录（数据来自内嵌的 GitHub Security Advisory 快照）。
  delete 删除会话及其全部关联证据（级联删除）。
  version 输出版本信息。
  help 显示总帮助或某条命令的详细用法。
  man 以 roff 格式输出手册页（可管道到 man -l -，或将 docs/vecmap.1 安装到系统）。
  completion 输出 bash 或 zsh 的补全脚本。

全局参数
  --db PATH 本地数据库路径（默认 ~/.vecmap/vecmap.db）
  --lang en|zh 界面与报告语言（默认：设备系统语言，否则 en）
  --verbose 输出底层协议调试日志
  --help, -h 显示该命令的帮助
  --usage 仅输出命令语法

示例
  # 标准扫描单个 Qdrant 主机
  vecmap scan --authorize --scope-cidr 10.0.0.0/24 http://10.0.0.5:6333
  # 带认证的深度扫描与提取
  vecmap scan --authorize --mode deep --api-key SECRET --vectors 10.0.0.5:6333
  # 扫描 TLS Redis 端点
  vecmap scan --authorize rediss://db.example.com:6380
  # 扫描 PostgreSQL pgvector 数据库
  vecmap scan --authorize --dsn 'postgres://user:pass@10.0.0.9:5432/vecdb' 10.0.0.9:5432

目标格式
  http://host:6333  https://host  redis://host:6379  postgres://user:pass@host/db  grpc://host:19530
  10.0.0.5:6333    10.0.0.0/24（CIDR，配合 --ports 展开）

退出码
  0  成功    1  运行期错误    2  用法错误

环境变量
  VECMAP_DB     默认数据库路径（覆盖 ~/.vecmap/vecmap.db）
  VECMAP_LANG   默认界面语言（en|zh）
  NO_COLOR      关闭彩色输出
  HTTP_PROXY / HTTPS_PROXY   未指定 --proxy 时生效

文件
  ~/.vecmap/vecmap.db   本地会话数据库（目录 0700、文件 0600）
  <--output 路径>        会话报告（0600）

授权声明：必须事先取得每个目标范围的书面授权
并传入 --authorize。未授权扫描属于违法行为。

使用 'vecmap help <命令>' 查看单条命令参数，'vecmap man' 输出手册页。
```

## 命令

| 命令 | 说明 |
|---|---|
| `scan` | 攻击面扫描（指纹、探测、公告关联；`--mode deep` 提取数据） |
| `discover` | 主机/网段 TCP/HTTP/TLS/gRPC/RESP 并发端口发现 |
| `dump` | 深度枚举与记录提取（等价 `--mode deep --extract`） |
| `sessions` | 列出本地会话 |
| `report` | 导出会话报告（markdown/json/html） |
| `advisories` | 列出内置公告目录 |
| `delete` | 删除会话（级联） |
| `version` | 版本信息 |
| `help` | 总览或单命令帮助 |
| `man` | roff 手册页（中/英） |
| `completion` | bash/zsh 补全脚本 |

## 目标格式

```
http://host:6333   https://host   redis://host:6379
postgres://user:pass@host/db   grpc://host:19530
10.0.0.5:6333      10.0.0.0/24（CIDR，配合 --ports 展开）
```

厂商默认端口：

| 厂商 | 端口 |
|---|---|
| Qdrant | 6333, 6334 |
| Milvus | 19530, 9091 |
| Weaviate | 8080, 50051 |
| Chroma | 8000 |
| Redis | 6379, 6380 |
| Elasticsearch / OpenSearch | 9200, 9300 |
| pgvector | 5432 |
| Typesense | 8108 |
| Pinecone | 443 |
| Vespa | 8080, 19071 |

## 认证

| 参数 | 说明 |
|---|---|
| `--api-key KEY` | API Key，请求头按厂商自动选择（Qdrant `api-key`、Typesense `X-TYPESENSE-API-KEY`、Pinecone `Api-Key`、ES/OpenSearch `ApiKey`，其余 `Bearer`） |
| `--bearer TOKEN` | `Authorization: Bearer` |
| `--user` / `--pass` | HTTP Basic |
| `--dsn DSN` | PostgreSQL 连接串 |
| `--database NAME` | 数据库名 / 租户路径 / Redis 库号 |

## 范围与授权

- **`--authorize` 必填**：使用前必须取得目标范围的书面授权，未授权扫描违法。
- `--scope-cidr` / `--scope-domain`：允许范围（可重复），配置后未命中即拒绝。
- `--exclude-cidr` / `--exclude-domain`：排除范围；仅配置排除项时默认宽松。
- `--scope-port`：端口白名单。
- 仅执行只读操作；`/management/stop` 只做版本关联，绝不请求。

## 公告数据来源

内置公告**零 Go 硬编码**，全部来自内嵌数据文件
（`internal/constant/data/advisories/`，`go:embed` 打入二进制）：

| 文件 | 内容 |
|---|---|
| `GHSA-*.json` | GitHub Advisory API 官方记录快照 |
| `extra.json` | 无公开 GHSA JSON 的补充条目（CVE-2026-69111、CVE-2026-92782、Typesense 两条），字段同 GHSA 模式 |
| `meta.json` | 中文本地化、厂商归属、CVE↔CNVD 关联、MITRE 映射、匹配策略与区间校正 |

更新：`bash scripts/refresh_advisories.sh`。未核验的外部公告（`--advisories path.json`）仅列出、不参与自动匹配。

## 数据与报告

- 数据库默认 `~/.vecmap/vecmap.db`（`--db` 可改，`VECMAP_DB` 可覆盖），WAL + busy_timeout。
- 会话聚合目标、步骤、探测、集合、记录、发现与 HTTP 证据，`sessions`/`report` 离线复现。
- MITRE ATT&CK 目录 85 条 / 14 战术，中英双语；发现自带 T1595/T1046/T1213/T1567 等映射。

## 退出码与环境变量

| 退出码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 运行期错误（网络、数据库、适配器） |
| 2 | 用法错误（未知命令、缺少必填参数、缺少 `--authorize`） |

| 环境变量 | 作用 |
|---|---|
| `VECMAP_DB` | 默认数据库路径 |
| `VECMAP_LANG` | 默认界面语言（`en`/`zh`） |
| `NO_COLOR` | 关闭彩色输出 |
| `HTTP_PROXY` / `HTTPS_PROXY` | 未指定 `--proxy` 时由 HTTP 客户端使用 |

## 本地化

- **全部用户可见输出中英双语**：帮助、man 手册页（中文版自动选择）、错误/用法提示、
  表格表头与取值、扫描报告卡、发现文本、报告（Markdown/HTML/JSON）。
- **默认跟随设备设置**：`--lang` > `VECMAP_LANG` > 设备系统语言
  （macOS `AppleLanguages`/`AppleLocale`，Linux 即 locale 环境变量）> 英文。
- 中文设备开箱即中文；`--lang=en` 随时切回。终端强制 `LANG=en_US` 不影响设备语言判定。

## 开发

```bash
make build    # 构建 ./build/vecmap
make inspect  # go vet ./...
make clean    # 清理构建产物与本地会话数据库
go test ./... # 运行测试套件（test/ 包）
```

`make manpage` 将内嵌手册页同步到 `docs/vecmap.1`、`docs/vecmap.zh.1`，供系统级安装。

## 项目结构

```
cmd/vecmap/              CLI 入口
internal/app/            命令解析、编排、帮助/手册/补全、TUI
internal/engine/         引擎：注册表、目标、范围、HTTP/gRPC/RESP、
                         发现、模糊探测、指纹、风险分析、提取
internal/engine/vendors/ 11 个厂商适配器 + RegisterAll
internal/model/          数据模型（会话/目标/集合/记录/发现/公告/报告）
internal/database/       SQLite 存储（WAL、级联删除、会话聚合）
internal/report/         报告渲染（Markdown/JSON/HTML）
internal/constant/       常量、MITRE 目录、公告数据加载
internal/utilities/      i18n、版本区间、脱敏、格式化
internal/logger/         日志适配（包装 utilities/logger）
test/                    测试（package test）
docs/                    手册页（中/英 roff）
scripts/                 公告快照刷新脚本
```

## 免责声明

vecmap 仅用于**已获授权的安全评估**。使用者必须取得目标资产的书面授权并对自身
行为负责。工具不包含任何漏洞利用、拒绝服务或数据破坏功能。
