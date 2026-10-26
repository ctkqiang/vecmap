# vecmap

<p align="center">
  <img src="docs/logo.svg" alt="vecmap Logo" width="120" height="120">
</p>

<p align="center">
  <strong>向量数据库攻击面评估框架</strong>
</p>

<p align="center">
  作者：<strong>钟智强</strong> · 哪吒网络安全
</p>

<p align="center">
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/语言-Go_1.27-00ADD8.svg" alt="Go"></a>
  <a href="#目标格式"><img src="https://img.shields.io/badge/厂商-Qdrant_·_Milvus_·_Weaviate_·_Chroma_·_Redis_·_ES_·_pgvector_·_Typesense_·_Pinecone_·_Vespa-7C3AED.svg" alt="厂商"></a>
  <a href="#命令一览"><img src="https://img.shields.io/badge/平台-macOS_·_Linux_·_Windows-165DFF.svg" alt="平台"></a>
  <a href="#编译与运行"><img src="https://img.shields.io/badge/构建-make-00B42A.svg" alt="make"></a>
  <a href="https://github.com/ctkqiang/vecmap/actions/workflows/compile-cross-platform.yml"><img src="https://img.shields.io/github/actions/workflow/status/ctkqiang/vecmap/compile-cross-platform.yml" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/许可证-GPL--3.0-blue.svg" alt="GPL-3.0"></a>
</p>

---

## 目录

- [项目概述](#项目概述)
- [系统架构](#系统架构)
- [命令一览](#命令一览)
- [目标格式](#目标格式)
- [公告数据来源](#公告数据来源)
- [项目结构](#项目结构)
- [下载](#下载)
- [编译与运行](#编译与运行)
- [测试](#测试)
- [安全最佳实践](#安全最佳实践)
- [免责声明](#免责声明)
- [许可证](#许可证)

---

## 项目概述

vecmap 是 Go 编写的向量数据库攻击面评估工具，sqlmap 风格的 AI / RAG / 向量检索
基础设施深度侦察：指纹识别、gRPC/REST 只读探测、模式枚举、记录提取、
CVE/CNVD 关联与 MITRE ATT&CK 报告。**工具在本地运行，但目标可以是互联网公网、
生产环境或内网的任意主机**——与 sqlmap 一样，只要获得授权即可扫描任何地址
（URL / 域名 / IP / CIDR）。所有证据与提取数据持久化到本地 SQLite（WAL），
离线可复现。无 AI/LLM 调用、无 SaaS 依赖、无破坏性动作。

**核心特性：**

| 特性             | 描述                                                                                |
| ---------------- | ----------------------------------------------------------------------------------- |
| 11 厂商适配器     | Qdrant、Milvus、Weaviate、Chroma、Redis/RediSearch、Elasticsearch、OpenSearch、pgvector、Typesense、Pinecone、Vespa；注册表机制，新增产品不改核心引擎 |
| gRPC 反射驱动     | v1alpha 服务反射 + dynamicpb 描述符动态调用 + raw wire 回退，不依赖任何生成桩          |
| 只读铁律          | 仅 GET/HEAD/OPTIONS 与只读 POST；`/management/stop`、`/delete`、`/drop`、`/upsert` 等破坏性路径硬拒绝，永不执行 |
| 深度提取          | 集合模式、维度、度量、索引类型、点数量、字段定义、记录负载与向量采样，上限可配         |
| 数据驱动公告      | 内嵌 GitHub Security Advisory 快照（GHSA JSON + extra + meta），零 Go 硬编码，CVE/CNVD 版本区间匹配 |
| 双语与设备语言    | 全部用户可见输出中英双语，默认跟随设备系统语言（macOS AppleLanguages/AppleLocale）     |
| 完整证据链        | HTTP 请求/响应/哈希/耗时全程记录，请求头、Cookie 与 URL 查询自动脱敏                  |
| 表驱动测试        | 版本区间、范围校验、wire 编解码、公告目录、WAL、脱敏、RESP、报告渲染集中在 `test/` 独立 package |

**中华人民共和国境内法律红线：**《中华人民共和国网络安全法》第二十七条明确禁止任何个人和组织从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动；未经授权对向量数据库与检索服务实施扫描、枚举与数据提取，可能触犯《中华人民共和国刑法》第二百八十五条（非法侵入计算机信息系统罪、非法获取计算机信息系统数据罪）。本工具仅限**自有资产或已获书面授权**的测试环境使用，使用者须自行确认符合所在地法律法规。

---

## 系统架构

应用层只依赖适配器接口（Adapter：Vendor / Fingerprint / Probe / Enumerate），
厂商实现收敛在 `internal/engine/vendors`；协议客户端与证据链由 `Runtime` 统一注入。

```mermaid
flowchart TB
    CLI["cmd/vecmap/main.go<br/>命令路由: scan / discover / dump / sessions / report / advisories / delete / help / man / completion"] --> APP["internal/app<br/>参数解析 · 扫描编排 · TUI 帮助/手册/补全"]
    APP --> REG["internal/engine<br/>适配器注册表 · 目标/范围 · HTTP/gRPC/RESP · 发现 · 探测 · 指纹 · 风险分析 · 提取"]
    REG --> ADAPT["internal/engine/vendors<br/>11 厂商适配器 · RegisterAll"]
    ADAPT --> PROTO["HTTP 证据链（脱敏/限速/哈希）<br/>gRPC 健康检查 + 反射动态调用 + raw wire<br/>Redis RESP · PostgreSQL 线协议（pgx）"]
    APP --> DB[("SQLite WAL<br/>~/.vecmap/vecmap.db<br/>会话/目标/集合/记录/发现/证据")]
    APP --> REPORT["internal/report<br/>Markdown / JSON / HTML<br/>风险汇总 · MITRE 覆盖 · 证据附录"]
    ADV["internal/constant/data/advisories<br/>GHSA 快照 · extra · meta"] -.-> REG
    MITRE["internal/constant/mitre.go<br/>85 条技术 · 14 战术 · 双语"] -.-> REG
    I18N["internal/utilities/i18n<br/>双语消息 · 版本区间 · 脱敏"] -.-> APP
```

---

## 命令一览

```bash
vecmap scan [OPTIONS] TARGET...               # 攻击面扫描：指纹、只读探测、CVE/CNVD 关联
vecmap discover [OPTIONS] HOST|CIDR...        # 主机/网段 TCP/HTTP/TLS/gRPC/RESP 并发端口发现
vecmap dump [OPTIONS] TARGET...               # 深度枚举与记录提取（--mode deep --extract）
vecmap sessions                               # 列出本地会话
vecmap report --session <id> [--format md|json|html] [--output 路径]   # 导出会话报告
vecmap advisories                             # 列出内置公告目录
vecmap delete --session <id>                  # 删除会话（级联）
vecmap version                                # 版本信息
vecmap help [命令]                             # 总览或单命令帮助（--usage 仅语法）
vecmap man                                    # roff 手册页（中/英，可管道 man -l -）
vecmap completion bash|zsh                    # shell 补全脚本
```

典型用法（内网资产 / 公网生产环境均可，与 sqlmap 一致）：

```bash
# 内网资产：CIDR 授权范围 + 只读探测
vecmap scan --authorize --scope-cidr 10.0.0.0/24 http://10.0.0.5:6333

# 公网生产环境：API Key 认证，扫描任意互联网目标（需书面授权）
vecmap scan --authorize --api-key SECRET https://vecdb.prod.example.com:6333

# 深度提取：记录 + 向量采样
vecmap dump --authorize --vectors --max-records 500 https://vecdb.prod.example.com:6333
```

| 命令        | 功能                         | 关键参数 |
| ----------- | ---------------------------- | -------- |
| `scan`      | 指纹识别 + 只读探测 + 公告关联 + 风险发现 | `--mode` `--extract` `--vectors` `--fuzz` `--api-key` `--scope-cidr` |
| `discover`  | 并发端口发现，开放端口作为会话目标持久化 | `--ports` `--timeout` `--concurrency` |
| `dump`      | 集合模式枚举 + 记录/向量提取 | `--collection` `--namespace` `--max-records` `--batch` |
| `sessions`  | 本地会话列表（状态着色）     | `--db` |
| `report`    | 离线报告渲染（Markdown/JSON/HTML） | `--format` `--output` `--lang` |
| `advisories`| 内置公告目录（数据驱动）     | `--lang` |
| `delete`    | 会话级联删除                 | `--session` |
| `man`       | 手册页输出（中/英）          | `--lang` |
| `completion`| bash/zsh 补全                | — |

完整帮助输出示例见 [README.en.md](README.en.md#help-output)（英文）与
`./build/vecmap help`（中文设备默认）。

---

## 目标格式

```bash
http://host:6333                        # Qdrant REST / gRPC 6334
https://host                            # Pinecone 等 HTTPS 端点
redis://host:6379                       # Redis / RediSearch
postgres://user:pass@host:5432/db       # PostgreSQL pgvector
grpc://host:19530                       # Milvus gRPC
10.0.0.5:6333                           # host:port 裸地址
10.0.0.0/24                             # CIDR 网段（配合 --ports 展开）
```

| 厂商 | 端口 | 认证方式 |
| ---- | ---- | -------- |
| Qdrant | 6333, 6334 | `--api-key`（`api-key` 头） |
| Milvus | 19530, 9091 | 无 / `--bearer` |
| Weaviate | 8080, 50051 | `--bearer` |
| Chroma | 8000 | `--bearer` |
| Redis | 6379, 6380 | `--user`/`--pass`（AUTH） |
| Elasticsearch / OpenSearch | 9200, 9300 | `--api-key`（`ApiKey` 头） |
| pgvector | 5432 | `--dsn` 或 `--user`/`--pass`/`--database` |
| Typesense | 8108 | `--api-key`（`X-TYPESENSE-API-KEY` 头） |
| Pinecone | 443 | `--api-key`（`Api-Key` 头） |
| Vespa | 8080, 19071 | 无 |

---

## 公告数据来源

内置公告**零 Go 硬编码**，全部来自内嵌数据文件
（`internal/constant/data/advisories/`，经 `go:embed` 打入二进制）：

| 文件 | 内容 |
| ---- | ---- |
| `GHSA-*.json` | GitHub Advisory API 官方记录快照 |
| `extra.json` | 无公开 GHSA JSON 的补充条目（CVE-2026-69111、CVE-2026-92782、Typesense 两条），字段同 GHSA 模式 |
| `meta.json` | 中文本地化、厂商归属、CVE↔CNVD 关联、MITRE 映射、匹配策略与区间校正 |

更新：`bash scripts/refresh_advisories.sh`。未核验的外部公告（`--advisories path.json`）仅列出、不参与自动匹配。

---

## 项目结构

```
vecmap/
├── cmd/vecmap/main.go                    # 入口：命令路由与输出（scan/discover/dump/sessions/report/advisories/delete/help/man/completion）
├── internal/
│   ├── app/                              # 参数解析 · 扫描编排 · TUI 帮助/手册/补全
│   ├── engine/                           # 注册表 · 目标/范围 · HTTP/gRPC/RESP · 发现 · 探测 · 指纹 · 风险分析 · 提取
│   │   └── vendors/                      # 11 厂商适配器 · RegisterAll
│   ├── model/                            # 会话/目标/集合/记录/发现/公告/报告领域模型
│   ├── database/                         # SQLite 存储（WAL · 级联删除 · 会话聚合）
│   ├── report/                           # 报告渲染（Markdown/JSON/HTML）
│   ├── constant/                         # 常量 · MITRE 目录 · 公告数据加载
│   │   └── data/advisories/              # GHSA 快照 · extra · meta
│   ├── utilities/                        # i18n · 版本区间 · 脱敏 · 格式化
│   │   └── logger/                       # 用户日志模块（原样保留）
│   └── logger/                           # 内部日志适配
├── test/                                 # 全部 *_test.go（独立 package，表驱动测试）
├── docs/                                 # 手册页（vecmap.1 / vecmap.zh.1）· logo.svg
├── scripts/refresh_advisories.sh         # 公告快照刷新
└── Makefile                              # build / inspect / clean
```

---

## 下载

### go install（最简单，无需 clone）

```bash
go install github.com/ctkqiang/vecmap/cmd/vecmap@latest
```

> `go install` 取包路径最后一段作为二进制名（`cmd/vecmap` → `vecmap`）。二进制默认
> 写入 `$(go env GOPATH)/bin/`（macOS/Linux 通常为 `~/go/bin/`）。若安装后提示
> `command not found`，是该目录不在 `PATH` 中，一次性追加即可：
>
> ```bash
> echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc   # zsh 用户
> source ~/.zshrc
> ```

未打 tag 时用 `@main` 安装最新提交；推送 `v1.0.0` 之类的 tag 后 `@latest` 即可解析，
CI（`.github/workflows/compile-cross-platform.yml`）会自动编译三平台产物并发布到
[GitHub Releases](https://github.com/ctkqiang/vecmap/releases)：

| 平台 | 文件 |
| ---- | ---- |
| macOS (arm64) | `vecmap-darwin-arm64` |
| macOS (amd64) | `vecmap-darwin-amd64` |
| Linux (amd64) | `vecmap-linux-amd64` |
| Linux (arm64) | `vecmap-linux-arm64` |
| Windows | `vecmap-windows-amd64.exe` |

---

## 编译与运行

### 前置条件

- Go 1.27+，CGO 开启（SQLite 驱动依赖）
- macOS / Linux / Windows 均可（平台相关能力仅 macOS 设备语言检测一处）

### Make 构建

```bash
make build     # 编译至 build/vecmap
make inspect   # go vet ./...
make clean     # 清理构建产物与本地会话数据库
go test ./...  # 运行测试
```

### 本地化

中文设备开箱即中文，语言优先级 `--lang` > `VECMAP_LANG` > 设备系统语言 > 英文；
`--lang=en` 随时切回，终端强制 `LANG=en_US` 不影响设备语言判定。

---

## 测试

测试集中在 [test/](test/) 独立 package，以表驱动测试覆盖版本区间、范围校验、
protobuf wire 编解码、公告目录匹配、SQLite/WAL、脱敏、RESP 解析、探测目录安全、
报告渲染与 CLI 解析等关键逻辑：

```bash
go test ./...
```

---

## 安全最佳实践

- 破坏性路径硬拒绝清单收敛在 `internal/engine/fuzz.go`，探测目录新增路径自动过闸；
  Milvus `/management/stop` 只做版本关联，绝不请求。
- 凭据仅存内存（`Credentials` 不序列化），HTTP 证据统一脱敏
  （Authorization/Cookie/api_key/敏感查询参数）。
- 范围校验前置：允许列表 / 排除列表 / 端口白名单，越界目标直接拒绝。
- 提取上限可配（`--max-records`/`--batch`/`--max-vector-values`），payload 截断
  与向量采样防超大响应。
- 不执行任何 shell 拼接、不落任何远程载荷、不自动新增破坏性能力。

## 免责声明

本项目仅用于**授权范围内**的安全评估与教学实验。在中华人民共和国境内使用须遵守
《中华人民共和国网络安全法》《中华人民共和国刑法》的相关规定（详见
[项目概述](#项目概述)中的法律红线说明）；对未授权目标使用属违法行为，后果由使用者
自行承担。

## 许可证

本项目采用 [GNU General Public License v3.0](LICENSE) 开源许可证：

- 可自由使用、修改与分发源代码
- 修改后再分发须同样以 GPL-3.0 开源
- 分发时必须附许可证全文与版权声明

---

<div align="center">

<h2>支持</h2>

<p>如果您觉得本项目对您有帮助，欢迎请我喝杯咖啡</p>
<p><sub>您的支持是我持续维护和改进的动力</sub></p>

<br/>

<strong>微信扫码捐赠</strong><br/><br/>
<img src="https://raw.gitcode.com/ctkqiang_sr/ctkqiang_sr/raw/main/mm_reward_qrcode_1778988737577.png"
     alt="微信扫码捐赠"
     width="240"
     style="border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.15);" />

<br/>
<br/>

</div>
