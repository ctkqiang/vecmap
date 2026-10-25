# vecmap

<p align="center">
  <img src="docs/logo.svg" alt="vecmap Logo" width="120" height="120">
</p>

<p align="center">
  <strong>Vector database attack-surface assessment framework</strong>
</p>

<p align="center">
  Author: <strong>Zhong Zhiqiang</strong> · Nezha Network Security
</p>

<p align="center">
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Language-Go_1.27-00ADD8.svg" alt="Go"></a>
  <a href="#target-formats"><img src="https://img.shields.io/badge/Vendors-Qdrant_·_Milvus_·_Weaviate_·_Chroma_·_Redis_·_ES_·_pgvector_·_Typesense_·_Pinecone_·_Vespa-7C3AED.svg" alt="Vendors"></a>
  <a href="#commands"><img src="https://img.shields.io/badge/Platform-macOS_·_Linux_·_Windows-165DFF.svg" alt="Platform"></a>
  <a href="#build--run"><img src="https://img.shields.io/badge/Build-make-00B42A.svg" alt="make"></a>
  <a href="https://github.com/ctkqiang/vecmap/actions/workflows/compile-cross-platform.yml"><img src="https://img.shields.io/github/actions/workflow/status/ctkqiang/vecmap/compile-cross-platform.yml" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPL--3.0-blue.svg" alt="GPL-3.0"></a>
</p>

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Commands](#commands)
- [Target Formats](#target-formats)
- [Advisory Data Sources](#advisory-data-sources)
- [Project Layout](#project-layout)
- [Download](#download)
- [Build & Run](#build--run)
- [Testing](#testing)
- [Security Best Practices](#security-best-practices)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Overview

vecmap is a Go CLI for sqlmap-style attack-surface assessment of AI / RAG /
vector retrieval infrastructure: product fingerprinting, read-only gRPC/REST
probing, schema enumeration, record extraction, CVE/CNVD correlation, and MITRE
ATT&CK reporting. All evidence and extracted data is persisted to a local SQLite
database (WAL) and reproducible offline. No AI/LLM calls, no SaaS dependency, no
destructive actions.

**Core features:**

| Feature              | Description                                                                         |
| -------------------- | ----------------------------------------------------------------------------------- |
| 11 vendor adapters   | Qdrant, Milvus, Weaviate, Chroma, Redis/RediSearch, Elasticsearch, OpenSearch, pgvector, Typesense, Pinecone, Vespa; registry-driven, no core-engine vendor branches |
| Reflection-driven gRPC | v1alpha server reflection + dynamicpb descriptor calls + raw-wire fallback, zero generated stubs |
| Read-only by design  | GET/HEAD/OPTIONS and read-only POST only; `/management/stop`, `/delete`, `/drop`, `/upsert` and other destructive paths are hard-denied, never invoked |
| Deep extraction      | Collection schemas, dimensions, metrics, index types, point counts, field definitions, record payloads, and vector samples — all limits configurable |
| Data-driven advisories | Embedded GitHub Security Advisory snapshots (GHSA JSON + extra + meta), zero Go hardcoding, CVE/CNVD version-range matching |
| Bilingual + device locale | Every user-facing string in English and Chinese; the default follows the device system language (macOS AppleLanguages/AppleLocale) |
| Full evidence chain  | HTTP request/response/hash/duration recorded for every exchange; headers, cookies, and URL query parameters auto-redacted |
| Table-driven tests   | Version ranges, scope checks, wire codecs, advisory catalog, WAL, redaction, RESP, report rendering — all in an isolated `test/` package |

**Legal notice (PRC):** Article 27 of the Cybersecurity Law of the People's
Republic of China prohibits unauthorized intrusion into networks, disruption of
network functions, and theft of network data; scanning, enumerating, or
extracting data from vector databases without authorization may violate Article
285 of the PRC Criminal Law (illegal intrusion / illegal acquisition of computer
information system data). Use this tool **only on assets you own or with written
authorization**, and verify compliance with your local laws.

---

## Architecture

The application layer depends only on adapter ports (Adapter: Vendor /
Fingerprint / Probe / Enumerate); vendor implementations live in
`internal/engine/vendors`, with protocol clients and the evidence chain injected
through `Runtime`.

```mermaid
flowchart TB
    CLI["cmd/vecmap/main.go<br/>command routing: scan / discover / dump / sessions / report / advisories / delete / help / man / completion"] --> APP["internal/app<br/>argument parsing · orchestration · TUI help/man/completion"]
    APP --> REG["internal/engine<br/>adapter registry · targets/scope · HTTP/gRPC/RESP · discovery · probing · fingerprinting · risk analysis · extraction"]
    REG --> ADAPT["internal/engine/vendors<br/>11 vendor adapters · RegisterAll"]
    ADAPT --> PROTO["HTTP evidence chain (redaction/rate-limit/hash)<br/>gRPC health + reflection dynamic calls + raw wire<br/>Redis RESP · PostgreSQL wire protocol (pgx)"]
    APP --> DB[("SQLite WAL<br/>~/.vecmap/vecmap.db<br/>sessions/targets/collections/records/findings/evidence")]
    APP --> REPORT["internal/report<br/>Markdown / JSON / HTML<br/>risk summary · MITRE coverage · evidence appendix"]
    ADV["internal/constant/data/advisories<br/>GHSA snapshots · extra · meta"] -.-> REG
    MITRE["internal/constant/mitre.go<br/>85 techniques · 14 tactics · bilingual"] -.-> REG
    I18N["internal/utilities/i18n<br/>bilingual messages · version ranges · redaction"] -.-> APP
```

---

## Commands

```bash
vecmap scan [OPTIONS] TARGET...               # attack-surface scan: fingerprint, read-only probes, CVE/CNVD correlation
vecmap discover [OPTIONS] HOST|CIDR...        # concurrent TCP/HTTP/TLS/gRPC/RESP port discovery
vecmap dump [OPTIONS] TARGET...               # deep enumeration and record extraction (--mode deep --extract)
vecmap sessions                               # list local sessions
vecmap report --session <id> [--format md|json|html] [--output PATH]   # export a session report
vecmap advisories                             # list the built-in advisory catalog
vecmap delete --session <id>                  # delete a session (cascading)
vecmap version                                # print the version
vecmap help [command]                         # overview or per-command help (--usage for synopsis only)
vecmap man                                    # roff manual page (en/zh, pipe to man -l -)
vecmap completion bash|zsh                    # shell completion scripts
```

| Command      | Purpose                              | Key options |
| ------------ | ------------------------------------ | ----------- |
| `scan`       | Fingerprinting + read-only probes + advisory correlation + findings | `--mode` `--extract` `--vectors` `--fuzz` `--api-key` `--scope-cidr` |
| `discover`   | Concurrent port discovery; open ports persisted as session targets | `--ports` `--timeout` `--concurrency` |
| `dump`       | Collection schema enumeration + record/vector extraction | `--collection` `--namespace` `--max-records` `--batch` |
| `sessions`   | Local session list (colored status) | `--db` |
| `report`     | Offline report rendering (Markdown/JSON/HTML) | `--format` `--output` `--lang` |
| `advisories` | Built-in advisory catalog (data-driven) | `--lang` |
| `delete`     | Session cascade deletion            | `--session` |
| `man`        | Manual page output (en/zh)          | `--lang` |
| `completion` | bash/zsh completion                 | — |

The full help output is shown in [Help Output](#help-output) below; Chinese
devices get the Chinese variant by default.

---

## Target Formats

```bash
http://host:6333                        # Qdrant REST / gRPC 6334
https://host                            # HTTPS endpoints (Pinecone etc.)
redis://host:6379                       # Redis / RediSearch
postgres://user:pass@host:5432/db       # PostgreSQL pgvector
grpc://host:19530                       # Milvus gRPC
10.0.0.5:6333                           # bare host:port
10.0.0.0/24                             # CIDR (expanded with --ports)
```

| Vendor | Ports | Authentication |
| ------ | ----- | -------------- |
| Qdrant | 6333, 6334 | `--api-key` (`api-key` header) |
| Milvus | 19530, 9091 | none / `--bearer` |
| Weaviate | 8080, 50051 | `--bearer` |
| Chroma | 8000 | `--bearer` |
| Redis | 6379, 6380 | `--user`/`--pass` (AUTH) |
| Elasticsearch / OpenSearch | 9200, 9300 | `--api-key` (`ApiKey` header) |
| pgvector | 5432 | `--dsn` or `--user`/`--pass`/`--database` |
| Typesense | 8108 | `--api-key` (`X-TYPESENSE-API-KEY` header) |
| Pinecone | 443 | `--api-key` (`Api-Key` header) |
| Vespa | 8080, 19071 | none |

---

## Advisory Data Sources

The built-in catalog has **zero Go hardcoding** — it is loaded from embedded data
files (`internal/constant/data/advisories/`, compiled in via `go:embed`):

| File | Contents |
| ---- | -------- |
| `GHSA-*.json` | Official GitHub Advisory API record snapshots |
| `extra.json` | Supplementary entries without a public GHSA JSON (CVE-2026-69111, CVE-2026-92782, two Typesense entries), same schema |
| `meta.json` | Chinese localization, vendor attribution, CVE↔CNVD linkage, MITRE mappings, match policies, and range corrections |

Refresh: `bash scripts/refresh_advisories.sh`. Unverified external advisories
(`--advisories path.json`) are listed but never auto-matched.

---

## Project Layout

```
vecmap/
├── cmd/vecmap/main.go                    # entrypoint: command routing and output
├── internal/
│   ├── app/                              # argument parsing · orchestration · TUI help/man/completion
│   ├── engine/                           # registry · targets/scope · HTTP/gRPC/RESP · discovery · probing · fingerprinting · analysis · extraction
│   │   └── vendors/                      # 11 vendor adapters · RegisterAll
│   ├── model/                            # session/target/collection/record/finding/advisory/report models
│   ├── database/                         # SQLite store (WAL · cascade deletes · session aggregation)
│   ├── report/                           # report rendering (Markdown/JSON/HTML)
│   ├── constant/                         # constants · MITRE catalog · advisory data loader
│   │   └── data/advisories/              # GHSA snapshots · extra · meta
│   ├── utilities/                        # i18n · version ranges · redaction · formatting
│   │   └── logger/                       # user's logging module (preserved as-is)
│   └── logger/                           # internal logging adapter
├── test/                                 # all *_test.go (isolated package, table-driven)
├── docs/                                 # manual pages (vecmap.1 / vecmap.zh.1) · logo.svg
├── scripts/refresh_advisories.sh         # advisory snapshot refresh
└── Makefile                              # build / inspect / clean
```

---

## Download

### go install (simplest, no clone required)

```bash
go install github.com/ctkqiang/vecmap/cmd/vecmap@latest
```

> `go install` names the binary after the last path segment (`cmd/vecmap` →
> `vecmap`). It lands in `$(go env GOPATH)/bin/` (usually `~/go/bin/` on
> macOS/Linux). If you get `command not found`, add that directory to your
> `PATH`:
>
> ```bash
> echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc   # zsh users
> source ~/.zshrc
> ```

Use `@main` for unreleased commits; `@latest` resolves once a `v*` tag (e.g.
`v1.0.0`) is pushed, and CI (`.github/workflows/compile-cross-platform.yml`)
builds and publishes cross-platform binaries to
[GitHub Releases](https://github.com/ctkqiang/vecmap/releases):

| Platform | File |
| -------- | ---- |
| macOS (arm64) | `vecmap-darwin-arm64` |
| macOS (amd64) | `vecmap-darwin-amd64` |
| Linux (amd64) | `vecmap-linux-amd64` |
| Linux (arm64) | `vecmap-linux-arm64` |
| Windows | `vecmap-windows-amd64.exe` |

---

## Build & Run

### Prerequisites

- Go 1.27+ with CGO enabled (SQLite driver)
- macOS / Linux / Windows (the only platform-specific code is macOS device-language detection)

### Make build

```bash
make build     # build ./build/vecmap
make inspect   # go vet ./...
make clean     # remove build artifacts and the local session database
go test ./...  # run the test suite
```

### Localization

Chinese devices get Chinese out of the box; priority is `--lang` >
`VECMAP_LANG` > device system language > English. `--lang=en` switches back at
any time; a terminal that forces `LANG=en_US` does not override the device
setting.

---

## Help Output

`./build/vecmap help --lang=en` prints:

```
__     __ _____ _____ __  __    _    ____  
\ \   / // ____/ ____|  \/  |  / \  |  _ \ 
 \ \ / /| |   | |    | |\/| | / _ \ | |_) |
  \ V / | |___| |____| |  | |/ ___ \|  __/ 
   \_/  |______\______|_|  |_/_/   \_\_|    
vecmap v1.0.0 — Vector database attack-surface assessment framework
USAGE
  vecmap <command> [options]
  vecmap <command> --help

DESCRIPTION
  vecmap is a local-only, sqlmap-style attack-surface assessment framework for
  vector databases and retrieval infrastructure (Qdrant, Milvus, Weaviate, Chroma,
  Redis, Elasticsearch, OpenSearch, pgvector, Typesense, Pinecone, Vespa).
  All probes are strictly read-only; destructive endpoints are never invoked.

COMMANDS
  scan Attack-surface scan of vector databases: product fingerprinting, read-only surface probes, CVE/CNVD correlation and risk findings. Use --mode deep (or --extract) to enumerate collections and extract records.
  discover Concurrent TCP/HTTP/TLS/gRPC/RESP port discovery across hosts or CIDR ranges. Open ports are persisted as session targets.
  dump Deep enumeration and record extraction (implies --mode deep --extract). Restrict scope with --collection and --namespace.
  sessions List locally persisted sessions, newest first.
  report Render a session report offline. Without --output the report is printed to stdout.
  advisories List the built-in advisory catalog sourced from embedded GitHub Security Advisory snapshots.
  delete Delete a session and all of its associated evidence (cascading).
  version Print the version string.
  help Show this help or the detailed usage of one command.
  man Print the manual page in roff format (pipe to man -l - or install docs/vecmap.1).
  completion Print a shell completion script for bash or zsh.

GLOBAL OPTIONS
  --db PATH Local database path (default ~/.vecmap/vecmap.db)
  --lang en|zh UI and report language (default: device locale, else en)
  --verbose Verbose protocol logging
  --help, -h Show help for the command
  --usage Print the command synopsis only

EXAMPLES
  # Standard scan of one Qdrant host
  vecmap scan --authorize --scope-cidr 10.0.0.0/24 http://10.0.0.5:6333
  # Deep scan with authenticated extraction
  vecmap scan --authorize --mode deep --api-key SECRET --vectors 10.0.0.5:6333
  # Scan a Redis endpoint over TLS
  vecmap scan --authorize rediss://db.example.com:6380
  # Scan a PostgreSQL pgvector database
  vecmap scan --authorize --dsn 'postgres://user:pass@10.0.0.9:5432/vecdb' 10.0.0.9:5432

TARGET FORMATS
  http://host:6333  https://host  redis://host:6379  postgres://user:pass@host/db  grpc://host:19530
  10.0.0.5:6333    10.0.0.0/24 (CIDR, expand with --ports)

EXIT STATUS
  0  success        1  runtime error        2  usage error

ENVIRONMENT
  VECMAP_DB     default database path (overrides ~/.vecmap/vecmap.db)
  VECMAP_LANG   default UI language (en|zh)
  NO_COLOR      disable colored output
  HTTP_PROXY / HTTPS_PROXY   honored when --proxy is not set

FILES
  ~/.vecmap/vecmap.db   local session database (dir 0700, file 0600)
  <--output path>       session reports (0600)

AUTHORIZATION: you must obtain written permission for every target
and pass --authorize. Unauthorized scanning is illegal.

See 'vecmap help <command>' for per-command options, and 'vecmap man' for the manual.
```

---

## Testing

Tests live in the isolated [test/](test/) package and cover version ranges,
scope checks, protobuf wire codecs, advisory matching, SQLite/WAL, redaction,
RESP parsing, probe-catalog safety, report rendering, and CLI parsing:

```bash
go test ./...
```

---

## Security Best Practices

- The destructive-path denylist lives in `internal/engine/fuzz.go`; every probe
  catalog path passes through it. Milvus `/management/stop` is correlated by
  version only and never requested.
- Credentials exist only in memory (`Credentials` is never serialized); HTTP
  evidence is redacted (Authorization/Cookie/api_key/sensitive query params).
- Scope checks run before any traffic: allowlists / exclusions / port
  allowlists; out-of-scope targets are rejected outright.
- Extraction limits are configurable (`--max-records`/`--batch`/
  `--max-vector-values`); payload truncation and vector sampling bound response sizes.
- No shell concatenation, no remote payload execution, no new destructive
  capabilities are added automatically.

## Disclaimer

This project is for **authorized security assessments and educational
experiments only**. Within the People's Republic of China, usage is subject to
the Cybersecurity Law and the Criminal Law (see the legal notice in
[Overview](#overview)); using it against unauthorized targets is illegal and the
consequences rest entirely with the user.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE):

- Free to use, modify, and distribute the source code
- Modified versions must be released under GPL-3.0 as well
- The full license text and copyright notice must accompany any distribution

---

<div align="center">

<h2>Support</h2>

<p>If this project has helped you, consider buying me a coffee</p>
<p><sub>Your support keeps the maintenance going</sub></p>

<br/>

<strong>WeChat donation QR</strong><br/><br/>
<img src="https://raw.gitcode.com/ctkqiang_sr/ctkqiang_sr/raw/main/mm_reward_qrcode_1778988737577.png"
     alt="WeChat donation QR"
     width="240"
     style="border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.15);" />

<br/>
<br/>

</div>
