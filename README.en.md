<div align="center">

# vecmap

**Vector database attack-surface assessment framework** — 向量数据库攻击面评估框架

A sqlmap-style deep-reconnaissance tool for AI / RAG / vector retrieval infrastructure

[简体中文](README.md) | English

</div>

---

## Overview

vecmap is a **local-only** Go CLI for performing sqlmap-style deep reconnaissance
against **authorized** vector databases and retrieval infrastructure: product
fingerprinting, read-only gRPC/REST probing, schema enumeration, record
extraction, CVE/CNVD correlation, and MITRE ATT&CK reporting. All evidence and
extracted data is persisted to a local SQLite database (WAL) for offline
reproduction and report export.

**No AI/LLM calls, no SaaS dependency, no destructive actions.** Every probe is
strictly read-only (GET/HEAD/OPTIONS and read-only POST); destructive endpoints
such as `/management/stop`, `/delete`, `/drop`, and `/upsert` are hard-denied
and never invoked.

## Features

| Capability | Details |
|---|---|
| Vendor adapters | Qdrant, Milvus, Weaviate, Chroma, Redis/RediSearch, Elasticsearch, OpenSearch, PostgreSQL pgvector, Typesense, Pinecone, Vespa |
| Fingerprinting | REST endpoint fingerprints, gRPC health checks + server reflection, raw protobuf string extraction |
| Real protocols | Reflection-driven dynamic gRPC calls (dynamicpb + protojson) with raw-wire fallback, Redis RESP client, PostgreSQL wire protocol (pgx) |
| Read-only probing | Per-vendor probe catalogs with a hard destructive-path denylist and permissive-CORS detection |
| Deep extraction | Collection schemas, dimensions, metrics, index types, point counts, field definitions, record payloads, and vector samples |
| Advisory correlation | Embedded GitHub Security Advisory snapshots (data-driven, zero Go hardcoding), version-range matching against CVE/CNVD |
| Risk analysis | Unauthenticated enumeration/extraction, metrics/docs/snapshot exposure, CORS, gRPC reflection, cleartext endpoints — bilingual text with MITRE mappings |
| Reports | Markdown / JSON / HTML with a risk summary, MITRE coverage table, and evidence appendix |
| Persistence | SQLite WAL at `~/.vecmap/vecmap.db` (dir 0700, file 0600) |
| Localization | Every user-facing string is bilingual; the default language follows the device setting (macOS system language) |
| CLI UX | ASCII banner, colored TUI, `help`/`--usage`/`man` manual page, bash/zsh completion, standard exit codes |

## Installation

```bash
# Requires Go 1.27+ with CGO enabled (SQLite driver)
go build -o bin/vecmap ./cmd/vecmap
```

## Quick Start

```bash
# Help (Chinese devices get Chinese by default; --lang=en switches to English)
./bin/vecmap help
./bin/vecmap help scan            # full options for one command
./bin/vecmap scan --usage         # synopsis only

# Standard scan: fingerprinting, read-only probes, CVE correlation
./bin/vecmap scan --authorize \
  --scope-cidr 10.0.0.0/24 \
  http://10.0.0.5:6333

# Deep scan: enumerate collections, extract records and vectors
./bin/vecmap dump --authorize --vectors --max-records 500 \
  --scope-cidr 10.0.0.0/24 \
  http://10.0.0.5:6333

# Port discovery
./bin/vecmap discover --authorize --scope-cidr 10.0.0.0/24 10.0.0.0/24

# Sessions and reports
./bin/vecmap sessions
./bin/vecmap report --session <id> --format markdown --output report.md

# Manual page and shell completion
./bin/vecmap man | man -l -
source <(./bin/vecmap completion bash)
```

## Commands

| Command | Description |
|---|---|
| `scan` | Attack-surface scan (fingerprinting, probes, advisory correlation; `--mode deep` extracts data) |
| `discover` | Concurrent TCP/HTTP/TLS/gRPC/RESP port discovery across hosts/CIDRs |
| `dump` | Deep enumeration and record extraction (implies `--mode deep --extract`) |
| `sessions` | List local sessions |
| `report` | Export a session report (markdown/json/html) |
| `advisories` | List the built-in advisory catalog |
| `delete` | Delete a session (cascading) |
| `version` | Print the version |
| `help` | Overview or per-command help |
| `man` | roff manual page (English/Chinese) |
| `completion` | bash/zsh completion scripts |

## Target Formats

```
http://host:6333   https://host   redis://host:6379
postgres://user:pass@host/db   grpc://host:19530
10.0.0.5:6333      10.0.0.0/24 (CIDR, expanded with --ports)
```

Vendor default ports:

| Vendor | Ports |
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

## Authentication

| Flag | Description |
|---|---|
| `--api-key KEY` | API key; header chosen per vendor (Qdrant `api-key`, Typesense `X-TYPESENSE-API-KEY`, Pinecone `Api-Key`, ES/OpenSearch `ApiKey`, others `Bearer`) |
| `--bearer TOKEN` | `Authorization: Bearer` |
| `--user` / `--pass` | HTTP Basic |
| `--dsn DSN` | PostgreSQL connection string |
| `--database NAME` | Database name / tenant path / Redis DB number |

## Scope and Authorization

- **`--authorize` is required**: obtain written permission for the target scope
  before scanning; unauthorized scanning is illegal.
- `--scope-cidr` / `--scope-domain`: authorized scope (repeatable); when set,
  unmatched hosts are denied.
- `--exclude-cidr` / `--exclude-domain`: exclusions; exclusion-only scopes are
  otherwise permissive.
- `--scope-port`: port allowlist.
- Read-only operations only; `/management/stop` is correlated by version but
  never requested.

## Advisory Data Sources

The built-in catalog has **zero Go hardcoding** — it is loaded from embedded data
files (`internal/constant/data/advisories/`, compiled in via `go:embed`):

| File | Contents |
|---|---|
| `GHSA-*.json` | Official GitHub Advisory API record snapshots |
| `extra.json` | Supplementary entries without a public GHSA JSON (CVE-2026-69111, CVE-2026-92782, two Typesense entries), same schema |
| `meta.json` | Chinese localization, vendor attribution, CVE↔CNVD linkage, MITRE mappings, match policies, and range corrections |

Refresh: `bash scripts/refresh_advisories.sh`. Unverified external advisories
(`--advisories path.json`) are listed but never auto-matched.

## Data and Reports

- Database defaults to `~/.vecmap/vecmap.db` (override with `--db` or `VECMAP_DB`),
  WAL + busy_timeout.
- Sessions aggregate targets, steps, probes, collections, records, findings, and
  HTTP evidence; `sessions`/`report` reproduce everything offline.
- MITRE ATT&CK catalog: 83 techniques across 14 tactics, bilingual; findings map
  to T1595/T1046/T1213/T1567 and more.

## Exit Codes and Environment Variables

| Exit code | Meaning |
|---|---|
| 0 | Success |
| 1 | Runtime error (network, database, adapter) |
| 2 | Usage error (unknown command, missing required argument, missing `--authorize`) |

| Variable | Effect |
|---|---|
| `VECMAP_DB` | Default database path |
| `VECMAP_LANG` | Default UI language (`en`/`zh`) |
| `NO_COLOR` | Disable colored output |
| `HTTP_PROXY` / `HTTPS_PROXY` | Used by the HTTP client when `--proxy` is not set |

## Localization

- **Every user-facing string is bilingual**: help, manual page (Chinese version
  selected automatically), error/usage hints, table headers and values, the scan
  report card, finding texts, and reports (Markdown/HTML/JSON).
- **The default follows the device**: `--lang` > `VECMAP_LANG` > device system
  language (macOS `AppleLanguages`/`AppleLocale`; on Linux the locale environment
  variables) > English.
- Chinese devices get Chinese out of the box; `--lang=en` switches back. A
  terminal that forces `LANG=en_US` does not override the device setting.

## Development

```bash
make build    # build bin/vecmap
make test     # go test ./... (package test)
make vet      # go vet ./...
make fmt      # gofmt -l .
make manpage  # sync docs/vecmap.1 and docs/vecmap.zh.1
```

## Project Layout

```
cmd/vecmap/              CLI entrypoint
internal/app/            argument parsing, orchestration, help/man/completion, TUI
internal/engine/         engine: registry, targets, scope, HTTP/gRPC/RESP,
                         discovery, probing, fingerprinting, analysis, extraction
internal/engine/vendors/ 11 vendor adapters + RegisterAll
internal/model/          data models (sessions/targets/collections/records/findings/advisories/reports)
internal/database/       SQLite store (WAL, cascade deletes, session aggregation)
internal/report/         report rendering (Markdown/JSON/HTML)
internal/constant/       constants, MITRE catalog, advisory data loader
internal/utilities/      i18n, version ranges, redaction, formatting
internal/logger/         logging adapter (wraps utilities/logger)
test/                    tests (package test)
docs/                    manual pages (English/Chinese roff)
scripts/                 advisory snapshot refresh script
```

## Disclaimer

vecmap is for **authorized security assessments only**. You must obtain written
permission for the target assets and are responsible for your own actions. The
tool contains no exploits, no denial-of-service, and no destructive functionality.
