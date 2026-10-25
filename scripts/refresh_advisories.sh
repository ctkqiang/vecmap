#!/usr/bin/env bash
# refresh_advisories.sh — 从 GitHub Advisory API 重新下载内置公告快照。
#
# 用法: bash scripts/refresh_advisories.sh
# 输出: internal/constant/data/advisories/GHSA-*.json
#
# 说明:
# - GHSA 记录来自 https://api.github.com/advisories/GHSA-<id>（官方数据）。
# - extra.json 中的条目（CVE-2026-69111、CVE-2026-92782、CVE-2026-47216、
#   CVE-2026-47225）没有公开 GHSA JSON，请勿删除；如需更新请手工核对
#   NVD/CVE.org/VulnCheck 后修改 extra.json。
# - meta.json 提供中文本地化、厂商归属、匹配策略与影响区间校正，
#   不随本脚本覆盖。
set -euo pipefail

GHSA_IDS=(
  xcr2-h8hv-6227  # CVE-2024-3584 Qdrant
  7m75-x27w-r52r  # CVE-2024-3829 Qdrant
  f632-vm87-2m2f  # CVE-2026-25628 Qdrant
  mhjq-8c7m-3f7p  # CVE-2025-64513 Milvus
  7ppg-37fh-vcr6  # CVE-2026-26190 Milvus
  jqpm-wf57-qx5c  # CVE-2026-11500 Weaviate
  f4j7-r4q5-qw2c  # CVE-2026-45829 Chroma
  jfh8-c2jp-5v3q  # CVE-2021-44228 Apache Log4j2
  9wpj-h5jq-88p9  # CVE-2022-0543 Redis (Debian packaging)
)

TARGET_DIR="$(cd "$(dirname "$0")/.." && pwd)/internal/constant/data/advisories"
mkdir -p "$TARGET_DIR"

for id in "${GHSA_IDS[@]}"; do
  case "$id" in \#*) continue ;; esac
  curl -sf \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/advisories/GHSA-$id" \
    -o "$TARGET_DIR/GHSA-$id.json"
  echo "updated GHSA-$id"
done

echo "done; run: go test ./test/ -run Advisory"
