// vecmap 文档站 —— 双语渲染 + 浏览器语言自动检测
"use strict";

const I18N = {
  zh: {
    lang: "zh",
    toggle: "EN",
    hero: {
      badge: "v1.0.0 · 本地运行 · 只读探测 · GPL-3.0",
      title: "向量数据库攻击面评估框架",
      subtitle: "sqlmap 风格的 AI / RAG / 向量检索基础设施深度侦察工具：指纹识别、只读探测、模式枚举、记录提取、CVE/CNVD 关联与 MITRE ATT&CK 报告。",
      copy: "复制",
      copied: "已复制",
      installNote: "一键安装（无需 clone）：二进制写入 $(go env GOPATH)/bin/vecmap，要求 Go 1.27+（CGO 开启）。",
      getStarted: "快速开始",
      docs: "命令一览",
      gitHub: "GitHub",
    },
    nav: {
      features: "特性",
      commands: "命令",
      vendors: "厂商",
      arch: "架构",
      data: "数据",
      install: "安装",
      localization: "本地化",
      legal: "授权",
    },
    stats: [
      { value: "11", label: "厂商适配器" },
      { value: "85", label: "MITRE 技术" },
      { value: "13", label: "内置公告" },
      { value: "3", label: "报告格式" },
    ],
    features: {
      title: "核心特性",
      items: [
        { icon: "🧩", title: "11 厂商适配器", desc: "Qdrant、Milvus、Weaviate、Chroma、Redis/RediSearch、Elasticsearch、OpenSearch、pgvector、Typesense、Pinecone、Vespa；注册表机制，新增产品不改核心引擎。" },
        { icon: "🛰️", title: "gRPC 反射驱动", desc: "v1alpha 服务反射 + dynamicpb 描述符动态调用 + raw wire 回退，不依赖任何生成桩。" },
        { icon: "🛡️", title: "只读铁律", desc: "仅 GET/HEAD/OPTIONS 与只读 POST；/management/stop、/delete、/drop、/upsert 等破坏性路径硬拒绝，永不执行。" },
        { icon: "🧬", title: "深度提取", desc: "集合模式、维度、度量、索引类型、点数量、字段定义、记录负载与向量采样，上限可配。" },
        { icon: "📚", title: "数据驱动公告", desc: "内嵌 GitHub Security Advisory 快照，零 Go 硬编码，CVE/CNVD 版本区间匹配。" },
        { icon: "🌏", title: "双语与设备语言", desc: "全部输出中英双语，默认跟随设备系统语言（macOS AppleLanguages）。" },
        { icon: "🔎", title: "完整证据链", desc: "HTTP 请求/响应/哈希/耗时全程记录，请求头、Cookie 与 URL 查询自动脱敏。" },
        { icon: "🧪", title: "表驱动测试", desc: "版本区间、范围、wire 编解码、公告目录、WAL、脱敏、RESP、报告渲染全覆盖。" },
      ],
    },
    commands: {
      title: "命令一览",
      desc: "全部命令均需 --authorize 确认已获书面授权；破坏性接口永不执行。",
      code: `vecmap scan [OPTIONS] TARGET...          # 攻击面扫描：指纹、只读探测、CVE/CNVD 关联
vecmap discover [OPTIONS] HOST|CIDR...   # 主机/网段并发端口发现
vecmap dump [OPTIONS] TARGET...          # 深度枚举与记录提取
vecmap sessions                          # 列出本地会话
vecmap report --session <id> ...         # 导出会话报告（markdown/json/html）
vecmap advisories                        # 列出内置公告目录
vecmap delete --session <id>             # 删除会话（级联）
vecmap version                           # 版本信息
vecmap help [命令]                       # 帮助（--usage 仅语法）
vecmap man                               # roff 手册页（中/英）
vecmap completion bash|zsh               # shell 补全脚本`,
      rows: [
        ["scan", "指纹识别 + 只读探测 + 公告关联 + 风险发现", "--mode --extract --vectors --fuzz --api-key --scope-cidr"],
        ["discover", "并发端口发现，开放端口持久化为会话目标", "--ports --timeout --concurrency"],
        ["dump", "集合模式枚举 + 记录/向量提取", "--collection --namespace --max-records --batch"],
        ["sessions", "本地会话列表（状态着色）", "--db"],
        ["report", "离线报告渲染", "--format --output --lang"],
        ["advisories", "内置公告目录（数据驱动）", "--lang"],
        ["delete", "会话级联删除", "--session"],
        ["man", "手册页输出（中/英）", "--lang"],
        ["completion", "bash/zsh 补全", "—"],
      ],
    },
    vendors: {
      title: "厂商与端口",
      desc: "目标支持 URL、host:port 与 CIDR（配合 --ports 展开）。",
      rows: [
        ["Qdrant", "6333, 6334", "--api-key（api-key 头）"],
        ["Milvus", "19530, 9091", "无 / --bearer"],
        ["Weaviate", "8080, 50051", "--bearer"],
        ["Chroma", "8000", "--bearer"],
        ["Redis / RediSearch", "6379, 6380", "--user / --pass（AUTH）"],
        ["Elasticsearch / OpenSearch", "9200, 9300", "--api-key（ApiKey 头）"],
        ["PostgreSQL pgvector", "5432", "--dsn 或 --user/--pass/--database"],
        ["Typesense", "8108", "--api-key（X-TYPESENSE-API-KEY 头）"],
        ["Pinecone", "443", "--api-key（Api-Key 头）"],
        ["Vespa", "8080, 19071", "无"],
      ],
    },
    arch: {
      title: "系统架构",
      desc: "应用层只依赖适配器接口（Vendor / Fingerprint / Probe / Enumerate），厂商实现收敛在 vendors 包。",
      nodes: [
        { title: "cmd/vecmap", desc: "命令路由：scan / discover / dump / sessions / report / advisories / delete / help / man / completion", sub: false },
        { title: "internal/app", desc: "参数解析 · 扫描编排 · TUI 帮助 / 手册 / 补全", sub: true },
        { title: "internal/engine", desc: "适配器注册表 · 目标/范围 · 发现 · 探测 · 指纹 · 风险分析 · 提取", sub: false },
        { title: "internal/engine/vendors", desc: "11 厂商适配器 · RegisterAll", sub: true },
        { title: "协议层", desc: "HTTP 证据链（脱敏/限速/哈希） · gRPC 反射动态调用 + raw wire · Redis RESP · PostgreSQL 线协议", sub: false, proto: true },
        { title: "SQLite WAL", desc: "~/.vecmap/vecmap.db —— 会话 / 目标 / 集合 / 记录 / 发现 / 证据（目录 0700，文件 0600）", sub: true },
        { title: "internal/report", desc: "Markdown / JSON / HTML —— 风险汇总 · MITRE 覆盖 · 证据附录", sub: false },
      ],
    },
    data: {
      title: "数据与公告",
      desc: "内置公告零 Go 硬编码，全部来自内嵌 GitHub Security Advisory 数据文件。",
      rows: [
        ["GHSA-*.json", "GitHub Advisory API 官方记录快照"],
        ["extra.json", "无公开 GHSA JSON 的补充条目（CVE-2026-69111、CVE-2026-92782、Typesense 两条）"],
        ["meta.json", "中文本地化、厂商归属、CVE↔CNVD 关联、MITRE 映射、匹配策略与区间校正"],
      ],
      exitTitle: "退出码",
      exit: [
        ["0", "成功"],
        ["1", "运行期错误（网络、数据库、适配器）"],
        ["2", "用法错误（未知命令、缺少必填参数、缺少 --authorize）"],
      ],
      envTitle: "环境变量",
      env: [
        ["VECMAP_DB", "默认数据库路径（覆盖 ~/.vecmap/vecmap.db）"],
        ["VECMAP_LANG", "默认界面语言（en/zh）"],
        ["NO_COLOR", "关闭彩色输出"],
        ["HTTP_PROXY / HTTPS_PROXY", "未指定 --proxy 时由 HTTP 客户端使用"],
      ],
    },
    install: {
      title: "安装",
      note: "make build 输出 ./build/vecmap；中文设备开箱即中文，--lang=en 随时切回。文档站无需构建，直接打开 docs/index.html。",
    },
    localization: {
      title: "本地化",
      desc: "全部用户可见输出中英双语；默认跟随设备系统语言（macOS AppleLanguages/AppleLocale，Linux 即 locale 环境变量）。语言优先级：",
      priority: [
        ["--lang", "命令行参数"],
        ["VECMAP_LANG", "环境变量"],
        ["设备系统语言", "macOS AppleLanguages/AppleLocale"],
        ["英文", "兜底"],
      ],
    },
    legal: {
      title: "安全与授权",
      text: "《中华人民共和国网络安全法》第二十七条禁止任何个人和组织从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动；未经授权对向量数据库与检索服务实施扫描、枚举与数据提取，可能触犯《中华人民共和国刑法》第二百八十五条。本工具仅限自有资产或已获书面授权的测试环境使用。",
      disclaimer: "使用前必须取得目标范围的书面授权并传入 --authorize。未授权扫描违法，后果由使用者自行承担。",
    },
    support: {
      title: "支持",
      text: "如果您觉得本项目对您有帮助，欢迎请我喝杯咖啡",
    },
    footer: {
      text: "作者：钟智强 · 哪吒网络安全 · 向量数据库攻击面评估框架",
    },
  },

  en: {
    lang: "en",
    toggle: "中文",
    hero: {
      badge: "v1.0.0 · local-only · read-only probing · GPL-3.0",
      title: "Vector Database Attack-Surface Assessment Framework",
      subtitle: "A sqlmap-style deep-reconnaissance tool for AI / RAG / vector retrieval infrastructure: fingerprinting, read-only probing, schema enumeration, record extraction, CVE/CNVD correlation, and MITRE ATT&CK reporting.",
      copy: "Copy",
      copied: "Copied",
      installNote: "One-command install (no clone): the binary lands in $(go env GOPATH)/bin/vecmap. Requires Go 1.27+ with CGO enabled.",
      getStarted: "Get Started",
      docs: "Commands",
      gitHub: "GitHub",
    },
    nav: {
      features: "Features",
      commands: "Commands",
      vendors: "Vendors",
      arch: "Architecture",
      data: "Data",
      install: "Install",
      localization: "Localization",
      legal: "Legal",
    },
    stats: [
      { value: "11", label: "vendor adapters" },
      { value: "85", label: "MITRE techniques" },
      { value: "13", label: "built-in advisories" },
      { value: "3", label: "report formats" },
    ],
    features: {
      title: "Core Features",
      items: [
        { icon: "🧩", title: "11 vendor adapters", desc: "Qdrant, Milvus, Weaviate, Chroma, Redis/RediSearch, Elasticsearch, OpenSearch, pgvector, Typesense, Pinecone, Vespa — registry-driven, zero vendor branches in the core engine." },
        { icon: "🛰️", title: "Reflection-driven gRPC", desc: "v1alpha server reflection + dynamicpb descriptor calls + raw-wire fallback. No generated stubs." },
        { icon: "🛡️", title: "Read-only by design", desc: "GET/HEAD/OPTIONS and read-only POST only; /management/stop, /delete, /drop, /upsert and other destructive paths are hard-denied." },
        { icon: "🧬", title: "Deep extraction", desc: "Collection schemas, dimensions, metrics, index types, point counts, field definitions, record payloads and vector samples — all limits configurable." },
        { icon: "📚", title: "Data-driven advisories", desc: "Embedded GitHub Security Advisory snapshots with zero Go hardcoding; CVE/CNVD version-range matching." },
        { icon: "🌏", title: "Bilingual + device locale", desc: "Every output in English and Chinese; the default follows the device system language (macOS AppleLanguages)." },
        { icon: "🔎", title: "Full evidence chain", desc: "Request/response/hash/duration recorded for every exchange; headers, cookies and URL queries auto-redacted." },
        { icon: "🧪", title: "Table-driven tests", desc: "Version ranges, scope, wire codecs, advisory catalog, WAL, redaction, RESP and report rendering all covered." },
      ],
    },
    commands: {
      title: "Commands",
      desc: "Every command requires --authorize confirming written permission; destructive endpoints are never invoked.",
      code: `vecmap scan [OPTIONS] TARGET...          # attack-surface scan: fingerprint, read-only probes, CVE/CNVD correlation
vecmap discover [OPTIONS] HOST|CIDR...   # concurrent host/CIDR port discovery
vecmap dump [OPTIONS] TARGET...          # deep enumeration and record extraction
vecmap sessions                          # list local sessions
vecmap report --session <id> ...         # export a session report (markdown/json/html)
vecmap advisories                        # list the built-in advisory catalog
vecmap delete --session <id>             # delete a session (cascading)
vecmap version                           # print the version
vecmap help [command]                    # help (--usage for synopsis only)
vecmap man                               # roff manual page (en/zh)
vecmap completion bash|zsh               # shell completion scripts`,
      rows: [
        ["scan", "Fingerprinting + read-only probes + advisory correlation + findings", "--mode --extract --vectors --fuzz --api-key --scope-cidr"],
        ["discover", "Concurrent port discovery; open ports persisted as session targets", "--ports --timeout --concurrency"],
        ["dump", "Collection schema enumeration + record/vector extraction", "--collection --namespace --max-records --batch"],
        ["sessions", "Local session list (colored status)", "--db"],
        ["report", "Offline report rendering", "--format --output --lang"],
        ["advisories", "Built-in advisory catalog (data-driven)", "--lang"],
        ["delete", "Session cascade deletion", "--session"],
        ["man", "Manual page output (en/zh)", "--lang"],
        ["completion", "bash/zsh completion", "—"],
      ],
    },
    vendors: {
      title: "Vendors & Ports",
      desc: "Targets support URLs, host:port pairs and CIDR ranges (expanded with --ports).",
      rows: [
        ["Qdrant", "6333, 6334", "--api-key (api-key header)"],
        ["Milvus", "19530, 9091", "none / --bearer"],
        ["Weaviate", "8080, 50051", "--bearer"],
        ["Chroma", "8000", "--bearer"],
        ["Redis / RediSearch", "6379, 6380", "--user / --pass (AUTH)"],
        ["Elasticsearch / OpenSearch", "9200, 9300", "--api-key (ApiKey header)"],
        ["PostgreSQL pgvector", "5432", "--dsn or --user/--pass/--database"],
        ["Typesense", "8108", "--api-key (X-TYPESENSE-API-KEY header)"],
        ["Pinecone", "443", "--api-key (Api-Key header)"],
        ["Vespa", "8080, 19071", "none"],
      ],
    },
    arch: {
      title: "Architecture",
      desc: "The application layer depends only on adapter ports (Vendor / Fingerprint / Probe / Enumerate); vendor implementations live in the vendors package.",
      nodes: [
        { title: "cmd/vecmap", desc: "Command routing: scan / discover / dump / sessions / report / advisories / delete / help / man / completion", sub: false },
        { title: "internal/app", desc: "Argument parsing · orchestration · TUI help / manual / completion", sub: true },
        { title: "internal/engine", desc: "Adapter registry · targets/scope · discovery · probing · fingerprinting · analysis · extraction", sub: false },
        { title: "internal/engine/vendors", desc: "11 vendor adapters · RegisterAll", sub: true },
        { title: "Protocol layer", desc: "HTTP evidence chain (redaction/rate-limit/hash) · gRPC reflection dynamic calls + raw wire · Redis RESP · PostgreSQL wire protocol", sub: false, proto: true },
        { title: "SQLite WAL", desc: "~/.vecmap/vecmap.db — sessions / targets / collections / records / findings / evidence (dir 0700, file 0600)", sub: true },
        { title: "internal/report", desc: "Markdown / JSON / HTML — risk summary · MITRE coverage · evidence appendix", sub: false },
      ],
    },
    data: {
      title: "Data & Advisories",
      desc: "The built-in catalog has zero Go hardcoding — it is loaded from embedded GitHub Security Advisory data files.",
      rows: [
        ["GHSA-*.json", "Official GitHub Advisory API record snapshots"],
        ["extra.json", "Supplementary entries without a public GHSA JSON (CVE-2026-69111, CVE-2026-92782, two Typesense entries)"],
        ["meta.json", "Chinese localization, vendor attribution, CVE↔CNVD linkage, MITRE mappings, match policies and range corrections"],
      ],
      exitTitle: "Exit codes",
      exit: [
        ["0", "Success"],
        ["1", "Runtime error (network, database, adapter)"],
        ["2", "Usage error (unknown command, missing required argument, missing --authorize)"],
      ],
      envTitle: "Environment variables",
      env: [
        ["VECMAP_DB", "Default database path (overrides ~/.vecmap/vecmap.db)"],
        ["VECMAP_LANG", "Default UI language (en/zh)"],
        ["NO_COLOR", "Disable colored output"],
        ["HTTP_PROXY / HTTPS_PROXY", "Used by the HTTP client when --proxy is not set"],
      ],
    },
    install: {
      title: "Install",
      note: "make build produces ./build/vecmap. Chinese devices get Chinese out of the box; --lang=en switches back. The docs site needs no build — open docs/index.html.",
    },
    localization: {
      title: "Localization",
      desc: "Every user-facing string is bilingual; the default follows the device system language (macOS AppleLanguages/AppleLocale, on Linux the locale environment variables). Priority:",
      priority: [
        ["--lang", "command-line flag"],
        ["VECMAP_LANG", "environment variable"],
        ["Device language", "macOS AppleLanguages/AppleLocale"],
        ["English", "fallback"],
      ],
    },
    legal: {
      title: "Authorization & Legal",
      text: "Article 27 of the PRC Cybersecurity Law prohibits unauthorized intrusion into networks, disruption of network functions, and theft of network data; scanning, enumerating, or extracting data from vector databases without authorization may violate Article 285 of the PRC Criminal Law. Use this tool only on assets you own or with written authorization.",
      disclaimer: "Obtain written permission for the target scope and pass --authorize before scanning. Unauthorized scanning is illegal; the consequences rest entirely with the user.",
    },
    support: {
      title: "Support",
      text: "If this project has helped you, consider buying me a coffee",
    },
    footer: {
      text: "Author: Zhong Zhiqiang · Nezha Network Security · Vector Database Attack-Surface Assessment Framework",
    },
  },
};

// ---- 语言检测：localStorage 覆盖 > navigator.language zh 前缀 > en ----
function detectLang() {
  const saved = localStorage.getItem("vecmap-lang");
  if (saved === "zh" || saved === "en") return saved;
  const nav = (navigator.language || navigator.userLanguage || "").toLowerCase();
  return nav.indexOf("zh") === 0 ? "zh" : "en";
}

let lang = detectLang();

function t(key) {
  return key.split(".").reduce((obj, part) => (obj ? obj[part] : undefined), I18N[lang]);
}

function applyStatic() {
  document.documentElement.lang = lang;
  document.title = lang === "zh"
    ? "vecmap — 向量数据库攻击面评估框架"
    : "vecmap — Vector Database Attack-Surface Assessment Framework";
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  const toggle = document.getElementById("lang-toggle");
  toggle.textContent = I18N[lang].toggle;
}

function renderStats() {
  const box = document.getElementById("hero-stats");
  box.innerHTML = I18N[lang].stats
    .map((s) => `<div class="hero-stat"><div class="hero-stat-value">${s.value}</div><div class="hero-stat-label">${s.label}</div></div>`)
    .join("");
}

function renderFeatures() {
  document.getElementById("features-grid").innerHTML = I18N[lang].features.items
    .map((f) => `<div class="card"><div class="card-icon">${f.icon}</div><div class="card-title">${f.title}</div><p class="card-desc">${f.desc}</p></div>`)
    .join("");
}

function renderCommands() {
  document.getElementById("commands-code").textContent = I18N[lang].commands.code;
  const rows = I18N[lang].commands.rows;
  const head = lang === "zh" ? ["命令", "功能", "关键参数"] : ["Command", "Purpose", "Key options"];
  document.getElementById("commands-table").innerHTML =
    `<thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>` +
    rows.map((r) => `<tr><td><code>${r[0]}</code></td><td>${r[1]}</td><td>${r[2]}</td></tr>`).join("") +
    `</tbody>`;
}

function renderVendors() {
  const head = lang === "zh" ? ["厂商", "端口", "认证方式"] : ["Vendor", "Ports", "Authentication"];
  document.getElementById("vendors-table").innerHTML =
    `<thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>` +
    I18N[lang].vendors.rows.map((r) => `<tr><td>${r[0]}</td><td>${r[1]}</td><td><code>${r[2]}</code></td></tr>`).join("") +
    `</tbody>`;
}

function renderArch() {
  document.getElementById("arch-flow").innerHTML = I18N[lang].arch.nodes
    .map((n) => {
      const cls = n.proto ? "arch-node proto" : n.sub ? "arch-node sub" : "arch-node";
      return `<div class="${cls}"><div><div class="arch-node-title">${n.title}</div><div class="arch-node-desc">${n.desc}</div></div></div>`;
    })
    .join('<div class="arch-arrow">↓</div>');
}

function renderData() {
  const data = I18N[lang].data;
  const fileHead = lang === "zh" ? ["文件", "内容"] : ["File", "Contents"];
  document.getElementById("data-table").innerHTML =
    `<thead><tr>${fileHead.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>` +
    data.rows.map((r) => `<tr><td><code>${r[0]}</code></td><td>${r[1]}</td></tr>`).join("") +
    `</tbody>`;

  const exitHead = lang === "zh" ? ["退出码", "含义"] : ["Code", "Meaning"];
  document.getElementById("exit-table").innerHTML =
    `<thead><tr><th colspan="2">${data.exitTitle}</th></tr></thead><tbody>` +
    data.exit.map((r) => `<tr><td><code>${r[0]}</code></td><td>${r[1]}</td></tr>`).join("") +
    `</tbody>`;

  const envHead = lang === "zh" ? ["环境变量", "作用"] : ["Variable", "Effect"];
  document.getElementById("env-table").innerHTML =
    `<thead><tr><th colspan="2">${data.envTitle}</th></tr></thead><tbody>` +
    data.env.map((r) => `<tr><td><code>${r[0]}</code></td><td>${r[1]}</td></tr>`).join("") +
    `</tbody>`;
}

function renderPriority() {
  document.getElementById("priority-list").innerHTML = I18N[lang].localization.priority
    .map((p) => `<li><code>${p[0]}</code> — ${p[1]}</li>`)
    .join("");
}

function renderAll() {
  applyStatic();
  renderStats();
  renderFeatures();
  renderCommands();
  renderVendors();
  renderArch();
  renderData();
  renderPriority();
}

// ---- 复制按钮 ----
function bindCopy() {
  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      let text = "";
      if (btn.dataset.copyText) {
        text = btn.dataset.copyText;
      } else {
        const target = document.getElementById(btn.dataset.copyTarget);
        text = target ? target.textContent : "";
      }
      navigator.clipboard.writeText(text).then(() => {
        const original = btn.textContent;
        btn.textContent = t("hero.copied");
        btn.classList.add("copied");
        setTimeout(() => {
          btn.textContent = original;
          btn.classList.remove("copied");
        }, 1400);
      });
    });
  });
}

// ---- 语言切换 ----
document.getElementById("lang-toggle").addEventListener("click", () => {
  lang = lang === "zh" ? "en" : "zh";
  localStorage.setItem("vecmap-lang", lang);
  renderAll();
});

// ---- 滚动高亮 ----
function bindScrollSpy() {
  const links = document.querySelectorAll(".nav a");
  const sections = Array.from(links)
    .map((link) => document.querySelector(link.getAttribute("href")))
    .filter(Boolean);
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        links.forEach((link) => {
          link.classList.toggle("active", link.getAttribute("href") === "#" + entry.target.id);
        });
      });
    },
    { rootMargin: "-20% 0px -70% 0px" }
  );
  sections.forEach((section) => observer.observe(section));
}

renderAll();
bindCopy();
bindScrollSpy();
