#!/usr/bin/env node
"use strict";

/**
 * Next.js App Router + Supabase Security Audit CLI
 *
 * Usage:
 *   node security-audit.js ./path/to/project
 *   node security-audit.js .               # カレントディレクトリを診断
 *
 * Stack:
 *   - Next.js App Router
 *   - Supabase（service_role key のみ使用・anon key 不使用推奨）
 *   - 独自 JWT 認証（Supabase Auth 不使用の場合）
 *   - Vercel (or any hosting)
 */

const fs   = require("fs");
const path = require("path");

// ─── 設定 ─────────────────────────────────────────────────────────────────────

const INCLUDE_EXTENSIONS   = new Set([".ts", ".tsx", ".js", ".jsx"]);
const INCLUDE_SPECIAL_FILES = new Set([".env.example", ".env.local.example", "middleware.ts"]);
const INCLUDE_DIRS = [
  "lib/", "utils/", "actions/", "app/api/", "services/", "hooks/", "supabase/migrations/",
];
const EXCLUDE_DIRS  = new Set(["node_modules", ".git", ".next", "dist", "build"]);
const SKIP_FILES    = new Set([".env", ".env.local", "security-audit.js"]);
const MAX_CHARS     = 5000;

// NX002 のデフォルト除外ルート（認証前アクセスが設計上正しいもの）
// プロジェクトに合わせて追加・削除してください。
//
// 追加例：
//   "app/api/auth/register",   // 新規登録（認証前）
//   "app/api/contact",         // 未登録ユーザー向け問い合わせ
//   "app/api/webhooks/stripe", // Stripe Webhook（署名検証で担保）
//
const ALLOWLIST_NX002 = [
  "app/api/auth/register",           // 新規登録（認証前）
  "app/api/auth/login",              // ログイン（認証前）
  "app/api/apply",                   // 未登録ユーザー向け申込
  "app/api/contact",                 // 未登録ユーザー向け問い合わせ
  "app/api/presence",                // 匿名セッション
];

// NX001 で許可する NEXT_PUBLIC_ 変数（公開設計のもの）
// SUPABASE_URL と VAPID_PUBLIC_KEY は公開可能なためデフォルトで除外。
const KNOWN_SAFE_PUBLIC_VARS = new Set([
  "NEXT_PUBLIC_SUPABASE_URL",
  "NEXT_PUBLIC_VAPID_PUBLIC_KEY",
]);

// ─── ファイル収集 ──────────────────────────────────────────────────────────────

function shouldInclude(filePath, rootDir) {
  const rel  = path.relative(rootDir, filePath).replace(/\\/g, "/");
  const base = path.basename(filePath);
  const ext  = path.extname(filePath);

  if (SKIP_FILES.has(base)) return false;
  if (INCLUDE_SPECIAL_FILES.has(base)) return true;
  if (base.startsWith("next.config") && !rel.includes("/")) return true;
  if (!INCLUDE_EXTENSIONS.has(ext)) return false;
  if (!rel.includes("/")) return true;                          // root level .ts/.js
  return INCLUDE_DIRS.some((d) => rel.startsWith(d));
}

function walk(dir, rootDir, out = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return out; }

  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (EXCLUDE_DIRS.has(e.name) || (e.name.startsWith(".") && e.name !== ".env")) continue;
      walk(full, rootDir, out);
    } else if (e.isFile() && shouldInclude(full, rootDir)) {
      out.push(full);
    }
  }
  return out;
}

// ─── ユーティリティ ────────────────────────────────────────────────────────────

function readFile(fp) {
  try { return fs.readFileSync(fp, "utf8").slice(0, MAX_CHARS); }
  catch { return ""; }
}

function lineAt(content, idx) {
  return content.slice(0, idx).split("\n").length;
}

function findAll(content, re) {
  const r = [], g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  let m;
  while ((m = g.exec(content)) !== null) r.push({ match: m[0], index: m.index, line: lineAt(content, m.index) });
  return r;
}

function inAllowlist(rel, list) {
  // rel は常に "/" 正規化済み
  return list.some((p) => rel.startsWith(p));
}

// ─── 診断結果コレクター ────────────────────────────────────────────────────────

const findings = [];

function report(severity, id, rel, line, desc, fix) {
  findings.push({ severity, id, rel, line, desc, fix });
}

// ─── チェック実装 ──────────────────────────────────────────────────────────────

/* SB001 🔴  SUPABASE_SERVICE_ROLE_KEY が NEXT_PUBLIC_ 付きで定義されていないか */
function sb001(c, rel) {
  for (const m of findAll(c, /NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY/)) {
    report("critical", "SB001", rel, m.line,
      `SUPABASE_SERVICE_ROLE_KEY が NEXT_PUBLIC_ プレフィックス付きで露出している。クライアントバンドルに含まれリーク確定。`,
      `\`${rel}\` の \`NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY\` を \`SUPABASE_SERVICE_ROLE_KEY\` に変更し、app/api/ からのみ参照してください。`);
  }
}

/* SB002 🔴  anon キーがフロントエンドコードに存在しないか */
function sb002(c, rel) {
  const has = c.includes("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY") || c.includes("SUPABASE_PUBLISHABLE_KEY");
  if (!has) return;
  const isFront = c.includes('"use client"') || (rel.startsWith("app/") && !rel.startsWith("app/api/"));
  if (isFront) {
    report("critical", "SB002", rel, 1,
      `anon キー (SUPABASE_PUBLISHABLE_KEY) がフロントエンドで参照されている。削除済みのキーが再導入されている可能性。`,
      `\`${rel}\` から SUPABASE_PUBLISHABLE_KEY の参照を削除し、Supabase 操作は \`/api/\` Route Handler 経由に変更してください。`);
  }
}

/* SB003 🔴  extractToken を使っているが verifyMemberToken を呼んでいない */
function sb003(c, rel) {
  if (!rel.startsWith("app/api/")) return;
  if (!c.includes("extractToken")) return;
  if (c.includes("verifyMemberToken")) return;
  // 他の認証パターンがあれば除外（管理者ルート等）
  if (c.includes("ADMIN_PASSWORD") || c.includes("isMaster") || c.includes("verifyLocationPassword")) return;
  report("critical", "SB003", rel, 1,
    `extractToken() を呼んでいるが verifyMemberToken() が見当たらない。トークンの正当性が検証されないまま処理が続く可能性。`,
    `\`${rel}\` で \`verifyMemberToken(token)\` の戻り値を必ずチェックし、null の場合は即座に 401 を返してください。`);
}

/* SB004 🔴  fallback-dev-secret が本番コードに残っていないか */
function sb004(c, rel) {
  for (const m of findAll(c, /fallback-dev-secret/)) {
    report("critical", "SB004", rel, m.line,
      `"fallback-dev-secret" がコードに残っている。MEMBER_JWT_SECRET 未設定時に本番でも使われるリスク。`,
      `本番環境に \`MEMBER_JWT_SECRET\` を設定してください。コード上では未設定時にサーバー起動を失敗させることを推奨します：\n\`\`\`ts\nif (!process.env.MEMBER_JWT_SECRET) throw new Error("MEMBER_JWT_SECRET is required");\n\`\`\``);
  }
}

/* SB005 🟡  /api/admin/ 配下で ADMIN_PASSWORD 検証が行われているか */
function sb005(c, rel) {
  if (!rel.startsWith("app/api/admin/")) return;
  if (rel.endsWith("auth/route.ts") || rel.endsWith("auth/route.js")) return;  // 認証エンドポイント自体は除外
  // 公開 API は ALLOWLIST_NX002 で除外済みのため、ここでは管理系のみチェック
  const hasCheck = c.includes("ADMIN_PASSWORD") || c.includes("isMaster") || c.includes("communityAuth") || c.includes("verifyLocationPassword");
  if (!hasCheck) {
    report("warning", "SB005", rel, 1,
      `管理系 API に ADMIN_PASSWORD / isMaster の検証が見当たらない。認証なしで管理操作が実行される可能性。`,
      `\`${rel}\` の各 handler 先頭に \`if (!isMaster(req)) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });\` を追加してください。`);
  }
}

/* NX001 🔴  NEXT_PUBLIC_ プレフィックスに機密情報が含まれていないか */
function nx001(c, rel) {
  for (const m of findAll(c, /NEXT_PUBLIC_\w+/)) {
    const name = m.match;
    if (KNOWN_SAFE_PUBLIC_VARS.has(name)) continue;
    if (/KEY|SECRET|PASSWORD|TOKEN|PASS|ROLE|PRIVATE/i.test(name.replace("NEXT_PUBLIC_", ""))) {
      report("critical", "NX001", rel, m.line,
        `NEXT_PUBLIC_ に機密情報が含まれている可能性: \`${name}\``,
        `\`${name}\` を \`${name.replace("NEXT_PUBLIC_", "")}\` に変更し、app/api/ からのみ参照するようにしてください。`);
    }
  }
}

/* NX002 🔴  変更系 API handler に認証チェックがあるか */
function nx002(c, rel) {
  if (!rel.startsWith("app/api/")) return;
  if (!/route\.[jt]sx?$/.test(rel)) return;
  if (inAllowlist(rel, ALLOWLIST_NX002)) return;
  if (!/export async function (POST|PUT|PATCH|DELETE)/i.test(c)) return;  // 変更系がなければスキップ

  const hasAuth =
    /authorization/i.test(c) ||
    c.includes("verifyMemberToken") ||
    c.includes("isMaster") ||
    c.includes("ADMIN_PASSWORD") ||
    c.includes("verifyLocationPassword") ||
    c.includes("extractToken") ||
    c.includes("member-token") ||
    c.includes("communityAuth");

  if (!hasAuth) {
    report("critical", "NX002", rel, 1,
      `変更系 handler (POST/PUT/PATCH/DELETE) に認証チェックが見当たらない。`,
      `\`${rel}\` の各 handler 先頭に認証チェックを追加してください（例: \`isMaster(req)\` or \`verifyMemberToken(extractToken(req))\`）。`);
  }
}

/* NX003 🔴  "use server" ファイルの先頭でセッション検証しているか */
function nx003(c, rel) {
  if (!/["']use server["']/.test(c)) return;
  const idx   = c.search(/["']use server["']/);
  const block = c.slice(idx, idx + 600);
  const hasAuth = /session|getUser|verifyMemberToken|auth\(\)/.test(block);
  if (!hasAuth) {
    report("critical", "NX003", rel, lineAt(c, idx),
      `"use server" ファイルの先頭付近にセッション検証が見当たらない。未認証ユーザーが Server Action を呼べる可能性。`,
      `\`${rel}\` の各 Server Action 関数内先頭で \`verifyMemberToken()\` 等のセッション検証を実施し、未認証の場合は処理を中断してください。`);
  }
}

/* NX004 🟡  middleware.ts に matcher 設定があるか */
function nx004(c, rel) {
  if (rel !== "middleware.ts" && rel !== "middleware.js") return;
  if (!c.includes("matcher")) {
    report("warning", "NX004", rel, 1,
      `middleware.ts に matcher 設定が見当たらない。保護ルートがすべてのリクエストに適用されるか確認が必要。`,
      `\`middleware.ts\` に \`export const config = { matcher: ["/wework/:path*", "/admin/:path*"] }\` のような matcher を追加してください。`);
  }
}

/* NX005 🔴  "use client" コンポーネントから直接 Supabase を操作していないか */
function nx005(c, rel) {
  if (!/["']use client["']/.test(c)) return;
  const hasDb = c.includes("createClient") || c.includes("supabase.from") || c.includes("@supabase/supabase-js");
  if (hasDb) {
    report("critical", "NX005", rel, 1,
      `"use client" コンポーネントから直接 Supabase にアクセスしている。anon キー露出と RLS バイパスのリスク。`,
      `\`${rel}\` の Supabase 直接アクセスを除去し、\`fetch("/api/...")\` 経由に変更してください。`);
  }
}

/* GN001 🔴  APIキー・シークレットのハードコード検出 */
function gn001(c, rel) {
  if (rel.includes(".example")) return;  // サンプルファイルは除外

  const patterns = [
    { re: /(['"])sk-[A-Za-z0-9]{20,}\1/,                 desc: "OpenAI API キーらしきハードコード値" },
    { re: /(['"])pk_live_[A-Za-z0-9]{20,}\1/,            desc: "Stripe 本番公開キーらしきハードコード値" },
    { re: /(['"])AKIA[A-Z0-9]{16}\1/,                    desc: "AWS アクセスキー ID らしきハードコード値" },
    { re: /(['"])ey[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_.-]+\1/, desc: "JWT トークンらしきハードコード値" },
    { re: /service_role.*(['"])[a-zA-Z0-9.+/=]{60,}\1/i, desc: "Supabase service_role キーらしきハードコード値" },
    { re: /(?:password|passwd)\s*[:=]\s*(['"])[^${\s'"]{8,}\1/i, desc: "パスワードがハードコードされている可能性" },
    { re: /(?:secret)\s*[:=]\s*(['"])[^${\s'"]{8,}\1(?!.*fallback)/i, desc: "シークレットがハードコードされている可能性" },
  ];

  for (const { re, desc } of patterns) {
    for (const m of findAll(c, re)) {
      // コメント行スキップ
      const lineStart = c.lastIndexOf("\n", m.index) + 1;
      const lineText  = c.slice(lineStart, c.indexOf("\n", m.index));
      if (/^\s*(\/\/|\*)/.test(lineText)) continue;
      report("critical", "GN001", rel, m.line, desc,
        `\`${rel}\` L${m.line} のハードコード値を環境変数に移動してください。`);
    }
  }
}

/* GN002 🟡  console.log への機密情報出力 */
function gn002(c, rel) {
  for (const m of findAll(c, /console\.(log|error|warn|info)\s*\([^)]*?(password|token|secret|key(?!board)|hash|auth)/i)) {
    report("warning", "GN002", rel, m.line,
      `console.${m.match.split(".")[1].split("(")[0]}() に機密情報が含まれている可能性: \`${m.match.slice(0, 60)}\``,
      `\`${rel}\` L${m.line} の console.log から機密情報を除去するか、ログ出力を削除してください。`);
  }
}

/* GN003 🔵  @vercel/ への強依存 */
function gn003(c, rel) {
  for (const m of findAll(c, /from\s+['"]@vercel\//)) {
    report("info", "GN003", rel, m.line,
      `@vercel/ パッケージへの直接依存。Vercel 以外のホスティングへの移行が困難になる。`,
      `\`${rel}\` L${m.line} の @vercel/ 依存が必要最小限か確認し、可能であれば抽象化を検討してください。`);
  }
}

// ─── メイン ────────────────────────────────────────────────────────────────────

const rootDir = path.resolve(process.argv[2] || ".");
const start   = Date.now();

console.log("\n🔍 Next.js + Supabase セキュリティ診断を開始します...");
console.log(`📁 対象: ${rootDir}\n`);

const files = walk(rootDir, rootDir);
console.log(`📄 ${files.length} ファイルを解析中...\n`);

for (const fp of files) {
  const rel = path.relative(rootDir, fp).replace(/\\/g, "/");
  const c   = readFile(fp);
  if (!c) continue;

  sb001(c, rel); sb002(c, rel); sb003(c, rel); sb004(c, rel); sb005(c, rel);
  nx001(c, rel); nx002(c, rel); nx003(c, rel); nx004(c, rel); nx005(c, rel);
  gn001(c, rel); gn002(c, rel); gn003(c, rel);
}

const elapsed   = ((Date.now() - start) / 1000).toFixed(1);
const criticals = findings.filter((f) => f.severity === "critical");
const warnings  = findings.filter((f) => f.severity === "warning");
const infos     = findings.filter((f) => f.severity === "info");

// ─── レポート生成 ──────────────────────────────────────────────────────────────

const now = new Date();
const ts  = now.toISOString().replace(/[-:.TZ]/g, "").slice(0, 15);
const reportPath = `security-report-${ts}.md`;

const EMOJI = { critical: "🔴", warning: "🟡", info: "🔵" };
const LABEL = { critical: "Critical", warning: "Warning", info: "Info" };

function md(...lines) { return lines.join("\n"); }

const sections = [];

sections.push(md(
  `# セキュリティ診断レポート`,
  ``,
  `| 項目 | 値 |`,
  `|------|-----|`,
  `| 生成日時 | ${now.toLocaleString("ja-JP")} |`,
  `| 対象ディレクトリ | \`${rootDir}\` |`,
  `| 解析ファイル数 | ${files.length} |`,
  `| 解析時間 | ${elapsed} 秒 |`,
  `| ファイル先頭解析上限 | ${MAX_CHARS.toLocaleString()} 文字 |`,
));

sections.push(md(
  `## サマリー`,
  ``,
  `| 重要度 | 件数 |`,
  `|--------|------|`,
  `| 🔴 Critical | ${criticals.length} |`,
  `| 🟡 Warning  | ${warnings.length} |`,
  `| 🔵 Info     | ${infos.length} |`,
  `| **合計** | **${findings.length}** |`,
));

if (findings.length === 0) {
  sections.push(`✅ 診断対象の問題は検出されませんでした。\n`);
} else {
  const detailLines = [`## 詳細`, ``];

  for (const sev of ["critical", "warning", "info"]) {
    const group = findings.filter((f) => f.severity === sev);
    if (!group.length) continue;

    detailLines.push(`### ${EMOJI[sev]} ${LABEL[sev]} (${group.length} 件)`, ``);

    // チェックID でグループ化
    const byId = {};
    for (const f of group) (byId[f.id] = byId[f.id] || []).push(f);

    for (const [id, items] of Object.entries(byId)) {
      detailLines.push(`#### ${id}`, ``);
      for (const f of items) {
        detailLines.push(`- **ファイル**: \`${f.rel}\`${f.line ? ` (L${f.line})` : ""}`);
        detailLines.push(`  **リスク**: ${f.desc}`, ``);
      }
    }
  }
  sections.push(detailLines.join("\n"));

  // ClaudeCode 修正指示文
  const fixLines = [
    `## ClaudeCode 修正指示文`,
    ``,
    `> 以下を Claude Code にそのまま貼り付けて使えます。`,
    ``,
  ];

  if (criticals.length > 0) {
    fixLines.push("```text");
    fixLines.push("以下のセキュリティ問題を修正してください：\n");
    for (const f of criticals) {
      fixLines.push(`【${f.id}】${f.rel}${f.line ? ` (L${f.line})` : ""}`);
      fixLines.push(f.fix);
      fixLines.push("");
    }
    fixLines.push("```");
  } else {
    fixLines.push(`Critical な問題は検出されませんでした。`);
  }

  if (warnings.length > 0) {
    fixLines.push(``, `### Warning の修正候補`, ``);
    fixLines.push("```text");
    for (const f of warnings) {
      fixLines.push(`【${f.id}】${f.rel}${f.line ? ` (L${f.line})` : ""}`);
      fixLines.push(f.fix);
      fixLines.push("");
    }
    fixLines.push("```");
  }

  sections.push(fixLines.join("\n"));
}

sections.push(md(
  `---`,
  `*Next.js + Supabase Security Audit — 静的解析（正規表現ベース）*`,
  `*アローリスト適用: NX002 除外ルート ${ALLOWLIST_NX002.length} 件*`,
));

const reportContent = sections.join("\n\n") + "\n";
fs.writeFileSync(reportPath, reportContent, "utf8");

// ─── コンソール出力 ────────────────────────────────────────────────────────────

const line = "─".repeat(52);
console.log(line);
console.log(`🔴 Critical : ${criticals.length}`);
console.log(`🟡 Warning  : ${warnings.length}`);
console.log(`🔵 Info     : ${infos.length}`);
console.log(line);

if (criticals.length > 0) {
  console.log(`\n🔴 Critical 問題:`);
  for (const f of criticals) {
    console.log(`   [${f.id}] ${f.rel}${f.line ? `:${f.line}` : ""}`);
    console.log(`         ${f.desc}`);
  }
}

console.log(`\n📝 レポート: ${reportPath}`);
console.log(`⏱  解析時間: ${elapsed}秒\n`);

process.exit(criticals.length > 0 ? 1 : 0);
