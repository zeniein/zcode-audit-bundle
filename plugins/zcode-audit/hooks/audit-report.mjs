#!/usr/bin/env node
/**
 * ZCode 审计报告生成器 (zcode-audit)
 * ---------------------------------------------------------------------------
 * 读审计日志（<dataDir>/logs/YYYY-MM-DD.jsonl），输出可读报告。
 *
 * 用法：
 *   node audit-report.mjs                      # 今天全部会话，文本报告
 *   node audit-report.mjs --date 2026-10-27    # 指定日期
 *   node audit-report.mjs --session <id>       # 指定会话
 *   node audit-report.mjs --tool Bash          # 只看某个工具
 *   node audit-report.mjs --json               # 输出 JSON
 *   node audit-report.mjs --html out.html      # 输出单文件 HTML
 *   node audit-report.mjs --dir ~/.zcode/audit # 指定数据目录
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = path.resolve(HERE, '..');

/* ------------------------------ 参数解析 ------------------------------ */

function parseArgs(argv) {
  const out = { dir: null, date: null, session: null, tool: null, json: false, html: null, limit: 0 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dir') out.dir = argv[++i];
    else if (a === '--date') out.date = argv[++i];
    else if (a === '--session') out.session = argv[++i];
    else if (a === '--tool') out.tool = argv[++i];
    else if (a === '--json') out.json = true;
    else if (a === '--html') out.html = argv[++i];
    else if (a === '--limit') out.limit = Number(argv[++i]) || 0;
    else if (a === '--help' || a === '-h') { printHelp(); process.exit(0); }
  }
  return out;
}

function printHelp() {
  process.stdout.write(`ZCode 审计报告

  --dir <目录>      审计数据目录（默认 ~/.zcode/audit）
  --date <YYYY-MM-DD> 只看某天
  --session <id>    只看某次会话
  --tool <名称>     只看某类工具（如 Bash / Write）
  --json            输出 JSON
  --html <文件>     输出单文件 HTML 报告
  --limit <n>       最多输出 n 条时间线条目
`);
}

/* ------------------------------ 定位数据 ------------------------------ */

function resolveDataDir(explicit) {
  if (explicit) return expand(explicit);
  if (process.env.ZCODE_AUDIT_DIR) return expand(process.env.ZCODE_AUDIT_DIR);
  const cfgPath = path.join(PLUGIN_ROOT, 'audit.config.json');
  try {
    if (fs.existsSync(cfgPath)) {
      const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
      if (cfg.dataDir) return expand(cfg.dataDir, PLUGIN_ROOT);
    }
  } catch { /* ignore */ }
  return path.join(os.homedir(), '.zcode', 'audit');
}

function expand(p, base) {
  let dir = String(p);
  if (dir.startsWith('~/')) dir = path.join(os.homedir(), dir.slice(2));
  else if (!path.isAbsolute(dir)) dir = path.resolve(base || PLUGIN_ROOT, dir);
  return dir;
}

function loadRecords(dataDir, opts) {
  const logDir = path.join(dataDir, 'logs');
  if (!fs.existsSync(logDir)) return [];
  const files = fs.readdirSync(logDir).filter((f) => f.endsWith('.jsonl')).sort();
  const recs = [];
  for (const f of files) {
    if (opts.date && f !== `${opts.date}.jsonl`) continue;
    let content;
    try { content = fs.readFileSync(path.join(logDir, f), 'utf8'); } catch { continue; }
    for (const line of content.split('\n')) {
      if (!line.trim()) continue;
      try { recs.push(JSON.parse(line)); } catch { /* 跳过坏行 */ }
    }
  }
  return recs;
}

/* ------------------------------ 摘要工具 ------------------------------ */

const INTERESTING_KEYS = [
  'command', 'file_path', 'path', 'url', 'query', 'pattern', 'description',
  'prompt', 'content', 'old_string', 'new_string', 'notebook_path', 'subagent_type',
];

function summarizeArgs(args) {
  if (!args || typeof args !== 'object') return '';
  const parts = [];
  for (const k of INTERESTING_KEYS) {
    if (!(k in args)) continue;
    const v = args[k];
    if (v === undefined || v === null) continue;
    let s;
    if (typeof v === 'string') s = v;
    else s = JSON.stringify(v);
    s = s.replace(/\s+/g, ' ').trim();
    const cap = k === 'content' ? 80 : 160;
    if (s.length > cap) s = s.slice(0, cap - 1) + '…';
    parts.push(`${k}=${s}`);
    if (parts.length >= 3) break;
  }
  if (!parts.length) {
    const keys = Object.keys(args);
    return keys.length ? `参数键: ${keys.slice(0, 8).join(', ')}` : '(无参数)';
  }
  return parts.join('  ');
}

function countRedacted(obj, acc = { n: 0, keys: new Set() }) {
  if (!obj || typeof obj !== 'object') return acc;
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string' && v.startsWith('[已脱敏')) { acc.n++; acc.keys.add(k); }
    else if (v && typeof v === 'object') countRedacted(v, acc);
  }
  return acc;
}

function fmtTime(ts) {
  if (!ts) return '--';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${String(d.getMilliseconds()).padStart(3, '0')}`;
}

/* ------------------------------ 报告组装 ------------------------------ */

function buildReport(recs, opts) {
  const bySession = new Map();
  for (const r of recs) {
    const sid = r.session_id || 'unknown';
    if (!bySession.has(sid)) bySession.set(sid, []);
    bySession.get(sid).push(r);
  }

  const sessions = [];
  for (const [sid, list] of bySession) {
    list.sort((a, b) => String(a.ts).localeCompare(String(b.ts)));
    const toolCalls = list.filter((r) => r.event === 'PreToolUse');
    const successes = list.filter((r) => r.event === 'PostToolUse');
    const failures = list.filter((r) => r.event === 'PostToolUseFailure');
    const prompts = list.filter((r) => r.event === 'UserPromptSubmit');
    const starts = list.filter((r) => r.event === 'SessionStart');
    const stops = list.filter((r) => r.event === 'Stop');

    const byTool = {};
    for (const c of toolCalls) {
      const t = c.tool_name || 'unknown';
      byTool[t] = (byTool[t] || 0) + 1;
    }

    const shellCommands = [];
    const fileWrites = [];
    for (const c of toolCalls) {
      const t = (c.tool_name || '').toLowerCase();
      const a = c.args || {};
      if (/^(bash|shell|run|terminal|exec)$/.test(t) && a.command) {
        shellCommands.push({ ts: c.ts, command: String(a.command) });
      }
      if (/^(write|edit|multiedit|notebookedit)$/.test(t)) {
        const f = a.file_path || a.notebook_path || a.path;
        if (f) fileWrites.push({ ts: c.ts, tool: c.tool_name, file: String(f) });
      }
    }

    const redacted = { n: 0, keys: new Set() };
    for (const r of list) {
      countRedacted(r.args, redacted);
      countRedacted(r.result, redacted);
      countRedacted(r.prompt, redacted);
    }

    sessions.push({
      session_id: sid,
      cwd: starts[0]?.cwd || list[0]?.cwd || null,
      source: starts[0]?.source || null,
      model: starts[0]?.model || null,
      permission_mode: list[0]?.permission_mode || null,
      started_at: list[0]?.ts || null,
      ended_at: stops.length ? stops[stops.length - 1].ts : null,
      user_prompts: prompts.map((p) => ({ ts: p.ts, text: p.prompt, length: p.prompt_length })),
      tool_call_count: toolCalls.length,
      success_count: successes.length,
      failure_count: failures.length,
      by_tool: byTool,
      shell_commands: shellCommands,
      file_writes: fileWrites,
      failures: failures.map((f) => ({ ts: f.ts, tool: f.tool_name, error: f.error, is_interrupt: f.is_interrupt })),
      redacted_fields: redacted.n,
      redacted_keys: [...redacted.keys],
      timeline: list,
    });
  }

  return {
    generated_at: new Date().toISOString(),
    data_dir: opts.dataDir,
    filter: { date: opts.date || null, session: opts.session || null, tool: opts.tool || null },
    total_records: recs.length,
    session_count: sessions.length,
    sessions,
  };
}

/* ------------------------------ 文本输出 ------------------------------ */

function renderText(rep) {
  const L = [];
  L.push('══════════════════════════════════════════════════════════════');
  L.push('  ZCode 会话审计报告');
  L.push(`  生成时间：${rep.generated_at}`);
  L.push(`  数据目录：${rep.data_dir}`);
  L.push(`  记录总数：${rep.total_records}    会话数：${rep.session_count}`);
  L.push('══════════════════════════════════════════════════════════════');

  for (const s of rep.sessions) {
    L.push('');
    L.push('┌─ 会话 ' + s.session_id);
    L.push('│  工作目录 : ' + (s.cwd || '(未知)'));
    L.push('│  启动来源 : ' + (s.source || '(未知)') + '    模型: ' + (s.model || '(未知)'));
    L.push('│  权限模式 : ' + (s.permission_mode || '(未知)'));
    L.push('│  时间跨度 : ' + (s.started_at || '-') + '  →  ' + (s.ended_at || '(未结束)'));
    L.push('│  工具调用 : ' + s.tool_call_count + ' 次   成功 ' + s.success_count + '   失败 ' + s.failure_count);
    L.push('│  脱敏字段 : ' + s.redacted_fields + (s.redacted_keys.length ? ' (' + s.redacted_keys.join(', ') + ')' : ''));
    if (Object.keys(s.by_tool).length) {
      L.push('│  工具分布 : ' + Object.entries(s.by_tool).map(([k, v]) => `${k}×${v}`).join('  '));
    }

    if (s.user_prompts.length) {
      L.push('│');
      L.push('│  ── 用户输入 ──');
      for (const p of s.user_prompts) {
        const one = String(p.text || '').replace(/\s+/g, ' ').slice(0, 200);
        L.push('│   ' + fmtTime(p.ts) + '  ' + one + (p.length > 200 ? '…' : ''));
      }
    }

    L.push('│');
    L.push('│  ── 工具调用时间线 ──');
    for (const r of s.timeline) {
      if (r.event === 'SessionStart' || r.event === 'Stop') {
        L.push('│   ' + fmtTime(r.ts) + '  ▸ ' + r.event);
        continue;
      }
      if (r.event === 'UserPromptSubmit') continue;
      const mark = r.status === 'failure' ? '✗' : r.status === 'success' ? '✓' : '→';
      const detail = summarizeArgs(r.args);
      let line = '│   ' + fmtTime(r.ts) + '  ' + mark + ' ' + (r.tool_name || '?') + (detail ? '  ' + detail : '');
      if (r.event === 'PostToolUseFailure' && r.error) {
        const e = String(r.error).replace(/\s+/g, ' ').slice(0, 120);
        line += '\n│        ↳ 错误: ' + e;
      }
      L.push(line);
    }

    if (s.shell_commands.length) {
      L.push('│');
      L.push('│  ── 执行的 Shell 命令 ──');
      for (const c of s.shell_commands) {
        L.push('│   ' + fmtTime(c.ts) + '  $ ' + c.command.replace(/\s+/g, ' ').slice(0, 200));
      }
    }

    if (s.file_writes.length) {
      L.push('│');
      L.push('│  ── 写入 / 修改的文件 ──');
      for (const f of s.file_writes) {
        L.push('│   ' + fmtTime(f.ts) + '  ' + f.tool + '  ' + f.file);
      }
    }

    if (s.failures.length) {
      L.push('│');
      L.push('│  ── 失败清单 ──');
      for (const f of s.failures) {
        L.push('│   ' + fmtTime(f.ts) + '  ' + (f.tool || '?') + ': ' + String(f.error || '').replace(/\s+/g, ' ').slice(0, 160));
      }
    }
    L.push('└' + '─'.repeat(68));
  }
  return L.join('\n');
}

/* ------------------------------ HTML 输出 ------------------------------ */

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function renderHtml(rep) {
  const s = rep.sessions[0] && rep.sessions.length === 1 ? rep.sessions[0] : null;
  let body = '';

  for (const sess of rep.sessions) {
    const rows = sess.timeline.map((r) => {
      const mark = r.status === 'failure' ? '<span class="bad">✗</span>' : r.status === 'success' ? '<span class="ok">✓</span>' : '<span class="dim">→</span>';
      const detail = summarizeArgs(r.args);
      return `<tr><td class="t">${esc(fmtTime(r.ts))}</td><td class="m">${mark}</td><td class="n">${esc(r.tool_name || r.event)}</td><td class="d">${esc(detail)}</td></tr>`;
    }).join('');

    const cmds = sess.shell_commands.map((c) => `<li><code>${esc(c.command)}</code></li>`).join('');
    const files = sess.file_writes.map((f) => `<li><code>${esc(f.file)}</code> <span class="dim">${esc(f.tool)}</span></li>`).join('');
    const fails = sess.failures.map((f) => `<li><code>${esc(f.tool || '?')}</code> — ${esc(String(f.error || '').slice(0, 200))}</li>`).join('');

    body += `<section class="card">
  <h2>会话 <code>${esc(sess.session_id)}</code></h2>
  <div class="meta">
    <span><b>工作目录</b> ${esc(sess.cwd || '-')}</span>
    <span><b>来源</b> ${esc(sess.source || '-')}</span>
    <span><b>模型</b> ${esc(sess.model || '-')}</span>
    <span><b>工具调用</b> ${sess.tool_call_count}（成功 ${sess.success_count} / 失败 ${sess.failure_count}）</span>
    <span><b>脱敏字段</b> ${sess.redacted_fields}</span>
  </div>
  ${cmds ? `<h3>执行的 Shell 命令</h3><ul>${cmds}</ul>` : ''}
  ${files ? `<h3>写入 / 修改的文件</h3><ul>${files}</ul>` : ''}
  <h3>时间线</h3>
  <table><thead><tr><th>时间</th><th></th><th>工具</th><th>参数摘要</th></tr></thead><tbody>${rows}</tbody></table>
  ${fails ? `<h3>失败清单</h3><ul>${fails}</ul>` : ''}
</section>`;
  }

  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ZCode 审计报告</title>
<style>
:root{--bg:#fbfbfa;--card:#fff;--line:#e6e4df;--txt:#23201c;--dim:#8a857d;--ok:#1a7f4b;--bad:#c0392b;--code:#f5f3ee}
*{box-sizing:border-box}
body{margin:0;padding:32px;background:var(--bg);color:var(--txt);font:15px/1.7 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif}
.wrap{max-width:1100px;margin:0 auto}
h1{font-size:24px;margin:0 0 4px}
.sub{color:var(--dim);font-size:13px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px 24px;margin-bottom:20px}
h2{font-size:17px;margin:0 0 14px;word-break:break-all}
h3{font-size:14px;margin:20px 0 8px;color:#5d574e}
.meta{display:flex;flex-wrap:wrap;gap:8px 20px;font-size:13px;color:#4a453e}
.meta b{font-weight:600;color:var(--dim);margin-right:4px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:500;font-size:12px}
td.t{white-space:nowrap;color:var(--dim);font-variant-numeric:tabular-nums}
td.n{font-weight:600;white-space:nowrap}
td.d{color:#4a453e;word-break:break-all}
code{background:var(--code);padding:1px 6px;border-radius:5px;font-size:12.5px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
ul{margin:6px 0;padding-left:20px;font-size:13px}
.ok{color:var(--ok)}.bad{color:var(--bad)}.dim{color:var(--dim)}
</style></head><body><div class="wrap">
<h1>ZCode 审计报告</h1>
<div class="sub">生成于 ${esc(rep.generated_at)} · 数据目录 ${esc(rep.data_dir)} · 记录 ${rep.total_records} 条 / 会话 ${rep.session_count} 个</div>
${body || '<div class="card">没有找到审计记录。</div>'}
</div></body></html>`;
}

/* ------------------------------ main ------------------------------ */

function main() {
  const opts = parseArgs(process.argv.slice(2));
  opts.dataDir = resolveDataDir(opts.dir);

  let recs = loadRecords(opts.dataDir, opts);
  if (opts.session) recs = recs.filter((r) => r.session_id === opts.session);
  if (opts.tool) recs = recs.filter((r) => String(r.tool_name || '').toLowerCase() === opts.tool.toLowerCase());

  const rep = buildReport(recs, opts);

  if (opts.html) {
    fs.writeFileSync(opts.html, renderHtml(rep), 'utf8');
    process.stdout.write('HTML 报告已写入：' + opts.html + '\n');
    return;
  }
  if (opts.json) {
    const clone = JSON.parse(JSON.stringify(rep));
    for (const s of clone.sessions) delete s.timeline;
    process.stdout.write(JSON.stringify(clone, null, 2) + '\n');
    return;
  }
  process.stdout.write(renderText(rep) + '\n');
}

main();
