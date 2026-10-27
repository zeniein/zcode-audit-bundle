#!/usr/bin/env node
/**
 * ZCode 审计记录器 (zcode-audit)
 * ---------------------------------------------------------------------------
 * 协议约定（见 ZCode 官方文档 Hooks / stdin 输入契约）：
 *   - ZCode 向本进程 stdin 写入「一行 JSON + 换行」
 *   - stdout 只允许输出协议 JSON；本脚本 **不写 stdout**，避免污染协议
 *   - 诊断信息一律走 stderr
 *   - 无论成功失败都以 exit 0 结束：审计不该拖垮主流程
 *
 * 落盘：
 *   <dataDir>/logs/YYYY-MM-DD.jsonl        审计事件流水（append-only）
 *   <dataDir>/transcripts/<session>.jsonl  会话 transcript 快照（覆盖式）
 *   <dataDir>/errors.log                   记录器自身的报错
 *
 * 数据目录优先级：
 *   1. 环境变量 ZCODE_AUDIT_DIR
 *   2. 插件根目录 audit.config.json 里的 dataDir
 *   3. ~/.zcode/audit
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = path.resolve(HERE, '..');
const DEBUG = process.env.ZCODE_AUDIT_DEBUG === '1';

/* ------------------------------------------------------------------ *
 * 工具函数
 * ------------------------------------------------------------------ */

function dbg(...a) {
  if (DEBUG) process.stderr.write('[zcode-audit] ' + a.join(' ') + '\n');
}

function warn(msg) {
  try {
    process.stderr.write('[zcode-audit] ' + msg + '\n');
  } catch { /* stderr 不可写时忽略 */ }
}

function sha256(s) {
  try {
    return createHash('sha256').update(s, 'utf8').digest('hex');
  } catch {
    return '';
  }
}

/** 取第一个有值的字段（兼容 camelCase / snake_case 双份字段） */
function pick(obj, ...keys) {
  if (!obj || typeof obj !== 'object') return undefined;
  for (const k of keys) {
    if (obj[k] !== undefined && obj[k] !== null) return obj[k];
  }
  return undefined;
}

function nowIso() {
  return new Date().toISOString();
}

function today() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/* ------------------------------------------------------------------ *
 * 配置
 * ------------------------------------------------------------------ */

const DEFAULT_CONFIG = {
  // 审计数据目录；相对路径按插件根目录解析
  dataDir: '~/.zcode/audit',
  // 是否记录用户输入内容（UserPromptSubmit.prompt）
  includePrompt: true,
  // 是否记录工具结果内容（PostToolUse.tool_response）
  includeResult: true,
  // 是否归档 transcript 快照
  includeTranscript: true,
  // 单个字符串值的最大保留长度，超出则头尾截断
  maxValueLength: 2000,
  // 单条审计记录的最大字节数，超出则丢弃大字段
  maxRecordBytes: 131072,
  // transcript 快照节流间隔（毫秒）
  transcriptThrottleMs: 5000,
};

function loadConfig() {
  const cfg = { ...DEFAULT_CONFIG };
  const cfgPath = path.join(PLUGIN_ROOT, 'audit.config.json');
  try {
    if (fs.existsSync(cfgPath)) {
      Object.assign(cfg, JSON.parse(fs.readFileSync(cfgPath, 'utf8')));
    }
  } catch (e) {
    warn('audit.config.json 解析失败，使用默认配置：' + e.message);
  }

  if (process.env.ZCODE_AUDIT_DIR) cfg.dataDir = process.env.ZCODE_AUDIT_DIR;
  if (process.env.ZCODE_AUDIT_INCLUDE_PROMPT === '0') cfg.includePrompt = false;
  if (process.env.ZCODE_AUDIT_INCLUDE_RESULT === '0') cfg.includeResult = false;
  if (process.env.ZCODE_AUDIT_INCLUDE_TRANSCRIPT === '0') cfg.includeTranscript = false;

  let dir = String(cfg.dataDir || DEFAULT_CONFIG.dataDir);
  if (dir.startsWith('~/')) dir = path.join(os.homedir(), dir.slice(2));
  else if (!path.isAbsolute(dir)) dir = path.resolve(PLUGIN_ROOT, dir);
  cfg.dataDir = dir;
  cfg.maxValueLength = Number(cfg.maxValueLength) || 2000;
  cfg.maxRecordBytes = Number(cfg.maxRecordBytes) || 131072;
  cfg.transcriptThrottleMs = Number(cfg.transcriptThrottleMs) || 5000;
  return cfg;
}

/* ------------------------------------------------------------------ *
 * 脱敏 + 截断
 * ------------------------------------------------------------------ */

// 键名命中即脱敏（键名去掉分隔符后做子串匹配）
const SENSITIVE_KEY_PATTERNS = [
  'password', 'passwd', 'passphrase', 'secret', 'token', 'apikey',
  'accesskey', 'credential', 'authorization', 'privatekey', 'cookie',
];

// 值层面疑似密钥的特征
const SENSITIVE_VALUE_PATTERNS = [
  /\bsk-[A-Za-z0-9_-]{16,}/g,                                    // OpenAI / 各类 sk- 前缀
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g,                               // GitHub token
  /\bAKIA[0-9A-Z]{16}\b/g,                                        // AWS AccessKeyId
  /\bAIza[0-9A-Za-z_-]{30,}/g,                                   // Google API key
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}/g, // JWT
];

function isSensitiveKey(key) {
  const norm = String(key).toLowerCase().replace(/[^a-z0-9]/g, '');
  return SENSITIVE_KEY_PATTERNS.some((p) => norm.includes(p));
}

function maskValue(text) {
  let out = String(text);
  for (const re of SENSITIVE_VALUE_PATTERNS) {
    out = out.replace(re, (m) => `[疑似密钥已脱敏:${sha256(m).slice(0, 8)}]`);
  }
  return out;
}

/**
 * 对任意值做安全化：脱敏 + 截断 + 限深限量。
 * 返回可直接 JSON 序列化的结构。
 */
function sanitize(value, opts = {}) {
  const maxLen = opts.maxLen ?? 2000;
  const depth = opts.depth ?? 0;
  const seen = opts.seen ?? new WeakSet();

  if (value === null || value === undefined) return value ?? null;

  const t = typeof value;
  if (t === 'number' || t === 'boolean') return value;

  if (t === 'string') {
    const masked = maskValue(value);
    if (masked.length <= maxLen) return masked;
    const head = masked.slice(0, Math.floor(maxLen * 0.6));
    const tail = masked.slice(-Math.floor(maxLen * 0.2));
    const total = masked.length;
    return `${head}\n…[已截断：原长 ${total} 字符，sha256=${sha256(masked).slice(0, 16)}]…\n${tail}`;
  }

  if (t === 'function' || t === 'symbol' || t === 'bigint') return String(value);

  if (depth >= 8) return '[深度超限]';

  if (Array.isArray(value)) {
    if (seen.has(value)) return '[循环引用]';
    seen.add(value);
    const LIMIT = 200;
    const out = value.slice(0, LIMIT).map((v) => sanitize(v, { ...opts, depth: depth + 1, seen }));
    if (value.length > LIMIT) out.push(`…[数组已截断：共 ${value.length} 项，仅保留前 ${LIMIT} 项]`);
    seen.delete(value);
    return out;
  }

  if (t === 'object') {
    if (seen.has(value)) return '[循环引用]';
    seen.add(value);
    const keys = Object.keys(value);
    const LIMIT = 200;
    const out = {};
    for (const k of keys.slice(0, LIMIT)) {
      if (isSensitiveKey(k)) {
        const raw = value[k];
        out[k] = raw === null || raw === undefined
          ? null
          : `[已脱敏:${typeof raw}] sha256=${sha256(safeStringify(raw)).slice(0, 16)}`;
        continue;
      }
      out[k] = sanitize(value[k], { ...opts, depth: depth + 1, seen });
    }
    if (keys.length > LIMIT) out['__truncated_keys__'] = `共 ${keys.length} 个键，仅保留前 ${LIMIT} 个`;
    seen.delete(value);
    return out;
  }

  return String(value);
}

function safeStringify(v) {
  try {
    return JSON.stringify(v) ?? String(v);
  } catch {
    return String(v);
  }
}

/* ------------------------------------------------------------------ *
 * 落盘
 * ------------------------------------------------------------------ */

function ensureDir(dir) {
  try {
    fs.mkdirSync(dir, { recursive: true });
  } catch (e) {
    warn('创建目录失败 ' + dir + '：' + e.message);
  }
}

function appendLine(file, line) {
  try {
    ensureDir(path.dirname(file));
    // O_APPEND + 单次 write，保证多进程并发写同一文件时不会串行交错
    const fd = fs.openSync(file, 'a');
    try {
      fs.writeSync(fd, line.endsWith('\n') ? line : line + '\n');
    } finally {
      fs.closeSync(fd);
    }
    return true;
  } catch (e) {
    warn('写入失败 ' + file + '：' + e.message);
    try {
      ensureDir(path.dirname(file));
      fs.appendFileSync(path.join(path.dirname(file), '..', 'errors.log'),
        `${nowIso()} 写入失败 ${file}: ${e.message}\n`);
    } catch { /* ignore */ }
    return false;
  }
}

function writeAuditRecord(cfg, record) {
  const line = safeStringify(record);
  if (line.length > cfg.maxRecordBytes) {
    // 记录过大：裁掉最重的字段后重试
    const slim = { ...record };
    delete slim.args;
    delete slim.result;
    slim.truncated = true;
    slim.note = '单条记录超过 maxRecordBytes，args/result 已丢弃（原始内容见 transcript 快照）';
    const slimLine = safeStringify(slim);
    if (slimLine.length > cfg.maxRecordBytes) {
      return appendLine(path.join(cfg.dataDir, 'logs', today() + '.jsonl'),
        safeStringify({ ts: record.ts, event: record.event, session_id: record.session_id, tool_name: record.tool_name, tool_use_id: record.tool_use_id, oversized: true }));
    }
    return appendLine(path.join(cfg.dataDir, 'logs', today() + '.jsonl'), slimLine);
  }
  return appendLine(path.join(cfg.dataDir, 'logs', today() + '.jsonl'), line);
}

/* ------------------------------------------------------------------ *
 * transcript 快照
 * ------------------------------------------------------------------ */

function snapshotTranscript(cfg, input) {
  if (!cfg.includeTranscript) return;
  const src = pick(input, 'transcript_path', 'transcriptPath');
  if (!src || typeof src !== 'string') return;

  let stat;
  try {
    stat = fs.statSync(src);
  } catch {
    return; // transcript 不可读，跳过（不影响主流程）
  }
  if (!stat.isFile() || stat.size === 0) return;

  const sessionId = String(pick(input, 'session_id', 'sessionId') || 'unknown');
  const dest = path.join(cfg.dataDir, 'transcripts', `${sessionId}.jsonl`);
  const statePath = path.join(cfg.dataDir, 'state', `${sessionId}.json`);

  // 节流：短时间内不重复快照
  let state = {};
  try {
    if (fs.existsSync(statePath)) state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
  } catch { state = {}; }

  const isStop = String(pick(input, 'hook_event_name', 'hookEventName')) === 'Stop';
  const since = Date.now() - Number(state.lastSnapshotTs || 0);
  const grew = stat.size > Number(state.lastSize || 0);
  if (!isStop && since < cfg.transcriptThrottleMs && !grew) return;

  try {
    const buf = fs.readFileSync(src);
    ensureDir(path.dirname(dest));
    const tmp = dest + '.tmp';
    fs.writeFileSync(tmp, buf);
    fs.renameSync(tmp, dest); // 原子替换，避免读到半截文件
    state.lastSnapshotTs = Date.now();
    state.lastSize = stat.size;
    ensureDir(path.dirname(statePath));
    fs.writeFileSync(statePath, JSON.stringify(state));
  } catch (e) {
    warn('transcript 快照失败：' + e.message);
  }
}

/* ------------------------------------------------------------------ *
 * 主流程
 * ------------------------------------------------------------------ */

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

function buildRecord(cfg, input) {
  const event = String(pick(input, 'hook_event_name', 'hookEventName') || 'Unknown');
  const sessionId = pick(input, 'session_id', 'sessionId') ?? null;
  const toolName = pick(input, 'tool_name', 'toolName') ?? null;
  const toolUseId = pick(input, 'tool_use_id', 'toolUseId') ?? null;

  const rec = {
    ts: nowIso(),
    event,
    session_id: sessionId,
    tool_name: toolName,
    tool_use_id: toolUseId,
    cwd: pick(input, 'cwd') ?? null,
    permission_mode: pick(input, 'permission_mode', 'permissionMode') ?? null,
    status: 'recorded',
  };

  const sopts = { maxLen: cfg.maxValueLength };

  switch (event) {
    case 'SessionStart': {
      rec.source = pick(input, 'source') ?? null;
      rec.agent_type = pick(input, 'agent_type', 'agentType') ?? null;
      rec.model = pick(input, 'model') ?? null;
      break;
    }
    case 'UserPromptSubmit': {
      const prompt = pick(input, 'prompt') ?? '';
      if (cfg.includePrompt) {
        rec.prompt = sanitize(prompt, sopts);
      } else {
        rec.prompt_sha256 = sha256(String(prompt));
        rec.prompt = '[按配置未记录内容]';
      }
      rec.prompt_length = String(prompt).length;
      break;
    }
    case 'PreToolUse':
    case 'PermissionRequest': {
      const inputArgs = pick(input, 'tool_input', 'toolInput') ?? {};
      rec.args = sanitize(inputArgs, sopts);
      rec.args_sha256 = sha256(safeStringify(inputArgs));
      rec.args_keys = inputArgs && typeof inputArgs === 'object' ? Object.keys(inputArgs) : [];
      const sugg = pick(input, 'permission_suggestions', 'permissionSuggestions');
      if (sugg) rec.permission_suggestions = sanitize(sugg, sopts);
      break;
    }
    case 'PostToolUse': {
      const inputArgs = pick(input, 'tool_input', 'toolInput') ?? {};
      rec.args = sanitize(inputArgs, sopts);
      rec.args_sha256 = sha256(safeStringify(inputArgs));
      const resp = pick(input, 'tool_response', 'toolResponse');
      if (cfg.includeResult) {
        rec.result = sanitize(resp, sopts);
      } else {
        rec.result_sha256 = sha256(safeStringify(resp));
        rec.result = '[按配置未记录结果内容]';
      }
      rec.result_ok = true;
      rec.status = 'success';
      break;
    }
    case 'PostToolUseFailure': {
      const inputArgs = pick(input, 'tool_input', 'toolInput') ?? {};
      rec.args = sanitize(inputArgs, sopts);
      const err = pick(input, 'error');
      rec.error = sanitize(err, sopts);
      rec.is_interrupt = Boolean(pick(input, 'is_interrupt', 'isInterrupt'));
      rec.status = 'failure';
      break;
    }
    case 'Stop': {
      rec.stop_hook_active = Boolean(pick(input, 'stop_hook_active', 'stopHookActive'));
      const last = pick(input, 'last_assistant_message', 'lastAssistantMessage');
      if (cfg.includeResult) rec.last_assistant_message = sanitize(last, sopts);
      rec.status = 'session_end';
      break;
    }
    default: {
      // 未知事件也留档，便于以后新增事件时不用改脚本
      rec.raw = sanitize(pick(input) ?? {}, sopts);
      break;
    }
  }

  return rec;
}

async function main() {
  const cfg = loadConfig();
  ensureDir(cfg.dataDir);

  const raw = await readStdin();
  // 协议规定是一次一行 JSON；这里逐行解析做容错，避免上游偶发多行时整批丢失
  const lines = raw.split('\n').map((l) => l.trim()).filter(Boolean);
  if (!lines.length) {
    appendLine(path.join(cfg.dataDir, 'errors.log'), `${nowIso()} stdin 为空，未记录任何事件\n`);
    return;
  }

  for (const line of lines) {
    let input;
    try {
      input = JSON.parse(line);
    } catch (e) {
      appendLine(path.join(cfg.dataDir, 'errors.log'),
        `${nowIso()} stdin 不是合法 JSON：${e.message}\n原始内容(前 500 字)：${line.slice(0, 500)}\n`);
      continue;
    }

    const rec = buildRecord(cfg, input);
    rec.host = os.hostname();
    rec.pid = process.pid;
    rec.plugin_version = '1.0.0';

    writeAuditRecord(cfg, rec);
    snapshotTranscript(cfg, input);
    dbg('recorded', rec.event, rec.tool_name || '');
  }
}

main()
  .catch((e) => {
    warn('记录器异常（不影响主流程）：' + (e && e.stack ? e.stack : e));
    try {
      const cfg = loadConfig();
      appendLine(path.join(cfg.dataDir, 'errors.log'), `${nowIso()} 记录器异常：${e && e.stack ? e.stack : e}\n`);
    } catch { /* ignore */ }
  })
  .finally(() => {
    // 审计脚本必须安静退出：不写 stdout、不用非 0 退出码
    process.exit(0);
  });
