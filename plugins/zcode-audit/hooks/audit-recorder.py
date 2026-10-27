#!/usr/bin/env python3
"""
ZCode 审计记录器 —— Python 3 兜底实现（与 audit-recorder.mjs 行为一致）

当 PATH 上没有 node 时，audit-recorder.sh 会调用本脚本。
协议：stdin 读一行 JSON，追加一行 JSON 到审计日志，stdout 留空，恒定 exit 0。
"""

import hashlib
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.path.dirname(HERE)
DEBUG = os.environ.get("ZCODE_AUDIT_DEBUG") == "1"

DEFAULT_CONFIG = {
    "dataDir": "~/.zcode/audit",
    "includePrompt": True,
    "includeResult": True,
    "includeTranscript": True,
    "maxValueLength": 2000,
    "maxRecordBytes": 131072,
    "transcriptThrottleMs": 5000,
}

SENSITIVE_KEY_PATTERNS = [
    "password", "passwd", "passphrase", "secret", "token", "apikey",
    "accesskey", "credential", "authorization", "privatekey", "cookie",
]

SENSITIVE_VALUE_PATTERNS = [
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), "OpenAI/sk- 前缀密钥"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), "GitHub token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS AccessKeyId"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"), "Google API key"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}"), "JWT"),
]


def dbg(*args):
    if DEBUG:
        sys.stderr.write("[zcode-audit] " + " ".join(str(a) for a in args) + "\n")


def warn(msg):
    try:
        sys.stderr.write("[zcode-audit] " + str(msg) + "\n")
    except Exception:
        pass


def sha256(text):
    try:
        return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
    except Exception:
        return ""


def pick(obj, *keys):
    if not isinstance(obj, dict):
        return None
    for k in keys:
        v = obj.get(k)
        if v is not None:
            return v
    return None


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        "%03dZ" % (datetime.now(timezone.utc).microsecond // 1000)


def today():
    return datetime.now().strftime("%Y-%m-%d")


def safe_stringify(v):
    # 与 Node 的 JSON.stringify 对齐：紧凑分隔符、不转义非 ASCII
    # 这样两边算出的 sha256 指纹完全一致，可以交叉校验同一份审计
    try:
        return json.dumps(v, ensure_ascii=False, default=str, separators=(",", ":"))
    except Exception:
        return str(v)


def js_type_name(v):
    """把 Python 类型名映射成 JS typeof，方便两套实现产出同样的审计文本"""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int) or isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return "unknown"


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    cfg_path = os.path.join(PLUGIN_ROOT, "audit.config.json")
    try:
        if os.path.exists(cfg_path):
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
    except Exception as e:
        warn("audit.config.json 解析失败，使用默认配置：" + str(e))

    if os.environ.get("ZCODE_AUDIT_DIR"):
        cfg["dataDir"] = os.environ["ZCODE_AUDIT_DIR"]
    if os.environ.get("ZCODE_AUDIT_INCLUDE_PROMPT") == "0":
        cfg["includePrompt"] = False
    if os.environ.get("ZCODE_AUDIT_INCLUDE_RESULT") == "0":
        cfg["includeResult"] = False
    if os.environ.get("ZCODE_AUDIT_INCLUDE_TRANSCRIPT") == "0":
        cfg["includeTranscript"] = False

    d = str(cfg.get("dataDir") or DEFAULT_CONFIG["dataDir"])
    if d.startswith("~/"):
        d = os.path.join(os.path.expanduser("~"), d[2:])
    elif not os.path.isabs(d):
        d = os.path.abspath(os.path.join(PLUGIN_ROOT, d))
    cfg["dataDir"] = d
    cfg["maxValueLength"] = int(cfg.get("maxValueLength") or 2000)
    cfg["maxRecordBytes"] = int(cfg.get("maxRecordBytes") or 131072)
    cfg["transcriptThrottleMs"] = int(cfg.get("transcriptThrottleMs") or 5000)
    return cfg


def is_sensitive_key(key):
    norm = re.sub(r"[^a-z0-9]", "", str(key).lower())
    return any(p in norm for p in SENSITIVE_KEY_PATTERNS)


def mask_value(text):
    out = str(text)
    for rx, _label in SENSITIVE_VALUE_PATTERNS:
        out = rx.sub(lambda m: "[疑似密钥已脱敏:%s]" % sha256(m.group(0))[:8], out)
    return out


def sanitize(value, opts, depth=0, seen=None):
    if seen is None:
        seen = set()
    max_len = opts["maxLen"]

    if value is None:
        return None
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        masked = mask_value(value)
        if len(masked) <= max_len:
            return masked
        head = masked[:int(max_len * 0.6)]
        tail = masked[-int(max_len * 0.2):]
        return "%s\n…[已截断：原长 %d 字符，sha256=%s]…\n%s" % (
            head, len(masked), sha256(masked)[:16], tail)
    if isinstance(value, (bytes, bytearray)):
        return "[二进制数据 %d 字节]" % len(value)

    if depth >= 8:
        return "[深度超限]"

    if isinstance(value, list):
        if id(value) in seen:
            return "[循环引用]"
        seen.add(id(value))
        limit = 200
        out = [sanitize(v, opts, depth + 1, seen) for v in value[:limit]]
        if len(value) > limit:
            out.append("…[数组已截断：共 %d 项，仅保留前 %d 项]" % (len(value), limit))
        seen.discard(id(value))
        return out

    if isinstance(value, dict):
        if id(value) in seen:
            return "[循环引用]"
        seen.add(id(value))
        limit = 200
        out = {}
        for k in list(value.keys())[:limit]:
            if is_sensitive_key(k):
                raw = value[k]
                out[k] = "[已脱敏:%s] sha256=%s" % (
                    js_type_name(raw), sha256(safe_stringify(raw))[:16])
                continue
            out[k] = sanitize(value[k], opts, depth + 1, seen)
        if len(value) > limit:
            out["__truncated_keys__"] = "共 %d 个键，仅保留前 %d 个" % (len(value), limit)
        seen.discard(id(value))
        return out

    return str(value)


def ensure_dir(d):
    try:
        os.makedirs(d, exist_ok=True)
    except Exception as e:
        warn("创建目录失败 %s：%s" % (d, e))


def append_line(file, line):
    try:
        ensure_dir(os.path.dirname(file))
        # O_APPEND + 单次 os.write，保证并发写不交错
        fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            os.write(fd, (line.rstrip("\n") + "\n").encode("utf-8", "replace"))
        finally:
            os.close(fd)
        return True
    except Exception as e:
        warn("写入失败 %s：%s" % (file, e))
        try:
            err_dir = os.path.dirname(os.path.dirname(file))
            os.makedirs(err_dir, exist_ok=True)
            with open(os.path.join(err_dir, "errors.log"), "a", encoding="utf-8") as f:
                f.write("%s 写入失败 %s: %s\n" % (now_iso(), file, e))
        except Exception:
            pass
        return False


def write_audit_record(cfg, rec):
    line = safe_stringify(rec)
    if len(line) > cfg["maxRecordBytes"]:
        slim = {k: v for k, v in rec.items() if k not in ("args", "result")}
        slim["truncated"] = True
        slim["note"] = "单条记录超过 maxRecordBytes，args/result 已丢弃（原始内容见 transcript 快照）"
        slim_line = safe_stringify(slim)
        if len(slim_line) > cfg["maxRecordBytes"]:
            return append_line(
                os.path.join(cfg["dataDir"], "logs", today() + ".jsonl"),
                safe_stringify({
                    "ts": rec.get("ts"), "event": rec.get("event"),
                    "session_id": rec.get("session_id"), "tool_name": rec.get("tool_name"),
                    "tool_use_id": rec.get("tool_use_id"), "oversized": True,
                }))
        return append_line(os.path.join(cfg["dataDir"], "logs", today() + ".jsonl"), slim_line)
    return append_line(os.path.join(cfg["dataDir"], "logs", today() + ".jsonl"), line)


def snapshot_transcript(cfg, inp):
    if not cfg["includeTranscript"]:
        return
    src = pick(inp, "transcript_path", "transcriptPath")
    if not isinstance(src, str) or not src:
        return
    try:
        st = os.stat(src)
    except Exception:
        return
    if not os.path.isfile(src) or st.st_size == 0:
        return

    session_id = str(pick(inp, "session_id", "sessionId") or "unknown")
    dest = os.path.join(cfg["dataDir"], "transcripts", session_id + ".jsonl")
    state_path = os.path.join(cfg["dataDir"], "state", session_id + ".json")

    state = {}
    try:
        if os.path.exists(state_path):
            with open(state_path, "r", encoding="utf-8") as f:
                state = json.load(f)
    except Exception:
        state = {}

    is_stop = str(pick(inp, "hook_event_name", "hookEventName")) == "Stop"
    since = time.time() * 1000 - float(state.get("lastSnapshotTs") or 0)
    grew = st.st_size > int(state.get("lastSize") or 0)
    if (not is_stop) and since < cfg["transcriptThrottleMs"] and not grew:
        return

    try:
        with open(src, "rb") as f:
            buf = f.read()
        ensure_dir(os.path.dirname(dest))
        tmp = dest + ".tmp"
        with open(tmp, "wb") as f:
            f.write(buf)
        os.replace(tmp, dest)
        state["lastSnapshotTs"] = time.time() * 1000
        state["lastSize"] = st.st_size
        ensure_dir(os.path.dirname(state_path))
        with open(state_path, "w", encoding="utf-8") as f:
            json.dump(state, f)
    except Exception as e:
        warn("transcript 快照失败：" + str(e))


def build_record(cfg, inp):
    event = str(pick(inp, "hook_event_name", "hookEventName") or "Unknown")
    rec = {
        "ts": now_iso(),
        "event": event,
        "session_id": pick(inp, "session_id", "sessionId"),
        "tool_name": pick(inp, "tool_name", "toolName"),
        "tool_use_id": pick(inp, "tool_use_id", "toolUseId"),
        "cwd": pick(inp, "cwd"),
        "permission_mode": pick(inp, "permission_mode", "permissionMode"),
        "status": "recorded",
    }
    sopts = {"maxLen": cfg["maxValueLength"]}

    if event == "SessionStart":
        rec["source"] = pick(inp, "source")
        rec["agent_type"] = pick(inp, "agent_type", "agentType")
        rec["model"] = pick(inp, "model")
    elif event == "UserPromptSubmit":
        prompt = pick(inp, "prompt") or ""
        if cfg["includePrompt"]:
            rec["prompt"] = sanitize(prompt, sopts)
        else:
            rec["prompt_sha256"] = sha256(str(prompt))
            rec["prompt"] = "[按配置未记录内容]"
        rec["prompt_length"] = len(str(prompt))
    elif event in ("PreToolUse", "PermissionRequest"):
        args = pick(inp, "tool_input", "toolInput") or {}
        rec["args"] = sanitize(args, sopts)
        rec["args_sha256"] = sha256(safe_stringify(args))
        rec["args_keys"] = list(args.keys()) if isinstance(args, dict) else []
        sugg = pick(inp, "permission_suggestions", "permissionSuggestions")
        if sugg is not None:
            rec["permission_suggestions"] = sanitize(sugg, sopts)
    elif event == "PostToolUse":
        args = pick(inp, "tool_input", "toolInput") or {}
        rec["args"] = sanitize(args, sopts)
        rec["args_sha256"] = sha256(safe_stringify(args))
        resp = pick(inp, "tool_response", "toolResponse")
        if cfg["includeResult"]:
            rec["result"] = sanitize(resp, sopts)
        else:
            rec["result_sha256"] = sha256(safe_stringify(resp))
            rec["result"] = "[按配置未记录结果内容]"
        rec["result_ok"] = True
        rec["status"] = "success"
    elif event == "PostToolUseFailure":
        args = pick(inp, "tool_input", "toolInput") or {}
        rec["args"] = sanitize(args, sopts)
        rec["error"] = sanitize(pick(inp, "error"), sopts)
        rec["is_interrupt"] = bool(pick(inp, "is_interrupt", "isInterrupt"))
        rec["status"] = "failure"
    elif event == "Stop":
        rec["stop_hook_active"] = bool(pick(inp, "stop_hook_active", "stopHookActive"))
        if cfg["includeResult"]:
            rec["last_assistant_message"] = sanitize(
                pick(inp, "last_assistant_message", "lastAssistantMessage"), sopts)
        rec["status"] = "session_end"
    else:
        rec["raw"] = sanitize(inp, sopts)

    return rec


def main():
    cfg = load_config()
    ensure_dir(cfg["dataDir"])

    raw = sys.stdin.read()
    # 协议规定一次一行 JSON；这里逐行解析做容错，避免上游偶发多行时整批丢失
    lines = [l.strip() for l in raw.split("\n") if l.strip()]
    if not lines:
        append_line(os.path.join(cfg["dataDir"], "errors.log"),
                    "%s stdin 为空，未记录任何事件\n" % now_iso())
        return

    for line in lines:
        try:
            inp = json.loads(line)
        except Exception as e:
            append_line(os.path.join(cfg["dataDir"], "errors.log"),
                        "%s stdin 不是合法 JSON：%s\n原始内容(前 500 字)：%s\n"
                        % (now_iso(), e, line[:500]))
            continue

        rec = build_record(cfg, inp)
        rec["host"] = socket.gethostname()
        rec["pid"] = os.getpid()
        rec["plugin_version"] = "1.0.0"

        write_audit_record(cfg, rec)
        snapshot_transcript(cfg, inp)
        dbg("recorded", rec.get("event"), rec.get("tool_name") or "")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        warn("记录器异常（不影响主流程）：" + repr(e))
        try:
            cfg = load_config()
            append_line(os.path.join(cfg["dataDir"], "errors.log"),
                        "%s 记录器异常：%r\n" % (now_iso(), e))
        except Exception:
            pass
    finally:
        sys.exit(0)
