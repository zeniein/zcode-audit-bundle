# zcode-audit —— ZCode 会话审计插件

记录 ZCode 会话里**每一次工具调用**（工具名、参数、结果、失败原因）和**用户输入**，
落盘成 append-only 的 JSONL 审计日志，可随时回溯"这次到底执行了什么"。

## 记录什么

| 事件 | 记录内容 |
|------|----------|
| `SessionStart` | 会话 ID、工作目录、启动来源（startup/clear/compact）、模型 |
| `UserPromptSubmit` | 用户输入原文（可关闭）、长度 |
| `PreToolUse` | **工具名 + 完整参数**（`tool_input`）、参数键列表、参数 sha256 指纹 |
| `PostToolUse` | 工具名 + 参数 + **执行结果**（`tool_response`） |
| `PostToolUseFailure` | 工具名 + 参数 + **错误信息** + 是否被中断 |
| `Stop` | 会话结束标记、最后一条助手消息 |

> `PreToolUse` 是审计的锚点：它是唯一能在工具**执行前**拿到工具名和完整参数的事件。
> `PostToolUse` / `PostToolUseFailure` 靠 `tool_use_id` 与它配对，合成一条完整的"调用 + 结果"。

## 目录结构

```
zcode-audit/
├── .zcode-plugin/
│   └── plugin.json          插件清单（hooks/hooks.json 会被自动发现，这里不要重复声明）
├── hooks/
│   ├── hooks.json           七个事件的挂载配置
│   ├── audit-recorder.sh    启动器：有 node 用 node，没有就用 python3
│   ├── audit-recorder.mjs   记录器（Node 实现，零依赖）
│   ├── audit-recorder.py    记录器（Python 3 兜底实现，行为与 Node 版一致）
│   └── audit-report.mjs     汇总报告生成器
├── audit.config.json        数据目录、脱敏、截断等配置
└── README.md
```

## 安装

**方式 A：本地插件市场（推荐，适合团队共享）**

1. 把整个 `zcode-audit` 目录放到团队仓库的 `plugins/` 下
2. 仓库根目录放一份 `marketplace.json`（本包已提供示例）
3. ZCode → 设置 → 插件 → 右上角「创建 → 添加插件市场」→ 选本地目录
4. 在「个人」分段找到 zcode-audit → 安装 → 启用
5. **新建一个 session**（配置在 session 启动时快照）

**方式 B：用户级配置（只给自己用）**

把 `hooks` 段合并进 `~/.zcode/cli/config.json`，并确保 `hooks.enabled: true`。
完整示例见 `examples/user-config.json`。

> ⚠️ 项目级配置（`<workspace>/.zcode/config.json` / `<workspace>/zcode.json`）里的 `hooks`
> **当前版本不会执行**，日志里记为 `config_project_hooks_ignored`。要团队共享请走插件。

## 配置

编辑 `audit.config.json`：

```json
{
  "dataDir": "~/.zcode/audit",
  "includePrompt": true,
  "includeResult": true,
  "includeTranscript": true,
  "maxValueLength": 2000,
  "maxRecordBytes": 131072,
  "transcriptThrottleMs": 5000
}
```

| 字段 | 说明 |
|------|------|
| `dataDir` | 审计数据目录。默认 `~/.zcode/audit`（用户级、稳定、插件升级不丢） |
| `includePrompt` | 是否记录用户输入原文。关掉则只存 `prompt_sha256` |
| `includeResult` | 是否记录工具结果内容。关掉则只存 `result_sha256` |
| `includeTranscript` | 是否归档会话 transcript 快照 |
| `maxValueLength` | 单个字符串值的保留上限，超出头尾截断并附 sha256 |
| `maxRecordBytes` | 单条记录上限，超出丢弃 args/result 保住元信息 |
| `transcriptThrottleMs` | transcript 快照节流间隔 |

也可以用环境变量临时覆盖（优先级高于配置文件）：
`ZCODE_AUDIT_DIR`、`ZCODE_AUDIT_INCLUDE_PROMPT=0`、`ZCODE_AUDIT_INCLUDE_RESULT=0`、
`ZCODE_AUDIT_INCLUDE_TRANSCRIPT=0`、`ZCODE_AUDIT_DEBUG=1`。

## 落盘结构

```
~/.zcode/audit/
├── logs/
│   └── 2026-10-27.jsonl        审计事件流水（按天切分，append-only）
├── transcripts/
│   └── <session_id>.jsonl      会话 transcript 快照（覆盖式，原子替换）
├── state/
│   └── <session_id>.json       快照节流状态
└── errors.log                  记录器自身报错
```

## 查审计

```bash
# 文本报告（全部会话）
node hooks/audit-report.mjs

# 只看某次会话
node hooks/audit-report.mjs --session <session_id>

# 只看某天 / 某个工具
node hooks/audit-report.mjs --date 2026-10-27
node hooks/audit-report.mjs --tool Bash

# 单文件 HTML 报告
node hooks/audit-report.mjs --html ~/Desktop/审计报告.html

# 机器可读
node hooks/audit-report.mjs --json
```

## 隐私与安全

- **键名脱敏**：`password` / `secret` / `token` / `api_key` / `authorization` / `cookie` /
  `privatekey` / `credential` 等键的值一律替换为 `[已脱敏:<类型>] sha256=<指纹>`，
  保留指纹是为了能证明"确实有这个东西"而不泄露内容。
- **值层面脱敏**：`sk-…`、`ghp_…`、`AKIA…`、`AIza…`、JWT 这类特征串会被就地打码。
- **截断带指纹**：超长内容截断后附 `sha256`，可校验原文未被篡改。
- **日志默认只写本地**，不上传任何数据。
- 审计日志里仍然包含命令和文件路径等敏感业务信息，**请按公司数据分级管理**，
  接入 SIEM 前先确认合规要求。

## 设计约定

- 记录器**永远 exit 0**，任何异常都不会影响主流程。
- 记录器**不写 stdout**（stdout 是协议通道，脏了会导致 Hook 判定失败），诊断一律走 stderr。
- 写文件用 `O_APPEND` + 单次 `write`，多进程并发写不会串行交错。
- Node 与 Python 两套实现产出**完全一致**的记录，可交叉校验。

## 排查

Hook 不生效时依次确认：

1. Hook 是不是写在了项目级配置里（当前版本不执行）
2. `hooks.enabled` 是不是 `true`（用户级配置必须有）
3. 插件是不是处于启用状态
4. **有没有新建 session** —— 配置在 session 启动时形成快照，改完配置热更新不保证
5. 脚本路径是否存在、是否有执行权限（`bash <脚本路径>` 能跑通吗）
6. 看 ZCode 日志：`~/.zcode/cli/log/zcode-<日期>.jsonl`
   - `hook.run.failed`：Hook 执行失败（含来源和耗时）
   - `config_project_hooks_ignored`：项目级配置被忽略
