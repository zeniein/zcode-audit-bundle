# ZCode 会话审计（zcode-audit）—— 使用说明

一套开箱即用的 ZCode Hooks 方案：把"这次会话执行了什么、调用了哪些工具、参数是什么"
完整落盘成可检索、可回溯、可做合规留存的审计日志。

## 目录

```
zcode-hooks/
├── marketplace.json                 插件市场清单（本地市场入口）
├── plugins/
│   └── zcode-audit/                 插件本体
│       ├── .zcode-plugin/plugin.json
│       ├── hooks/hooks.json         七个审计事件的挂载配置
│       ├── hooks/audit-recorder.sh  启动器（node / python3 自动二选一）
│       ├── hooks/audit-recorder.mjs 记录器（Node）
│       ├── hooks/audit-recorder.py  记录器（Python 兜底）
│       ├── hooks/audit-report.mjs   汇总报告
│       ├── audit.config.json        配置
│       └── README.md                插件详细说明
├── examples/
│   └── user-config.json             用户级 ~/.zcode/cli/config.json 完整示例
├── ZCode_Hooks_审计方案.html         单文件方案书（离线可看）
└── ZCode_Hooks_审计方案.md           同一份内容的 Markdown 版
```

## 三步装上

1. **拷到你的 Mac**（ZCode 客户端在本地，钩子在本地跑）
   ```bash
   unzip zcode-audit-bundle.zip -d ~/zcode-audit
   ```

2. **添加本地插件市场**
   ZCode → 设置 → 插件 → 右上角「创建 → 添加插件市场」→ 选 `~/zcode-audit` 这个目录
   （也就是里面有 `marketplace.json` 的那一层）→ 在「个人」分段安装并启用 zcode-audit

3. **新建一个 session**，随便聊两句，然后看日志
   ```bash
   ls -la ~/.zcode/audit/logs/
   node ~/zcode-audit/plugins/zcode-audit/hooks/audit-report.mjs
   ```

> 第 3 步的"新建 session"不能省：ZCode 在 session 启动时拍一份 Hook 配置快照，
> 改完配置不会热更新到已经开着的 session。

## 不想装插件？

只想自己机器上用，可以把 `examples/user-config.json` 里的 `hooks` 段合并进
`~/.zcode/cli/config.json`，并把脚本路径换成实际绝对路径。注意用户级配置
**必须**有 `"hooks": { "enabled": true, ... }`，否则整段不生效。

## 查审计

```bash
cd ~/zcode-audit/plugins/zcode-audit
node hooks/audit-report.mjs                        # 文本报告
node hooks/audit-report.mjs --session <id>         # 单次会话
node hooks/audit-report.mjs --html report.html     # 单文件 HTML 报告
node hooks/audit-report.mjs --json                 # 机器可读
```

原始日志在 `~/.zcode/audit/logs/YYYY-MM-DD.jsonl`，一行一条记录，直接 grep 也能用：

```bash
# 这次会话跑过哪些 shell 命令
jq -r 'select(.event=="PreToolUse" and .tool_name=="Bash") | .args.command' ~/.zcode/audit/logs/$(date +%F).jsonl

# 改过哪些文件
jq -r 'select(.tool_name=="Write" or .tool_name=="Edit") | .args.file_path' ~/.zcode/audit/logs/$(date +%F).jsonl

# 所有失败
jq -r 'select(.event=="PostToolUseFailure") | "\(.ts) \(.tool_name) \(.error)"' ~/.zcode/audit/logs/$(date +%F).jsonl
```

## 三个最容易踩的坑

1. **项目级配置不执行** —— `<workspace>/.zcode/config.json` 里的 `hooks` 当前版本被整体忽略，
   团队共享必须走插件。
2. **两层结构不一样** —— 用户级配置挂在 `hooks.events` 下，插件的 `hooks/hooks.json` 是
   `hooks` 直接当事件表用。写错层级静默不生效。
3. **stdout 是协议通道** —— 审计脚本不能往 stdout 写任何东西（诊断走 stderr），
   否则 ZCode 解析失败，Hook 会被判定为可恢复失败。

完整分析、字段说明和更多边界情况见 `ZCode_Hooks_审计方案.html`。
