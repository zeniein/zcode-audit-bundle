#!/usr/bin/env bash
# ZCode 审计记录器统一启动器
# 优先用 Node（官方示例同款），没有 Node 就退到 Python 3。
# 无论成功失败都 exit 0：审计不能影响主流程。
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v node >/dev/null 2>&1; then
  exec node "$DIR/audit-recorder.mjs"
fi

if command -v python3 >/dev/null 2>&1; then
  exec python3 "$DIR/audit-recorder.py"
fi

if command -v python >/dev/null 2>&1; then
  exec python "$DIR/audit-recorder.py"
fi

echo "[zcode-audit] PATH 上既没有 node 也没有 python3，本次未记录" >&2
exit 0
