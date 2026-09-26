#!/usr/bin/env bash
# Installs (or updates) the dsite command: downloads direct-access.sh from
# GitHub, checks it, and installs it as /usr/local/bin/dsite.
#   curl -fsSL https://raw.githubusercontent.com/coeeshu/direct-access/main/install.sh | bash
# Only installs the command; nothing on the server is configured until you run dsite.
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
REPO=${DSITE_REPO:-coeeshu/direct-access}
REF=${DSITE_REF:-main}
URL="https://raw.githubusercontent.com/$REPO/$REF/direct-access.sh"
fail() { printf '错误：%s\n' "$1" >&2; exit 1; }

[[ $(id -u) -eq 0 ]] || fail '请用 root 执行：先 su（或 sudo -i）切换到 root，再运行安装命令。'
[[ $(uname -s) == Linux ]] || fail '只支持 Linux 服务器。'
command -v systemctl >/dev/null || fail '需要 systemd。'

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
printf '下载 %s\n' "$URL"
if command -v curl >/dev/null; then curl -fsSL --retry 2 --max-time 60 "$URL" -o "$tmp"
elif command -v wget >/dev/null; then wget -q -T 60 -O "$tmp" "$URL"
else fail '需要 curl 或 wget。'; fi

grep -q '^DSITE_VERSION=' "$tmp" && bash -n "$tmp" || fail '下载的文件不完整或不是 dsite 脚本，未安装。'
chmod 0755 "$tmp"
DSITE_REPO=$REPO DSITE_REF=$REF bash "$tmp" --install-self
"$(command -v dsite || echo /usr/local/bin/dsite)" version

cat << 'EOF'

安装完成。以 root 身份输入下面的命令打开菜单：
  dsite

第一次使用：菜单 1「环境检查」只读查看，再用 2「服务器首次部署」。
以后更新：dsite update
EOF
