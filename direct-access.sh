#!/usr/bin/env bash
# Grey-cloud (DNS-only) direct access for any local service, typically Docker
# containers that are otherwise published through a Cloudflare tunnel.
# Per site: Nginx reverse proxy, Let's Encrypt certificate, rate limits and an
# on/off switch. Server-wide: firewall (ufw/firewalld) with auto-rollback,
# fail2ban and host hardening. TUI via whiptail.
# Install: curl -fsSL https://raw.githubusercontent.com/coeeshu/direct-access/main/install.sh | bash
# Then run as root: dsite
# Never touches containers, Compose, databases, cloudflared or app configs.
set -euo pipefail
DSITE_VERSION=2026.09.27
umask 022
# Plain `su` on Debian keeps the user's PATH, which lacks /usr/sbin (ufw, sshd, nginx).
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# whiptail drops Chinese text under a non-UTF-8 locale; C.UTF-8 ships with Debian glibc.
if [[ $(locale charmap 2>/dev/null) != UTF-8 ]]; then export LC_ALL=C.UTF-8; fi
trap 'printf "脚本停止：第 %s 行失败。\n" "$LINENO" >&2' ERR
fail() { printf '错误：%s\n' "$1" >&2; exit 1; }
log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m注意：\033[0m%s\n' "$*"; }

SELF=$(readlink -f "${BASH_SOURCE[0]}")
CONFIG_ROOT=${DIRECT_SITES_ROOT:-/etc/direct-sites}
GLOBAL_CONF=$CONFIG_ROOT/global.conf
SITES_DIR=$CONFIG_ROOT/sites
BACKUP_ROOT=/var/backups/direct-sites
ACME_ROOT=/var/www/direct-sites-acme
NGX_HTTP_CONF=/etc/nginx/conf.d/direct-sites-http.conf
NGX_AVAIL=/etc/nginx/sites-available
NGX_ENABLED=/etc/nginx/sites-enabled
NGX_DEFAULT_SITE=$NGX_AVAIL/direct-sites-default.conf
NGX_DEBIAN_DEFAULT=$NGX_ENABLED/default
ERROR_LOG=/var/log/nginx/direct-sites.error.log
F2B_JAIL=/etc/fail2ban/jail.d/direct-sites.local
F2B_OLD_LOCAL=/etc/fail2ban/jail.local
SYSCTL_FILE=/etc/sysctl.d/90-direct-sites-hardening.conf
SSHD_DROPIN=/etc/ssh/sshd_config.d/90-direct-sites-hardening.conf
AUTO_UPGRADES=/etc/apt/apt.conf.d/20auto-upgrades
RENEW_HOOK=/etc/letsencrypt/renewal-hooks/deploy/direct-sites-reload-nginx.sh
ROLLBACK_UNIT=direct-sites-fw-rollback
ROLLBACK_SECONDS=180
SSH_REPORT_DIR=/var/log/direct-sites/ssh
DSITE_REPO=${DSITE_REPO:-coeeshu/direct-access}
DSITE_REF=${DSITE_REF:-main}
DSITE_BIN=/usr/local/bin/dsite
REPORT_BIN=$DSITE_BIN
OLD_REPORT_BIN=/usr/local/sbin/direct-access
REPORT_UNIT=direct-sites-ssh-report
REPORT_KEEP_DAYS=180
# New API / One API login, registration and verification endpoints.
NEWAPI_AUTH_PATHS='^/api/(user/(login|register|passkey/login)|verification|reset_password|oauth/)'

GLOBAL_KEYS=(EMAIL FIREWALL FW_KEEP F2B_IGNORE)
SITE_KEYS=(SITE_NAME DOMAIN UPSTREAM SOURCE PRESET API_RATE API_BURST CONN_LIMIT BODY_MB
  PROXY_TIMEOUT BUFFERING AUTH_PATHS AUTH_RATE AUTH_BURST HEALTH_PATH HSTS DIRECT)
EMAIL=             # Let's Encrypt 到期提醒邮箱（全部站点共用）
FIREWALL=          # 空=未由本脚本配置；ufw / firewalld
FW_KEEP=           # 额外保留的公网端口，如 "8443/tcp 51820/udp"
F2B_IGNORE=        # fail2ban 额外白名单 IP/CIDR

DRY_RUN=0
RENDER=0
BACKUP_DIR=
TXN=()

# ---------------------------------------------------------------- 配置 ----
validate() {
  local key=$1 value=$2 num='^[1-9][0-9]{0,5}$' re
  case $key in
    SITE_NAME) [[ $value =~ ^[a-z][a-z0-9_]{0,23}$ ]] ;;
    DOMAIN) [[ $value =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]] ;;
    UPSTREAM) [[ $value =~ ^(127\.0\.0\.1|\[::1\]):[1-9][0-9]{0,4}$ ]] ;;
    SOURCE) [[ $value =~ ^[A-Za-z0-9_.:/-]{0,128}$ ]] ;;
    PRESET) [[ $value == newapi || $value == api || $value == web || $value == custom ]] ;;
    API_RATE|API_BURST|AUTH_RATE|AUTH_BURST|CONN_LIMIT|BODY_MB|PROXY_TIMEOUT) [[ $value =~ $num ]] ;;
    BUFFERING|HSTS|DIRECT) [[ $value == on || $value == off ]] ;;
    AUTH_PATHS) re='^\^?/[A-Za-z0-9/_.|()?*+^$-]*$'; [[ -z $value || $value =~ $re ]] ;;
    HEALTH_PATH) [[ $value =~ ^/[A-Za-z0-9/_.~-]*$ ]] ;;
    EMAIL) [[ -z $value || $value =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] ;;
    FIREWALL) [[ -z $value || $value == ufw || $value == firewalld ]] ;;
    FW_KEEP) [[ $value =~ ^([1-9][0-9]{0,4}/(tcp|udp)( |$))*$ ]] ;;
    F2B_IGNORE) [[ $value =~ ^([0-9A-Fa-f:.]+(/[0-9]{1,3})?( |$))*$ ]] ;;
    *) return 1 ;;
  esac
}

# load_kv FILE KEY... — reads KEY=VALUE lines, accepting only the listed keys.
load_kv() {
  local file=$1 line key value
  shift
  [[ -f $file ]] || return 0
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line || $line == \#* ]] && continue
    key=${line%%=*} value=${line#*=}
    [[ " $* " == *" $key "* ]] && validate "$key" "$value" || fail "配置 $file 中 $key 的值无效：$value"
    printf -v "$key" '%s' "$value"
  done < "$file"
}

# save_kv FILE KEY... — atomic write, 0600.
save_kv() {
  local file=$1 key tmp
  shift
  mkdir -p "$(dirname "$file")"
  tmp=$(mktemp "$file.XXXXXX")
  {
    printf '# direct-access.sh 生成；请用脚本菜单修改，手工修改须保持 KEY=VALUE 格式\n'
    for key in "$@"; do printf '%s=%s\n' "$key" "${!key}"; done
  } > "$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$file"
}

load_global() { load_kv "$GLOBAL_CONF" "${GLOBAL_KEYS[@]}"; }
save_global() { save_kv "$GLOBAL_CONF" "${GLOBAL_KEYS[@]}"; }

site_file() { printf '%s/%s.conf' "$SITES_DIR" "$1"; }
site_names() {
  local f
  for f in "$SITES_DIR"/*.conf; do [[ -f $f ]] && basename "$f" .conf; done
  return 0
}

apply_preset() {
  PRESET=$1 AUTH_RATE=10 AUTH_BURST=10
  case $1 in
    newapi) API_RATE=20 API_BURST=40 CONN_LIMIT=60 BODY_MB=128 PROXY_TIMEOUT=900 BUFFERING=off
      AUTH_PATHS=$NEWAPI_AUTH_PATHS HEALTH_PATH=/api/status ;;
    api) API_RATE=20 API_BURST=40 CONN_LIMIT=60 BODY_MB=128 PROXY_TIMEOUT=900 BUFFERING=off
      AUTH_PATHS='' HEALTH_PATH=/ ;;
    web) API_RATE=10 API_BURST=50 CONN_LIMIT=30 BODY_MB=20 PROXY_TIMEOUT=120 BUFFERING=on
      AUTH_PATHS='' HEALTH_PATH=/ ;;
  esac
}

site_defaults() {
  SITE_NAME='' DOMAIN='' UPSTREAM='' SOURCE='' HSTS=on DIRECT=off
  apply_preset web
}

load_site() {
  site_defaults
  load_kv "$(site_file "$1")" "${SITE_KEYS[@]}"
  [[ $SITE_NAME == "$1" ]] || fail "站点文件 $(site_file "$1") 的 SITE_NAME 与文件名不一致"
}
save_site() { save_kv "$(site_file "$SITE_NAME")" "${SITE_KEYS[@]}"; }

# ------------------------------------------------------------ 文件与回滚 ----
run() {
  if ((DRY_RUN)); then printf '+'; printf ' %q' "$@"; printf '\n'; else "$@"; fi
}

ensure_backup_dir() {
  [[ -n $BACKUP_DIR ]] && return 0
  mkdir -p "$BACKUP_ROOT"
  chmod 0700 "$BACKUP_ROOT"
  BACKUP_DIR=$(mktemp -d "$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)-XXXX")
}

# Copies an absolute path into BACKUP_DIR keeping its layout. Avoids
# `cp --parents`, which fails on Debian 12 unless the cwd is /.
backup_copy() {
  mkdir -p "$BACKUP_DIR$(dirname "$1")"
  cp -a "$1" "$BACKUP_DIR$1"
}

backup_path() {
  local path=$1
  ensure_backup_dir
  if [[ ( -e $path || -L $path ) && ! -e $BACKUP_DIR$path && ! -L $BACKUP_DIR$path ]]; then
    backup_copy "$path"
  fi
  TXN+=("$path")
}

# Restores every path changed in this process to its pre-run content.
txn_rollback() {
  local path
  for path in "${TXN[@]}"; do
    rm -rf "$path"
    if [[ -e $BACKUP_DIR$path || -L $BACKUP_DIR$path ]]; then cp -a "$BACKUP_DIR$path" "$path"; fi
  done
  TXN=()
}

# install_file DEST MODE RENDER_CMD...; unchanged files are left untouched.
# Not used in a pipeline so the backup list (TXN) stays in this shell.
install_file() {
  local dest=$1 mode=$2 tmp
  tmp=$(mktemp)
  "${@:3}" > "$tmp"
  if ((DRY_RUN)); then printf '=== %s (%s) ===\n' "$dest" "$mode"; cat "$tmp"; rm -f "$tmp"; return 0; fi
  if [[ -f $dest && ! -L $dest ]] && cmp -s "$tmp" "$dest"; then rm -f "$tmp"; return 0; fi
  backup_path "$dest"
  install -D -m "$mode" "$tmp" "$dest"
  rm -f "$tmp"
  log "已写入 $dest"
}

remove_path() { # backs up, then deletes a file or symlink
  [[ -e $1 || -L $1 ]] || return 0
  backup_path "$1"
  rm -f "$1"
  log "已移除 $1（备份在 $BACKUP_DIR）"
}

link_path() { # link_path TARGET LINK
  [[ $(readlink "$2" 2>/dev/null) == "$1" ]] && return 0
  backup_path "$2"
  ln -sfn "$1" "$2"
}

# ------------------------------------------------------------------ 界面 ----
HAVE_UI=0
ui_init() {
  if [[ -t 0 && -t 1 ]] && command -v whiptail >/dev/null; then HAVE_UI=1; fi
}
ui_size() {
  local rows cols
  rows=$(tput lines 2>/dev/null || echo 24) cols=$(tput cols 2>/dev/null || echo 80)
  UI_H=$((rows > 34 ? 30 : rows - 4)) UI_W=$((cols > 104 ? 100 : cols - 4))
}
pause() { [[ -t 0 ]] && read -rp '按回车继续…' _ || true; }
# Display-only boxes: Esc (exit 255) just closes them, never fails the action.
ui_msg() {
  if ((HAVE_UI)); then ui_size; whiptail --title "$1" --scrolltext --msgbox "$2" "$UI_H" "$UI_W" || true
  else printf '\n== %s ==\n%b\n' "$1" "$2"; pause; fi
}
ui_textfile() {
  if ((HAVE_UI)); then ui_size; whiptail --title "$1" --scrolltext --textbox "$2" "$UI_H" "$UI_W" || true
  else printf '\n== %s ==\n' "$1"; cat "$2"; pause; fi
}
ui_yesno() { # title text [default-no]
  local extra=()
  [[ ${3:-} == no ]] && extra=(--defaultno)
  if ((HAVE_UI)); then ui_size; whiptail --title "$1" "${extra[@]}" --yesno "$2" "$UI_H" "$UI_W"; return; fi
  local answer
  printf '\n== %s ==\n%b\n' "$1" "$2"
  read -rp '确认？[y/N] ' answer
  [[ $answer == [yY]* ]]
}
ui_input() { # title text default -> stdout
  if ((HAVE_UI)); then ui_size; whiptail --title "$1" --inputbox "$2" 14 "$UI_W" "$3" 3>&1 1>&2 2>&3; return; fi
  local answer
  printf '\n== %s ==\n%b\n' "$1" "$2" >&2
  read -rp "[$3] " answer
  printf '%s\n' "${answer:-$3}"
}
ui_menu() { # title text tag desc ... -> stdout
  local title=$1 text=$2
  shift 2
  if ((HAVE_UI)); then ui_size; whiptail --title "$title" --menu "$text" "$UI_H" "$UI_W" $((UI_H - 8)) "$@" 3>&1 1>&2 2>&3; return; fi
  printf '\n== %s ==\n%b\n' "$title" "$text" >&2
  while (($#)); do printf '  %-4s %s\n' "$1" "$2" >&2; shift 2; done
  local answer
  read -rp '选择：' answer
  [[ -n $answer ]] && printf '%s\n' "$answer"
}
ui_checklist() { # title text tag desc ON|OFF ... -> space separated tags
  local title=$1 text=$2
  shift 2
  if ((HAVE_UI)); then
    ui_size
    whiptail --title "$title" --separate-output --checklist "$text" "$UI_H" "$UI_W" $((UI_H - 8)) "$@" 3>&1 1>&2 2>&3 | tr '\n' ' '
    return "${PIPESTATUS[0]}"
  fi
  local defaults=() answer
  printf '\n== %s ==\n%b\n' "$title" "$text" >&2
  while (($#)); do
    printf '  [%s] %-10s %s\n' "$([[ $3 == ON ]] && echo x || echo ' ')" "$1" "$2" >&2
    [[ $3 == ON ]] && defaults+=("$1")
    shift 3
  done
  read -rp "输入要选择的项（空格分隔，回车=默认 ${defaults[*]:-无}，- 表示都不选）：" answer
  if [[ -z $answer ]]; then printf '%s' "${defaults[*]:-}"; elif [[ $answer != - ]]; then printf '%s' "$answer"; fi
}

# ------------------------------------------------------------------ 探测 ----
require_root() { [[ $(id -u) -eq 0 ]] || fail '请先 su 切换到 root，再执行本脚本。'; }
has() { command -v "$1" >/dev/null 2>&1; }
cert_dir() { printf '/etc/letsencrypt/live/%s' "$1"; }
cert_ok() { # domain
  ((RENDER)) && return 0
  [[ -s $(cert_dir "$1")/fullchain.pem && -s $(cert_dir "$1")/privkey.pem ]]
}
cert_expiry() { openssl x509 -enddate -noout -in "$(cert_dir "$1")/fullchain.pem" 2>/dev/null | cut -d= -f2; }
ipv6_enabled() { [[ -e /proc/net/if_inet6 && $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1) == 0 ]]; }
site_tls() { [[ $DIRECT == on ]] && cert_ok "$DOMAIN"; } # for the loaded site

nginx_new_http2() { # nginx >= 1.25.1 uses "http2 on;"
  local version
  version=$(nginx -v 2>&1 | sed -n 's|.*nginx/\([0-9.]*\).*|\1|p')
  [[ -n $version ]] && printf '%s\n1.25.1\n' "$version" | sort -V -C -r 2>/dev/null
}

other_default_servers() {
  grep -RlsE 'listen[^;#]*default_server' /etc/nginx/conf.d "$NGX_ENABLED" 2>/dev/null \
    | grep -v 'direct-site' || true
}

detect_ssh_ports() {
  local ports=()
  if has sshd; then mapfile -t -O "${#ports[@]}" ports < <(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}'); fi
  mapfile -t -O "${#ports[@]}" ports < <(ss -H -ltnp 2>/dev/null | awk '/"sshd"/ {n = split($4, a, ":"); print a[n]}')
  if [[ -n ${SSH_CONNECTION:-} ]]; then ports+=("$(awk '{print $4}' <<< "$SSH_CONNECTION")"); fi
  printf '%s\n' "${ports[@]}" | grep -E '^[0-9]+$' | sort -un | tr '\n' ' ' | sed 's/ $//' || true
}

# Prints "port/proto process address" for sockets reachable from outside loopback.
public_listeners() {
  ss -H -lntup 2>/dev/null | awk '
    {
      proto = $1; addr = $5; n = split(addr, a, ":"); port = a[n]
      host = substr(addr, 1, length(addr) - length(port) - 1)
      if (host ~ /^(127\.|\[::1\]|::1|\[::ffff:127\.)/) next
      proc = "?"; if (match($0, /users:\(\("[^"]+"/)) proc = substr($0, RSTART + 9, RLENGTH - 10)
      key = port "/" proto
      if (!(key in seen)) { seen[key] = 1; print key, proc, addr }
    }' | sort -t/ -k1,1n || true
}

docker_bridge_subnets() {
  has docker || return 0
  local ids
  ids=$(docker network ls -q --filter driver=bridge 2>/dev/null) || return 0
  [[ -n $ids ]] || return 0
  # shellcheck disable=SC2086
  docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' $ids 2>/dev/null \
    | tr ' ' '\n' | grep -E '^[0-9a-fA-F:.]+/[0-9]+$' | sort -u | tr '\n' ' ' | sed 's/ $//' || true
}

# Loopback upstream for a host address; empty when 127.0.0.1 cannot reach it.
loopback_upstream() { # host port
  case $1 in
    ''|'*'|0.0.0.0|127.0.0.1|'[::]'|'::') printf '127.0.0.1:%s' "$2" ;;
    '[::1]'|'::1') printf '[::1]:%s' "$2" ;;
  esac
}

# Lists proxyable Docker services as "upstream<TAB>container<TAB>detail".
# Published ports come from docker inspect; host-network containers are
# matched to listening sockets through /proc/<pid>/cgroup.
discover_services() {
  has docker || return 0
  local id name mode line cport hip hport up addr pid host port
  while read -r id name mode; do
    [[ -z $id ]] && continue
    if [[ $mode == host ]]; then
      while read -r addr pid; do
        grep -qs "$id" "/proc/$pid/cgroup" || continue
        port=${addr##*:} host=${addr%:*}
        up=$(loopback_upstream "$host" "$port")
        [[ -n $up ]] && printf '%s\t%s\t%s\n' "$up" "$name" "host 网络，监听 $addr"
      done < <(ss -H -ltnp 2>/dev/null | awk 'match($0, /pid=[0-9]+/) {print $4, substr($0, RSTART + 4, RLENGTH - 4)}')
    else
      while read -r cport hip hport; do
        [[ $cport == */tcp && -n $hport ]] || continue
        up=$(loopback_upstream "$hip" "$hport")
        [[ -n $up ]] || continue
        line="发布 ${hip:-0.0.0.0}:$hport -> 容器 $cport"
        [[ $hip == 127.0.0.1 || $hip == ::1 ]] || line+="（⚠ 公网发布会绕过 ufw）"
        printf '%s\t%s\t%s\n' "$up" "$name" "$line"
      done < <(docker inspect -f '{{range $p, $b := .NetworkSettings.Ports}}{{range $b}}{{$p}} {{.HostIp}} {{.HostPort}}{{"\n"}}{{end}}{{end}}' "$id" 2>/dev/null)
    fi
  done < <(docker ps --no-trunc --format '{{.ID}} {{.Names}}' 2>/dev/null \
    | while read -r id name; do printf '%s %s %s\n' "$id" "$name" "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$id" 2>/dev/null)"; done)
  return 0
}

public_ip() { curl -4 -fsS --max-time 8 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | sed -n 's/^ip=//p' || true; }
resolved_ip() { getent ahostsv4 "$1" 2>/dev/null | awk '{print $1; exit}' || true; }

firewall_backend() {
  if [[ -n $FIREWALL ]]; then printf '%s' "$FIREWALL"
  elif systemctl is-active --quiet firewalld 2>/dev/null; then printf firewalld
  else printf ufw; fi
}

# True when at least one site is switched on and has a certificate.
any_tls_site() {
  local name
  for name in $(site_names); do
    ( load_site "$name"; site_tls ) && return 0
  done
  return 1
}

# ------------------------------------------------------------ 配置渲染 ----
render_nginx_http() {
  local name
  printf '# 由 direct-access.sh 生成，重新运行会覆盖；每个直连站点独立的限流区域。\n'
  for name in $(site_names); do
    (
      load_site "$name"
      printf '\n# %s -> %s\n' "$DOMAIN" "$UPSTREAM"
      printf 'limit_req_zone $binary_remote_addr zone=ds_%s_req:10m rate=%sr/s;\n' "$SITE_NAME" "$API_RATE"
      [[ -n $AUTH_PATHS ]] && printf 'limit_req_zone $binary_remote_addr zone=ds_%s_auth:10m rate=%sr/m;\n' "$SITE_NAME" "$AUTH_RATE"
      printf 'limit_conn_zone $binary_remote_addr zone=ds_%s_conn:10m;\n' "$SITE_NAME"
    )
  done
  cat << 'EOF'

map $http_upgrade $direct_sites_connection {
    default upgrade;
    ""      close;
}
EOF
}

listen_lines() { # port options
  printf '    listen %s%s;\n' "$1" "${2:+ $2}"
  if ((R_IPV6)); then printf '    listen [::]:%s%s;\n' "$1" "${2:+ $2}"; fi
}

acme_location() {
  cat << EOF
    location ^~ /.well-known/acme-challenge/ {
        root $ACME_ROOT;
        default_type text/plain;
        try_files \$uri =404;
    }
EOF
}

# Uses R_DEFAULT, R_IPV6, R_HTTP2NEW, R_ANY_TLS.
render_nginx_default() {
  local ssl_opts='ssl http2 default_server'
  ((R_HTTP2NEW)) && ssl_opts='ssl default_server'
  printf '# 由 direct-access.sh 生成：IP 或未知域名的请求一律拒绝，只保留证书验证路径。\n'
  ((R_DEFAULT)) || { printf '# 服务器已有其他 default_server，本文件不接管默认站点。\n'; return 0; }
  printf 'server {\n'
  listen_lines 80 default_server
  printf '    server_name _;\n    server_tokens off;\n    access_log off;\n'
  acme_location
  printf '    location / {\n        return 444;\n    }\n}\n'
  ((R_ANY_TLS)) || return 0
  printf '\nserver {\n'
  listen_lines 443 "$ssl_opts"
  ((R_HTTP2NEW)) && printf '    http2 on;\n'
  printf '    server_name _;\n    ssl_reject_handshake on;\n}\n'
}

render_proxy() {
  cat << EOF
        proxy_pass http://$UPSTREAM;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header CF-Connecting-IP "";
        proxy_set_header True-Client-IP "";
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$direct_sites_connection;
        proxy_connect_timeout 10s;
        proxy_read_timeout ${PROXY_TIMEOUT}s;
        proxy_send_timeout ${PROXY_TIMEOUT}s;
EOF
  if [[ $BUFFERING == off ]]; then
    printf '        proxy_buffering off;\n        proxy_request_buffering off;\n'
  fi
}

# Renders the loaded site. Uses R_IPV6, R_HTTP2NEW.
render_nginx_site() {
  local tls=0 ssl_opts='ssl http2'
  site_tls && tls=1
  ((R_HTTP2NEW)) && ssl_opts=ssl
  printf '# 由 direct-access.sh 生成（站点 %s，直连：%s），重新运行会覆盖。\n' "$SITE_NAME" "$DIRECT"
  printf '# 灰云直连 %s -> %s（%s，预设 %s）；Cloudflare 隧道不经过这里。\n\n' "$DOMAIN" "$UPSTREAM" "${SOURCE:-手动}" "$PRESET"
  printf 'server {\n'
  listen_lines 80
  printf '    server_name %s;\n    server_tokens off;\n' "$DOMAIN"
  acme_location
  printf '    location / {\n'
  if ((tls)); then printf '        return 301 https://$host$request_uri;\n'; else printf '        return 444;\n'; fi
  printf '    }\n}\n'
  ((tls)) || return 0
  printf '\nserver {\n'
  listen_lines 443 "$ssl_opts"
  ((R_HTTP2NEW)) && printf '    http2 on;\n'
  cat << EOF
    server_name $DOMAIN;
    server_tokens off;

    ssl_certificate $(cert_dir "$DOMAIN")/fullchain.pem;
    ssl_certificate_key $(cert_dir "$DOMAIN")/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:direct_sites_ssl:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    access_log /var/log/nginx/direct-site-$SITE_NAME.access.log;
    error_log $ERROR_LOG warn;

    client_max_body_size ${BODY_MB}m;
    client_header_timeout 15s;
    client_body_timeout 60s;

    limit_conn ds_${SITE_NAME}_conn $CONN_LIMIT;
    limit_conn_status 429;
    limit_conn_log_level warn;
    limit_req_status 429;
    limit_req_log_level warn;

EOF
  if [[ $HSTS == on ]]; then printf '    add_header Strict-Transport-Security "max-age=31536000" always;\n'; fi
  printf '    add_header X-Content-Type-Options "nosniff" always;\n'
  if [[ -n $AUTH_PATHS ]]; then
    printf '\n    location ~ "%s" {\n' "$AUTH_PATHS"
    printf '        limit_req zone=ds_%s_auth burst=%s nodelay;\n' "$SITE_NAME" "$AUTH_BURST"
    render_proxy
    printf '    }\n'
  fi
  printf '\n    location / {\n'
  printf '        limit_req zone=ds_%s_req burst=%s nodelay;\n' "$SITE_NAME" "$API_BURST"
  render_proxy
  printf '    }\n}\n'
}

render_site_by_name() { ( load_site "$1"; render_nginx_site ); }

render_f2b() { # ssh-ports ignore-list
  cat << EOF
# 由 direct-access.sh 生成，重新运行会覆盖。
[DEFAULT]
banaction = nftables-multiport
banaction_allports = nftables-allports
ignoreip = 127.0.0.1/8 ::1${2:+ $2}
bantime.increment = true
bantime.maxtime = 1w

# 显式覆盖旧 jail.local 可能在 [sshd] 中写入的动作、日志路径。
[sshd]
enabled = true
backend = systemd
banaction = nftables-multiport
action = %(action_)s
port = ${1// /,}
maxretry = 5
findtime = 10m
bantime = 1h

# 所有直连站点共用的限流日志：每分钟被 429 拒绝超过 60 次的 IP 临时封禁。
[nginx-limit-req]
enabled = true
backend = auto
port = http,https
logpath = $ERROR_LOG
maxretry = 60
findtime = 1m
bantime = 10m
EOF
}

render_sysctl() {
  cat << 'EOF'
# 由 direct-access.sh 生成。不修改 ip_forward（Docker 需要）。
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF
}

render_sshd() {
  cat << 'EOF'
# 由 direct-access.sh 生成。仅禁止 root 直接 SSH 登录（仍可普通用户登录后 su），
# 不修改端口、不关闭密码登录。
PermitRootLogin no
MaxAuthTries 4
LoginGraceTime 30
EOF
}

render_renew_hook() {
  cat << 'EOF'
#!/bin/sh
# 由 direct-access.sh 生成：证书续期后重新加载 Nginx。
nginx -t -q && systemctl reload nginx
EOF
}

render_auto_upgrades() {
  cat << 'EOF'
// 由 direct-access.sh 生成：每天更新软件列表并自动安装 Debian 安全更新。
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
}

# --------------------------------------------------------------- 防火墙 ----
# Inputs: FW_SSH_PORTS, FW_NETS, FW_KEEP, FW_HTTPS (on/off). Adds rules; never
# deletes rules that this script did not create (except 443 when unused).
fw_apply_ufw() {
  local port net
  run ufw default deny incoming
  run ufw default allow outgoing
  for port in $FW_SSH_PORTS; do run ufw allow "$port/tcp" comment 'direct-sites ssh'; done
  for net in $FW_NETS; do run ufw allow from "$net" comment 'direct-sites docker bridge'; done
  run ufw allow 80/tcp comment 'direct-sites acme+http'
  fw_https_ufw
  for port in $FW_KEEP; do run ufw allow "$port" comment 'direct-sites keep'; done
}
fw_https_ufw() {
  if [[ $FW_HTTPS == on ]]; then run ufw allow 443/tcp comment 'direct-sites https'
  else run ufw delete allow 443/tcp || true; fi
}

fw_zone() { if ((DRY_RUN)); then printf public; else firewall-cmd --get-default-zone; fi; }
fw_apply_firewalld() {
  local port net zone
  zone=$(fw_zone)
  for port in $FW_SSH_PORTS; do run firewall-cmd --permanent --zone="$zone" --add-port="$port/tcp"; done
  for net in $FW_NETS; do run firewall-cmd --permanent --zone=trusted --add-source="$net" || warn "$net 已属于其他区域，跳过"; done
  run firewall-cmd --permanent --zone="$zone" --add-port=80/tcp
  for port in $FW_KEEP; do run firewall-cmd --permanent --zone="$zone" --add-port="$port"; done
  fw_https_firewalld
}
fw_https_firewalld() {
  local zone
  zone=$(fw_zone)
  if [[ $FW_HTTPS == on ]]; then run firewall-cmd --permanent --zone="$zone" --add-port=443/tcp
  else run firewall-cmd --permanent --zone="$zone" --remove-port=443/tcp || true; fi
  run firewall-cmd --reload
}

# Opens 443 while any site serves HTTPS, closes it when none does.
fw_sync_https() {
  FW_HTTPS=off
  any_tls_site && FW_HTTPS=on
  case $FIREWALL in
    ufw) fw_https_ufw ;;
    firewalld) fw_https_firewalld ;;
    *) warn '防火墙尚未由本脚本配置，跳过 443 规则；请用菜单「配置防火墙」。' ;;
  esac
}

# Port 80 must be reachable for HTTP-01 even before this script manages the firewall.
fw_ensure_http() {
  if [[ $(firewall_backend) == firewalld ]] && systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-port=80/tcp && firewall-cmd --reload
  elif has ufw && ufw status | grep -q '^Status: active'; then
    ufw allow 80/tcp comment 'direct-sites acme+http'
  fi
}

# ------------------------------------------------------------ Nginx 应用 ----
# Rewrites every managed Nginx file from the site configs, drops files of
# deleted sites, then tests and reloads.
nginx_write_all() {
  local others name f
  R_DEFAULT=1 R_IPV6=0 R_HTTP2NEW=0 R_ANY_TLS=0
  ipv6_enabled && R_IPV6=1
  nginx_new_http2 && R_HTTP2NEW=1
  any_tls_site && R_ANY_TLS=1
  others=$(other_default_servers)
  if [[ -n $others ]]; then
    R_DEFAULT=0
    warn "已有其他 default_server（$others），本脚本不接管 IP/未知域名的默认站点。"
  fi
  mkdir -p "$ACME_ROOT"
  chmod 0755 "$ACME_ROOT"
  if [[ ! -e $ERROR_LOG ]]; then install -m 0640 -g adm /dev/null "$ERROR_LOG" 2>/dev/null || touch "$ERROR_LOG"; fi
  install_file "$NGX_HTTP_CONF" 0644 render_nginx_http
  install_file "$NGX_DEFAULT_SITE" 0644 render_nginx_default
  link_path "$NGX_DEFAULT_SITE" "$NGX_ENABLED/direct-sites-default.conf"
  for name in $(site_names); do
    install_file "$NGX_AVAIL/direct-site-$name.conf" 0644 render_site_by_name "$name"
    link_path "$NGX_AVAIL/direct-site-$name.conf" "$NGX_ENABLED/direct-site-$name.conf"
  done
  for f in "$NGX_AVAIL"/direct-site-*.conf; do
    [[ -e $f ]] || continue
    name=$(basename "$f" .conf) name=${name#direct-site-}
    [[ -f $(site_file "$name") ]] && continue
    remove_path "$NGX_ENABLED/direct-site-$name.conf"
    remove_path "$f"
  done
  nginx_activate
}

nginx_activate() {
  if ! nginx -t; then
    warn 'nginx -t 失败，正在恢复本次修改前的配置。'
    txn_rollback
    nginx -t || true
    fail 'Nginx 配置检查失败，已恢复原配置，现有网站不受影响。'
  fi
  if systemctl is-active --quiet nginx; then systemctl reload nginx; else systemctl enable --now nginx; fi
  log 'Nginx 已加载新配置。'
}

http_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@" || true; }

# HTTP code of https://DOMAIN/HEALTH_PATH via local Nginx; notes cert problems.
https_probe() {
  local code
  code=$(http_code --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN$HEALTH_PATH")
  if [[ $code == 000 ]]; then
    code=$(http_code -k --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN$HEALTH_PATH")
    [[ $code != 000 ]] && code="$code（证书校验失败：自签或已过期？）"
  fi
  printf '%s' "$code"
}

site_self_test() { # for the loaded site
  local code
  code=$(http_code "http://$UPSTREAM$HEALTH_PATH")
  log "本机服务 http://$UPSTREAM$HEALTH_PATH -> HTTP $code"
  if site_tls; then
    code=$(https_probe)
    log "经 Nginx https://$DOMAIN$HEALTH_PATH（本机解析）-> HTTP $code"
    [[ $code =~ ^(000|502|503|504) ]] && warn '经 Nginx 自检失败，请查看「状态与诊断」。'
  fi
  return 0
}

# ---------------------------------------------------------- 站点：选择 ----
pick_site() { # prompt -> site name on stdout
  local items=() name
  for name in $(site_names); do
    items+=("$name" "$( load_site "$name"; printf '%s -> %s  [直连：%s]' "$DOMAIN" "$UPSTREAM" "$DIRECT" )")
  done
  ((${#items[@]})) || fail '还没有直连站点，请先「添加直连站点」。'
  ui_menu '选择站点' "$1" "${items[@]}"
}

site_used_by() { # key value -> site name using it
  local name
  for name in $(site_names); do
    ( load_site "$name"; [[ ${!1} == "$2" ]] ) && { printf '%s' "$name"; return 0; }
  done
  return 0
}

# ------------------------------------------------------------------ 动作 ----
action_check() {
  local out listeners pub f services name
  out=$(mktemp)
  {
    printf '系统：%s\n' "$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"
    printf '\n[软件]\n'
    for f in whiptail nginx certbot fail2ban-client ufw firewall-cmd nft curl docker; do
      printf '  %-16s %s\n' "$f" "$(has "$f" && echo 已安装 || echo 未安装)"
    done
    printf '  %-16s %s\n' firewalld "$(systemctl is-active firewalld 2>/dev/null || true)"
    has ufw && printf '  %-16s %s\n' 'ufw 状态' "$(ufw status 2>/dev/null | head -1)"
    printf '  %-16s %s\n' 'fail2ban 服务' "$(systemctl is-active fail2ban 2>/dev/null || true)"
    printf '\n[SSH]\n  端口：%s\n' "$(detect_ssh_ports)"
    printf '\n[公网可达的监听端口]（不含 127.0.0.1/::1；ufw 只能拦住这里的端口）\n'
    listeners=$(public_listeners)
    printf '%s\n' "${listeners:-无}" | sed 's/^/  /'
    printf '\n[80/443 占用]\n'
    ss -H -ltnp '( sport = :80 or sport = :443 )' 2>/dev/null | awk '{print "  " $4, $6}' || true
    pub=$(public_ip)
    printf '\n[本机出口公网 IP] %s\n' "${pub:-获取失败}"
    printf '\n[可直连的 Docker 服务]（上游地址 容器 说明）\n'
    services=$(discover_services)
    printf '%s\n' "${services:-  未发现（没有发布到本机的端口）}" | sed 's/^/  /'
    printf '  说明：只发布在容器内部、没有映射到宿主机端口的服务，需要先在 Compose 里发布到 127.0.0.1。\n'
    printf '\n[直连站点]\n'
    for name in $(site_names); do
      (
        load_site "$name"
        printf '  %-12s %-32s -> %-16s 直连：%-3s 证书：%s  DNS：%s\n' "$SITE_NAME" "$DOMAIN" "$UPSTREAM" "$DIRECT" \
          "$(cert_ok "$DOMAIN" && cert_expiry "$DOMAIN" || echo 未申请)" "$(resolved_ip "$DOMAIN")"
      )
    done
    [[ -n $(site_names) ]] || printf '  无\n'
    printf '\n[Nginx 默认站点]\n  %s\n' "$(other_default_servers | tr '\n' ' ')"
  } > "$out" 2>&1
  ui_textfile '环境检查（只读）' "$out"
  rm -f "$out"
}

action_install() {
  local pkgs=(nginx certbot fail2ban python3-systemd nftables curl ca-certificates openssl whiptail)
  local busy sum pkgsum
  busy=$(ss -H -ltnp '( sport = :80 or sport = :443 )' 2>/dev/null | grep -v '"nginx"' || true)
  [[ -z $busy ]] || fail "80/443 已被非 Nginx 程序占用，请先确认用途，未做任何安装：$busy"
  [[ $(firewall_backend) == ufw ]] && pkgs+=(ufw)
  log "安装：${pkgs[*]}"
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${pkgs[@]}"
  # Debian 自带的默认站点占用 default_server；只在它是包内原样文件时停用。
  if [[ -L $NGX_DEBIAN_DEFAULT ]]; then
    sum=$(md5sum /etc/nginx/sites-available/default 2>/dev/null | awk '{print $1}')
    pkgsum=$(dpkg-query -W -f='${Conffiles}\n' nginx nginx-common 2>/dev/null | awk '$1 == "/etc/nginx/sites-available/default" {print $2}' | head -1)
    if [[ -n $sum && $sum == "$pkgsum" ]]; then
      remove_path "$NGX_DEBIAN_DEFAULT"
    else
      warn 'Debian 默认站点被修改过，保留不动。'
    fi
  fi
  systemctl enable --now nginx
  log '依赖安装完成。'
}

action_nginx() {
  has nginx || fail '尚未安装 Nginx，请先执行「安装依赖」。'
  nginx_write_all
}

# Asks for the site's domain, checks DNS, requests the certificate.
site_cert() { # for the loaded site
  has certbot || fail '尚未安装 certbot，请先执行「安装依赖」。'
  local res pub email args
  res=$(resolved_ip "$DOMAIN") pub=$(public_ip)
  if [[ -z $res || ( -n $pub && $res != "$pub" ) ]]; then
    ui_yesno 'DNS 检查' "$DOMAIN 解析为「${res:-失败}」，本机公网 IP 为「${pub:-未知}」。\n\n请在 Cloudflare 添加 A 记录 $DOMAIN -> ${pub:-本机 IP}，代理状态选「仅 DNS」（灰云）。\n橙云或未生效时 Let's Encrypt 验证会失败。仍要继续吗？" no \
      || fail '已取消证书申请。'
  fi
  if [[ -z $EMAIL ]]; then
    email=$(ui_input '证书邮箱' "用于 Let's Encrypt 到期提醒（所有站点共用，可留空）。" '') || fail '已取消。'
    validate EMAIL "$email" || fail "邮箱格式无效：$email"
    EMAIL=$email
    save_global
  fi
  fw_ensure_http
  log '需要云厂商安全组已放行 TCP 80，否则验证会超时。'
  args=(certonly --webroot -w "$ACME_ROOT" -d "$DOMAIN" --cert-name "$DOMAIN" --agree-tos --non-interactive --keep-until-expiring)
  if [[ -n $EMAIL ]]; then args+=(--email "$EMAIL"); else args+=(--register-unsafely-without-email); fi
  certbot "${args[@]}"
  install_file "$RENEW_HOOK" 0755 render_renew_hook
  systemctl enable --now certbot.timer 2>/dev/null || warn '未找到 certbot.timer，请确认证书自动续期方式。'
  cert_ok "$DOMAIN" || fail '证书文件不存在，申请未成功。'
  log "证书就绪：$DOMAIN 到期 $(cert_expiry "$DOMAIN")"
}

choose_service() { # -> "upstream<TAB>source" on stdout
  local services items=() up name detail i=0 choice port used
  services=$(discover_services)
  declare -A seen=()
  while IFS=$'\t' read -r up name detail; do
    [[ -z $up || -n ${seen[$up]:-} ]] && continue
    seen[$up]=1
    used=$(site_used_by UPSTREAM "$up")
    i=$((i + 1))
    items+=("$i" "$name  $up  $detail${used:+  [已有站点 $used]}")
    printf -v "SVC_$i" '%s\t%s' "$up" "$name"
  done <<< "$services"
  items+=(manual '手动输入本机端口（非 Docker 服务或未识别的端口）')
  choice=$(ui_menu '选择要直连的服务' '列出的是本机能访问到的 Docker 服务端口。Cloudflare 隧道原本指向哪个端口，就选哪个。' "${items[@]}") \
    || fail '已取消。'
  if [[ $choice == manual ]]; then
    port=$(ui_input '本机端口' '服务在本机监听的 TCP 端口（Nginx 会反代到 127.0.0.1:端口）：' '') || fail '已取消。'
    [[ $port =~ ^[1-9][0-9]{0,4}$ ]] || fail "端口无效：$port"
    printf '127.0.0.1:%s\tmanual' "$port"
    return 0
  fi
  [[ $choice =~ ^[0-9]+$ && $choice -ge 1 && $choice -le $i ]] || fail "选择无效：$choice"
  local var="SVC_$choice"
  printf '%s' "${!var}"
}

action_add_site() {
  has nginx || fail '尚未安装 Nginx，请先执行「服务器首次部署」或「安装依赖」。'
  local picked name preset used summary
  picked=$(choose_service)
  site_defaults
  UPSTREAM=${picked%%$'\t'*} SOURCE=${picked#*$'\t'}
  [[ $SOURCE == manual ]] && SOURCE=
  validate UPSTREAM "$UPSTREAM" || fail "上游地址无效：$UPSTREAM"
  used=$(site_used_by UPSTREAM "$UPSTREAM")
  if [[ -n $used ]]; then
    ui_yesno '重复的上游' "$UPSTREAM 已被站点 $used 使用。仍要再加一个域名指向它吗？" no || fail '已取消。'
  fi
  DOMAIN=$(ui_input '直连域名' "给 ${SOURCE:-$UPSTREAM} 用的灰云域名，例如 direct.example.com。\n请先在 Cloudflare 添加 A 记录指向本服务器，代理状态「仅 DNS」。" '') || fail '已取消。'
  DOMAIN=${DOMAIN,,}
  validate DOMAIN "$DOMAIN" || fail "域名格式无效：$DOMAIN"
  used=$(site_used_by DOMAIN "$DOMAIN")
  [[ -z $used ]] || fail "$DOMAIN 已属于站点 $used。"
  name=$(printf '%s' "${SOURCE:-${DOMAIN%%.*}}" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9_\n' '_' | sed 's/^[^a-z]*//' | cut -c1-20)
  [[ -n $name ]] || name=site
  if [[ -f $(site_file "$name") ]]; then name=${name:0:18}_$((RANDOM % 90 + 10)); fi
  name=$(ui_input '站点名称' '内部标识：小写字母开头，只能用小写字母、数字、下划线，最多 24 位。' "$name") || fail '已取消。'
  validate SITE_NAME "$name" || fail "站点名称无效：$name"
  [[ ! -f $(site_file "$name") ]] || fail "站点 $name 已存在。"
  SITE_NAME=$name
  preset=$(ui_menu '限流预设' '按服务类型选择，之后可在「站点管理 → 参数」里单独调整：' \
    newapi 'New API / One API 网关：流式长连接，登录注册严格限流' \
    api 'API / AI 服务：流式长连接，128MB 请求体，每 IP 20 次/秒' \
    web '普通网站 / 管理后台：每 IP 10 次/秒，20MB 请求体') || fail '已取消。'
  apply_preset "$preset"
  summary="站点：$SITE_NAME\n域名：https://$DOMAIN\n上游：$UPSTREAM（${SOURCE:-手动}）\n预设：$PRESET（每 IP ${API_RATE} 次/秒，并发 $CONN_LIMIT，请求体 ${BODY_MB}MB，超时 ${PROXY_TIMEOUT}s）\n\n接下来：写入 Nginx（80 端口只做证书验证）→ 申请证书 → 询问是否开启直连。\n注意：服务会收到 Host: $DOMAIN，部分程序（如需配置站点地址的后台）要在自身设置里允许这个域名。"
  ui_yesno '确认添加站点' "$summary" || fail '已取消。'
  mkdir -p "$SITES_DIR"
  chmod 0700 "$CONFIG_ROOT"
  save_site
  nginx_write_all
  site_self_test
  if ui_yesno '申请证书' "现在为 $DOMAIN 申请 Let's Encrypt 证书吗？\n（需要 DNS 已指向本机、安全组已放行 80）"; then
    site_cert
    if ui_yesno '开启直连' "证书已就绪。现在开启 https://$DOMAIN 直连吗？"; then
      DIRECT=on
      save_site
    fi
    nginx_write_all
    fw_sync_https
    site_self_test
  fi
  log "站点 $SITE_NAME 已添加。以后在「站点管理」里开关直连。"
}

action_site_cert() { # site
  load_site "$1"
  site_cert
  nginx_write_all
  fw_sync_https
  site_self_test
}

action_site_direct() { # site on|off
  load_site "$1"
  if [[ $2 == on ]]; then
    has nginx || fail '尚未安装 Nginx。'
    cert_ok "$DOMAIN" || fail "还没有 $DOMAIN 的证书，请先在站点管理里「申请证书」。"
    DIRECT=on
    save_site
    nginx_write_all
    fw_sync_https
    site_self_test
    log "直连已开启：https://$DOMAIN"
  else
    DIRECT=off
    save_site
    nginx_write_all
    fw_sync_https
    log "$DOMAIN 直连已关闭；隧道不受影响，80 端口仅保留证书验证。"
  fi
}

action_site_settings() { # site
  load_site "$1"
  local key value choice
  while true; do
    choice=$(ui_menu "站点参数：$SITE_NAME" '选择要修改的参数（返回时自动写入 Nginx 并生效）：' \
      DOMAIN "直连域名：$DOMAIN" \
      UPSTREAM "上游：$UPSTREAM" \
      PRESET "重新套用预设（当前 $PRESET）" \
      API_RATE "每 IP 每秒请求：$API_RATE" \
      API_BURST "突发：$API_BURST" \
      CONN_LIMIT "每 IP 并发连接：$CONN_LIMIT" \
      BODY_MB "请求体上限 MB：$BODY_MB" \
      PROXY_TIMEOUT "读写超时秒：$PROXY_TIMEOUT" \
      BUFFERING "代理缓冲（流式服务应为 off）：$BUFFERING" \
      AUTH_PATHS "严格限流路径正则：${AUTH_PATHS:-无}" \
      AUTH_RATE "严格路径每 IP 每分钟：$AUTH_RATE" \
      AUTH_BURST "严格路径突发：$AUTH_BURST" \
      HEALTH_PATH "自检路径：$HEALTH_PATH" \
      HSTS "HSTS：$HSTS" \
      back '返回并生效') || choice=back
    [[ -z $choice || $choice == back ]] && break
    if [[ $choice == PRESET ]]; then
      value=$(ui_menu '预设' '会覆盖限流/超时/缓冲/严格路径参数：' newapi 'New API 网关' api 'API / AI 服务' web '普通网站') || continue
      apply_preset "$value"
      save_site
      continue
    fi
    value=$(ui_input "$choice" "新的值（当前：${!choice:-空}）：" "${!choice}") || continue
    key=$choice
    [[ $key == DOMAIN ]] && value=${value,,}
    if ! validate "$key" "$value"; then ui_msg '无效' "$key 的值无效：$value"; continue; fi
    if [[ $key == DOMAIN && $value != "$DOMAIN" ]]; then
      [[ -z $(site_used_by DOMAIN "$value") ]] || { ui_msg '冲突' "$value 已被其他站点使用。"; continue; }
      DIRECT=off
      ui_msg '域名已修改' "新域名需要重新申请证书，直连已自动关闭。\n请在 Cloudflare 添加 $value 的灰云记录，再到站点管理里「申请证书」并开启直连。"
    fi
    printf -v "$key" '%s' "$value"
    [[ $key == PRESET ]] || PRESET=custom
    save_site
  done
  nginx_write_all
  fw_sync_https
}

action_site_delete() { # site
  load_site "$1"
  ui_yesno '删除站点' "删除站点 $SITE_NAME（$DOMAIN -> $UPSTREAM）？\n只移除本脚本的 Nginx 配置，不影响服务本身和 Cloudflare 隧道。\n证书保留在 /etc/letsencrypt，可稍后手动 certbot delete。" no || fail '已取消。'
  backup_path "$(site_file "$SITE_NAME")"
  rm -f "$(site_file "$SITE_NAME")"
  nginx_write_all
  fw_sync_https
  log "站点 $SITE_NAME 已删除。Cloudflare 上的灰云 DNS 记录请自行删除。"
}

site_menu() {
  local site choice
  if [[ -z $(site_names) ]]; then ui_msg '站点管理' '还没有直连站点，请先用菜单 3「添加直连站点」。'; return 0; fi
  site=$(pick_site '选择要管理的站点：') || return 0
  [[ -n $site ]] || return 0
  while [[ -f $(site_file "$site") ]]; do
    choice=$(ui_menu "站点：$site" "$( load_site "$site"; printf '%s -> %s    直连：%s    证书：%s' "$DOMAIN" "$UPSTREAM" "$DIRECT" "$(cert_ok "$DOMAIN" && cert_expiry "$DOMAIN" || echo 未申请)" )" \
      on '开启直连' \
      off '关闭直连' \
      cert '申请/更新证书' \
      settings '参数（限流/超时/域名）' \
      delete '删除站点' \
      back '返回') || return 0
    case $choice in
      on|off) run_menu_action direct "$site" "$choice" ;;
      cert) run_menu_action site-cert "$site" ;;
      settings) run_menu_action site-settings "$site" ;;
      delete) run_menu_action site-delete "$site" ;;
      *) return 0 ;;
    esac
  done
}

action_renew_test() {
  has certbot || fail '尚未安装 certbot。'
  certbot renew --dry-run
}

fw_backup_and_rollback_script() { # backend was_active
  local backend=$1 was_active=$2 script
  ensure_backup_dir
  if [[ $backend == ufw ]]; then
    backup_copy /etc/ufw
    [[ -f /etc/default/ufw ]] && backup_copy /etc/default/ufw
  else
    backup_copy /etc/firewalld
  fi
  script=$BACKUP_DIR/fw-rollback.sh
  {
    printf '#!/bin/sh\n# 由 direct-access.sh 生成：确认超时后把防火墙恢复到修改前。\nB=%q\n' "$BACKUP_DIR"
    if [[ $backend == ufw ]]; then
      [[ $was_active == 0 ]] && printf 'ufw --force disable\n'
      printf 'rm -rf /etc/ufw && cp -a "$B/etc/ufw" /etc/ufw\n'
      printf '[ -f "$B/etc/default/ufw" ] && cp -a "$B/etc/default/ufw" /etc/default/ufw\n'
      [[ $was_active == 1 ]] && printf 'ufw --force enable\n'
    else
      printf 'rm -rf /etc/firewalld && cp -a "$B/etc/firewalld" /etc/firewalld\nfirewall-cmd --reload\n'
    fi
    printf 'logger -t direct-sites "firewall rolled back from $B"\n'
  } > "$script"
  chmod 0700 "$script"
  printf '%s' "$script"
}

action_firewall() {
  local backend ssh_ports listeners items=() port proc addr state keep nets was_active=0 script summary
  backend=$(firewall_backend)
  if [[ $backend == ufw ]] && ! has ufw; then
    log '安装 ufw'
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ufw
  fi
  ssh_ports=$(detect_ssh_ports)
  [[ -n $ssh_ports ]] || fail '检测不到 SSH 端口，为防止锁死，不配置防火墙。'
  listeners=$(public_listeners)
  while read -r port proc addr; do
    [[ -z $port ]] && continue
    if [[ " $ssh_ports " == *" ${port%/*} "* && ${port#*/} == tcp ]]; then continue; fi
    if [[ $port == 80/tcp || $port == 443/tcp ]]; then continue; fi
    state=OFF
    case " $FW_KEEP " in *" $port "*) state=ON ;; esac
    items+=("$port" "$proc $addr" "$state")
  done <<< "$listeners"
  keep=
  if ((${#items[@]})); then
    keep=$(ui_checklist '保留其他公网端口' "默认拒绝所有入站。SSH($ssh_ports)、80、443 由脚本自动处理。\n以下端口当前对外监听，勾选的会对所有 IP 开放。\n经 Cloudflare 隧道或直连站点访问的服务都不用勾选；已有的按 IP 放行规则不受影响。" "${items[@]}") \
      || fail '已取消。'
  fi
  keep=$(xargs <<< "$keep")
  validate FW_KEEP "$keep" || fail "端口列表无效：$keep"
  nets=$(docker_bridge_subnets)
  FW_HTTPS=off
  any_tls_site && FW_HTTPS=on
  summary="防火墙：$backend\n默认：拒绝入站，允许出站\n放行 SSH：$ssh_ports/tcp\n放行 80/tcp（证书验证与跳转）\n443/tcp：$([[ $FW_HTTPS == on ]] && echo 放行 || echo 关闭（没有已开启的直连站点）)\n额外保留：${keep:-无}\nDocker 网桥网段（容器访问宿主机）：${nets:-无}\n\n启用后 ${ROLLBACK_SECONDS} 秒内若不确认，会自动恢复到修改前，防止 SSH 被锁。\n请保持当前窗口，稍后新开一个 SSH 窗口测试登录。"
  ui_yesno '确认防火墙规则' "$summary" || fail '已取消。'
  FW_KEEP=$keep FW_SSH_PORTS=$ssh_ports FW_NETS=$nets
  if [[ $backend == ufw ]]; then
    ufw status | grep -q '^Status: active' && was_active=1
  else
    systemctl is-active --quiet firewalld || fail 'firewalld 未运行。'
    was_active=1
  fi
  script=$(fw_backup_and_rollback_script "$backend" "$was_active")
  systemctl stop "$ROLLBACK_UNIT.timer" 2>/dev/null || true
  systemctl reset-failed "$ROLLBACK_UNIT.service" 2>/dev/null || true
  if ! systemd-run --quiet --unit="$ROLLBACK_UNIT" --on-active="$ROLLBACK_SECONDS" /bin/sh "$script"; then
    ui_yesno '无法设置自动回滚' 'systemd-run 失败，无法设置超时自动恢复。仍要继续吗？' no || fail '已取消。'
  fi
  log "已设置 ${ROLLBACK_SECONDS} 秒后自动回滚（$script）"
  if [[ $backend == ufw ]]; then
    fw_apply_ufw
    for port in $ssh_ports; do ufw show added | grep -q "allow $port/tcp" || fail "SSH $port 规则缺失，停止启用。"; done
    ((was_active)) || ufw --force enable
    ufw status verbose
  else
    fw_apply_firewalld
    firewall-cmd --list-all
  fi
  FIREWALL=$backend
  save_global
  if ui_yesno '确认 SSH 仍可登录' "防火墙已生效。\n请现在新开一个终端，执行和平时一样的 ssh 登录（端口 $ssh_ports）。\n\n能登录选「是」保留规则；不能登录选「否」立即恢复。\n若本窗口断开，${ROLLBACK_SECONDS} 秒后会自动恢复。"; then
    systemctl stop "$ROLLBACK_UNIT.timer" 2>/dev/null || true
    log '已确认，取消自动回滚。'
  else
    systemctl stop "$ROLLBACK_UNIT.timer" 2>/dev/null || true
    /bin/sh "$script"
    FIREWALL=
    save_global
    fail '已按要求恢复防火墙到修改前。'
  fi
}

# Writes the jail, tests and restarts fail2ban.
f2b_apply() { # ssh-ports
  [[ -e $ERROR_LOG ]] || { install -m 0640 -g adm /dev/null "$ERROR_LOG" 2>/dev/null || touch "$ERROR_LOG"; }
  install_file "$F2B_JAIL" 0644 render_f2b "$1" "$F2B_IGNORE"
  if ! fail2ban-client -t; then
    txn_rollback
    fail 'fail2ban 配置检查失败，已恢复原配置。'
  fi
  systemctl enable fail2ban
  systemctl restart fail2ban
  sleep 2
  fail2ban-client status
}

action_fail2ban() {
  has fail2ban-client || fail '尚未安装 fail2ban，请先执行「安装依赖」。'
  local ssh_ports ignore admin
  ssh_ports=$(detect_ssh_ports)
  [[ -n $ssh_ports ]] || fail '检测不到 SSH 端口。'
  ignore=$F2B_IGNORE
  admin=$(awk '{print $1}' <<< "${SSH_CONNECTION:-}")
  if [[ -n $admin && " $ignore " != *" $admin "* ]] \
    && ui_yesno 'fail2ban 白名单' "当前 SSH 来源 IP 为 $admin。\n是否加入 fail2ban 白名单？（家庭宽带 IP 可能会变）" no; then
    ignore=$(xargs <<< "$ignore $admin")
  fi
  ignore=$(ui_input 'fail2ban 白名单' '额外永不封禁的 IP/CIDR，空格分隔（可留空）：' "$ignore") || fail '已取消。'
  ignore=$(xargs <<< "$ignore")
  validate F2B_IGNORE "$ignore" || fail "白名单格式无效：$ignore"
  F2B_IGNORE=$ignore
  save_global
  # An old hand-written jail.local (inline "# comments", /var/log/auth.log) keeps
  # fail2ban from starting on Debian 12; its SSH settings are superseded here.
  if [[ -f $F2B_OLD_LOCAL ]] && ui_yesno '旧 fail2ban 配置' "发现 $F2B_OLD_LOCAL：\n\n$(head -c 1500 "$F2B_OLD_LOCAL")\n\n本脚本的配置已包含 SSH 端口与封禁规则。同一行里的 # 注释会被 fail2ban 当成配置值，Debian 12 也没有 /var/log/auth.log。\n是否备份后停用这个旧文件？（失败会自动恢复）"; then
    remove_path "$F2B_OLD_LOCAL"
  fi
  f2b_apply "$ssh_ports"
}

action_hardening() {
  local choice
  choice=$(ui_checklist '系统加固' '选择要执行的加固项：' \
    sysctl '内核网络参数（SYN Cookie、禁止重定向/源路由等）' ON \
    updates '自动安装 Debian 安全更新（unattended-upgrades，不自动重启）' ON \
    sshroot '禁止 root 直接 SSH 登录（普通用户登录后 su 不受影响）' OFF) || fail '已取消。'
  if [[ " $choice " == *" sysctl "* ]]; then
    install_file "$SYSCTL_FILE" 0644 render_sysctl
    sysctl -e -p "$SYSCTL_FILE" >/dev/null
    log '内核参数已生效。'
  fi
  if [[ " $choice " == *" updates "* ]]; then
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends unattended-upgrades
    install_file "$AUTO_UPGRADES" 0644 render_auto_upgrades
    systemctl enable --now unattended-upgrades 2>/dev/null || true
    log '已启用自动安全更新。'
  fi
  if [[ " $choice " == *" sshroot "* ]]; then
    grep -qsE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config \
      || fail 'sshd_config 没有 Include sshd_config.d，未修改 SSH。'
    [[ -n $(awk -F: '$3 >= 1000 && $3 < 60000 && $7 !~ /(nologin|false)$/' /etc/passwd) ]] \
      || fail '没有可登录的普通用户，为防止无法登录，不禁止 root SSH。'
    TXN=()
    install_file "$SSHD_DROPIN" 0644 render_sshd
    if ! sshd -t; then txn_rollback; fail 'sshd 配置检查失败，已恢复。'; fi
    systemctl reload ssh 2>/dev/null || systemctl reload sshd
    log '已禁止 root 直接 SSH 登录（当前连接不受影响）。'
  fi
}

# ------------------------------------------------------- SSH 登录记录 ----
report_range() { # today|yesterday|7d|30d -> R_SINCE R_UNTIL R_TITLE
  case $1 in
    today) R_SINCE=$(date '+%F 00:00:00') R_UNTIL=$(date -d tomorrow '+%F 00:00:00') R_TITLE="今天（$(date +%F)）" ;;
    yesterday) R_SINCE=$(date -d yesterday '+%F 00:00:00') R_UNTIL=$(date '+%F 00:00:00') R_TITLE="昨天（$(date -d yesterday +%F)）" ;;
    7d) R_SINCE=$(date -d '6 days ago' '+%F 00:00:00') R_UNTIL=$(date -d tomorrow '+%F 00:00:00') R_TITLE='最近 7 天' ;;
    30d) R_SINCE=$(date -d '29 days ago' '+%F 00:00:00') R_UNTIL=$(date -d tomorrow '+%F 00:00:00') R_TITLE='最近 30 天' ;;
    *) fail "未知时间范围：$1（today/yesterday/7d/30d）" ;;
  esac
}

# SSH attempts from the sshd journal plus fail2ban [sshd] bans in [since, until).
# Usage: ssh_report SINCE UNTIL TITLE ROW_LIMIT(0 = all)
ssh_report() {
  local since=$1 until=$2 title=$3 limit=$4 bans raw rows
  bans=$(mktemp) raw=$(mktemp)
  zcat -f /var/log/fail2ban.log* 2>/dev/null \
    | awk -v s="$since" -v u="$until" '/\[sshd\] Ban / { t = $1 " " substr($2, 1, 8); if (t >= s && t < u) print $NF }' > "$bans" || true
  journalctl SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session --since "$since" --until "$until" \
    -o short-iso --no-pager -q 2>/dev/null \
    | awk -v banfile="$bans" '
      # Read bans explicitly: "FNR == NR" breaks when the ban file is empty.
      BEGIN { while ((getline b < banfile) > 0) if (b != "") { ban[b]++; nban++ }; close(banfile) }
      {
        t = substr($0, 1, 19); sub(/T/, " ", t)
        i = index($0, "]: "); if (!i) next
        msg = substr($0, i + 3); ip = ""; user = ""
        m = msg; sub(/ port .*/, "", m); n = split(m, a, " ")
        if (msg ~ /^Accepted /) {
          ok[++nok] = sprintf("  %s  用户 %-12s 来自 %s（%s）", t, a[4], a[6], a[2]); ip = a[6]
        } else if (msg ~ /^Failed [^ ]+ for /) {
          ip = a[n]; user = a[n - 2]; if (user == "user" && a[n - 3] == "invalid") user = "(空)"
          fail[ip]++; tfail++
        } else if (msg ~ /^Invalid user /) {
          ip = a[n]; user = (n >= 5 ? a[3] : "(空)"); inv[ip]++; tinv++
        } else if (msg ~ /^Connection (closed|reset) by [0-9a-fA-F.:]+ port [0-9]+( \[preauth\])?$/ \
            || msg ~ /^(Did not receive identification|banner exchange|Timeout before authentication|Unable to negotiate with|ssh_dispatch_run_fatal: Connection from)/) {
          # Only connections that never tried a user/password; the "[preauth]"
          # lines that follow every failed login are not counted again.
          if (match(msg, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[0-9a-fA-F]+:[0-9a-fA-F:]*:[0-9a-fA-F]+/)) {
            ip = substr(msg, RSTART, RLENGTH); probe[ip]++; tprobe++
          }
        } else next
        if (ip == "") next
        if (!(ip in first)) first[ip] = t
        last[ip] = t
        if (user != "" && !((ip, user) in seenu) && nu[ip] < 6) { seenu[ip, user] = 1; nu[ip]++; users[ip] = users[ip] (nu[ip] > 1 ? "," : "") user }
      }
      END {
        nip = 0
        for (ip in first) {
          total = fail[ip] + inv[ip] + probe[ip]
          if (!total) continue
          nip++
          printf "ROW\t%d\t%-39s %6d %6d %6d  %s  %s  %s%s\n", total, ip, fail[ip], inv[ip], probe[ip],
            substr(first[ip], 6, 11), substr(last[ip], 6, 11), (users[ip] == "" ? "-" : users[ip]),
            (ip in ban ? "  【已封禁 " ban[ip] " 次】" : "")
        }
        printf "SUM\t密码/密钥验证失败：%d 次    不存在的用户名：%d 次    未认证的探测连接：%d 次\n", tfail, tinv, tprobe
        printf "SUM\t来源 IP：%d 个    fail2ban 封禁 SSH：%d 次（%d 个 IP）    成功登录：%d 次\n", nip, nban, length(ban), nok
        for (k = 1; k <= nok; k++) print "OK\t" ok[k]
      }' > "$raw" || true
  rows=$(grep -c '^ROW' "$raw" || true)
  printf 'SSH 登录记录：%s\n时段：%s ~ %s\n\n' "$title" "$since" "$until"
  grep '^SUM' "$raw" | cut -f2-
  printf '\n[成功登录]（请确认都是你自己）\n'
  grep '^OK' "$raw" | cut -f2- || true
  grep -q '^OK' "$raw" || printf '  无\n'
  printf '\n[尝试登录的 IP]（按次数排序%s）\n' "$([[ $limit -gt 0 && $rows -gt $limit ]] && echo "，只显示前 $limit 个，共 $rows 个" || true)"
  printf '%-39s %6s %6s %6s  %-11s  %-11s  %s\n' 'IP' '失败' '无效名' '探测' '首次' '最近' '尝试的用户名'
  if ((rows)); then
    grep '^ROW' "$raw" | sort -t$'\t' -k2,2nr | cut -f3- | { if ((limit)); then head -n "$limit"; else cat; fi; }
  else
    printf '  无\n'
  fi
  if [[ ! -d /var/log/journal ]]; then
    printf '\n注意：systemd 日志未持久化，重启后之前的记录会丢失；可在菜单里开启「每日自动记录」。\n'
  fi
  rm -f "$bans" "$raw"
}

action_ssh_report_daily() { # run by the systemd timer: saves yesterday's full report
  local day
  day=$(date -d yesterday +%F)
  report_range yesterday
  mkdir -p "$SSH_REPORT_DIR"
  chmod 0700 "$SSH_REPORT_DIR"
  ssh_report "$R_SINCE" "$R_UNTIL" "$R_TITLE" 0 > "$SSH_REPORT_DIR/$day.txt"
  chmod 0600 "$SSH_REPORT_DIR/$day.txt"
  find "$SSH_REPORT_DIR" -name '*.txt' -type f -mtime +"$REPORT_KEEP_DAYS" -delete
}

render_report_service() {
  cat << EOF
[Unit]
Description=Daily SSH login attempt report (direct-access.sh)

[Service]
Type=oneshot
ExecStart=$REPORT_BIN --action ssh-report-daily
EOF
}

render_report_timer() {
  cat << 'EOF'
[Unit]
Description=Daily SSH login attempt report (direct-access.sh)

[Timer]
OnCalendar=*-*-* 00:10:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

action_ssh_report_setup() {
  ui_yesno '每日自动记录' "每天 00:10 把前一天所有尝试登录 SSH 的 IP、次数、用户名和封禁情况保存到\n$SSH_REPORT_DIR/日期.txt，保留 ${REPORT_KEEP_DAYS} 天。\n定时任务调用 $REPORT_BIN（dsite update 后自动使用新版本）。$([[ -d /var/log/journal ]] || printf '\n\n同时开启 systemd 日志持久化（/var/log/journal），重启后记录不丢失。')" || fail '已取消。'
  [[ $SELF == "$REPORT_BIN" ]] || install_self "$SELF"
  install_file "/etc/systemd/system/$REPORT_UNIT.service" 0644 render_report_service
  install_file "/etc/systemd/system/$REPORT_UNIT.timer" 0644 render_report_timer
  if [[ ! -d /var/log/journal ]]; then
    mkdir -p /var/log/journal
    systemd-tmpfiles --create --prefix /var/log/journal
    systemctl restart systemd-journald
    log '已开启 systemd 日志持久化。'
  fi
  systemctl daemon-reload
  systemctl enable --now "$REPORT_UNIT.timer"
  [[ -f $SSH_REPORT_DIR/$(date -d yesterday +%F).txt ]] || action_ssh_report_daily
  log "已开启每日记录，文件在 $SSH_REPORT_DIR/"
}

action_ssh_report() {
  local choice out file items=()
  choice=$(ui_menu 'SSH 登录 / 爆破记录' "统计 sshd 日志里的登录失败、无效用户名、未认证探测，以及 fail2ban 封禁。\n每日记录：$(systemctl is-active "$REPORT_UNIT.timer" 2>/dev/null || true)" \
    today '今天' \
    yesterday '昨天' \
    7d '最近 7 天' \
    30d '最近 30 天（取决于日志保留）' \
    saved '查看已保存的每日记录' \
    setup '开启每日自动记录（保存到文件）') || return 0
  case $choice in
    setup) action_ssh_report_setup; return 0 ;;
    saved)
      for file in $(ls -1r "$SSH_REPORT_DIR"/*.txt 2>/dev/null | head -n 60); do
        items+=("$(basename "$file" .txt)" "$(sed -n '5p' "$file")")
      done
      ((${#items[@]})) || fail "还没有保存的记录（$SSH_REPORT_DIR），请先开启每日自动记录。"
      choice=$(ui_menu '已保存的每日记录' '选择日期：' "${items[@]}") || return 0
      ui_textfile "SSH 登录记录 $choice" "$SSH_REPORT_DIR/$choice.txt"
      return 0 ;;
  esac
  report_range "$choice"
  out=$(mktemp)
  ssh_report "$R_SINCE" "$R_UNTIL" "$R_TITLE" 200 > "$out"
  ui_textfile "SSH 登录记录：$R_TITLE" "$out"
  rm -f "$out"
}

security_group_text() {
  local ssh_ports=${RENDER_SSH_PORTS:-22} ip='' name domains=''
  if ! ((RENDER)); then ssh_ports=$(detect_ssh_ports) ip=$(public_ip); fi
  for name in $(site_names); do domains+="$( load_site "$name"; printf '    %s -> %s（直连：%s）' "$DOMAIN" "$UPSTREAM" "$DIRECT" )"$'\n'; done
  cat << EOF
云厂商「安全组 / 防火墙」在服务器外面，和本脚本配置的 ufw/firewalld 是两层，都要放行。

【入方向（Inbound）需要放行】
  TCP 80    来源 0.0.0.0/0（有 IPv6 再加 ::/0）  证书签发/自动续期、http 跳转 https
  TCP 443   来源 0.0.0.0/0（有 IPv6 再加 ::/0）  所有直连站点共用
  TCP ${ssh_ports:-SSH端口}  保持现有规则，不要删除；条件允许时只放行你的常用 IP

  所有直连站点共用 80/443，新增站点不用再改安全组。

【不要放行】
  各服务自己的端口（如 3000、8080）、数据库和 Redis 端口。用户只通过 443 访问，
  服务端口保持只给本机/隧道/指定 IP 使用。

【出方向（Outbound）】保持全部允许（Cloudflare 隧道、上游接口、证书续期都要出站）。

【控制台操作步骤】（各厂商大体相同）
  1. 登录云控制台，找到公网 IP 为 ${ip:-本服务器 IP} 的实例。
  2. 进入「安全组」（有的叫「防火墙」「网络与安全」「Firewall」）。
  3. 入方向规则 → 添加规则：策略 允许，协议 TCP，端口 80，来源 0.0.0.0/0。
  4. 同样添加 TCP 443；控制台支持 IPv6 时各再加一条来源 ::/0。
  5. 保存后，在浏览器打开 https://直连域名 验证。

【Cloudflare】每个直连域名都要在 DNS 里加一条 A 记录指向 ${ip:-本机 IP}，
  代理状态选「仅 DNS」（灰云）。原来的橙云隧道域名不用改。
  灰云会暴露服务器真实 IP，请务必完成防火墙与 fail2ban。

【当前直连站点】
${domains:-    无}
EOF
}

action_security_group() {
  local out
  out=$(mktemp)
  security_group_text > "$out"
  ui_textfile '云厂商安全组放行说明' "$out"
  rm -f "$out"
}

action_status() {
  local out name jail
  out=$(mktemp)
  {
    printf '防火墙：%s    证书邮箱：%s\n\n' "${FIREWALL:-未配置}" "${EMAIL:-未设置}"
    printf '[Nginx] %s\n' "$(systemctl is-active nginx 2>/dev/null || true)"
    has nginx && nginx -t 2>&1 | sed 's/^/  /'
    printf '  证书自动续期：%s\n' "$(systemctl is-active certbot.timer 2>/dev/null || true)"
    printf '\n[直连站点]\n'
    for name in $(site_names); do
      (
        load_site "$name"
        printf '  %s  %s -> %s（%s）\n' "$SITE_NAME" "$DOMAIN" "$UPSTREAM" "${SOURCE:-手动}"
        printf '    直连：%s    预设：%s    证书：%s\n' "$DIRECT" "$PRESET" "$(cert_ok "$DOMAIN" && cert_expiry "$DOMAIN" || echo 未申请)"
        printf '    本机服务：HTTP %s' "$(http_code "http://$UPSTREAM$HEALTH_PATH")"
        site_tls && printf '    经 Nginx HTTPS：HTTP %s' "$(https_probe)"
        printf '\n'
        f=/var/log/nginx/direct-site-$SITE_NAME.access.log
        [[ -f $f ]] && printf '    最近 5000 条访问中被限流(429)：%s\n' "$(tail -n 5000 "$f" | awk '$9 == 429' | wc -l)"
        true
      )
    done
    [[ -n $(site_names) ]] || printf '  无\n'
    printf '\n[防火墙]\n'
    case $FIREWALL in
      ufw) ufw status verbose 2>&1 | sed 's/^/  /' ;;
      firewalld) firewall-cmd --list-all 2>&1 | sed 's/^/  /' ;;
      *) printf '  未由本脚本配置\n' ;;
    esac
    printf '\n[fail2ban] %s\n' "$(systemctl is-active fail2ban 2>/dev/null || true)"
    if has fail2ban-client; then
      for jail in sshd nginx-limit-req; do fail2ban-client status "$jail" 2>&1 | sed 's/^/  /'; done
    fi
    printf '\n[公网监听端口]\n'
    public_listeners | sed 's/^/  /'
  } > "$out" 2>&1
  ui_textfile '状态与诊断' "$out"
  rm -f "$out"
}

action_bans() {
  has fail2ban-client || fail '尚未安装 fail2ban。'
  local out ip jail ips
  out=$(mktemp)
  {
    printf '当前被 fail2ban 封禁的 IP（到期自动解封；历史封禁见菜单 14）\n'
    for jail in $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' '); do
      ips=$(fail2ban-client get "$jail" banip 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9A-Fa-f:.]+$' || true)
      printf '\n[%s] %s 个\n' "$jail" "$(grep -c . <<< "$ips" || true)"
      [[ -n $ips ]] && sed 's/^/  /' <<< "$ips"
    done
    true
  } > "$out" 2>&1
  ui_textfile '当前封禁' "$out"
  rm -f "$out"
  ip=$(ui_input '解封 IP' '输入要解封的 IP（留空返回）：' '') || return 0
  [[ -z $ip ]] && return 0
  [[ $ip =~ ^[0-9A-Fa-f:.]+$ ]] || fail "IP 格式无效：$ip"
  fail2ban-client unban "$ip"
  log "已解封 $ip"
}

action_global_settings() {
  local email
  email=$(ui_input '证书邮箱' "Let's Encrypt 到期提醒邮箱（所有站点共用，可留空）：" "$EMAIL") || return 0
  validate EMAIL "$email" || fail "邮箱格式无效：$email"
  EMAIL=$email
  save_global
  log '已保存。'
}

action_server_setup() {
  ui_yesno '服务器首次部署' "将依次执行：安装依赖 → 防火墙 → fail2ban → 系统加固，然后引导添加第一个直连站点。\n每步失败会停止，已完成的步骤保留。\n不会重启或修改任何容器、数据库和 Cloudflare 隧道。" || return 0
  local step
  for step in install nginx firewall fail2ban hardening; do
    log "步骤：$step"
    sub_action "$step" || fail "步骤 $step 失败，已停止。"
  done
  if ui_yesno '添加站点' '服务器防护已完成。现在添加一个直连站点吗？'; then sub_action add-site || fail '添加站点未完成。'; fi
  sub_action security-group || true
}

# Each action runs in its own bash process so `set -e` and rollback apply.
sub_action() { "$BASH" "$SELF" --action "$@"; }

run_menu_action() {
  local rc=0
  clear 2>/dev/null || true
  sub_action "$@" || rc=$?
  load_global
  if ((rc)); then printf '\n操作未完成（退出码 %s），详情见上方输出。\n' "$rc"; else printf '\n完成。\n'; fi
  pause
}

main_menu() {
  local choice sites
  while true; do
    sites=$(site_names | wc -l)
    choice=$(ui_menu "dsite 灰云直连管理 $DSITE_VERSION" "直连站点：$sites 个    防火墙：${FIREWALL:-未配置}    fail2ban：$(systemctl is-active fail2ban 2>/dev/null || true)" \
      1 '环境检查（只读，含可直连的 Docker 服务）' \
      2 '服务器首次部署（依赖→防火墙→fail2ban→加固→添加站点）' \
      3 '添加直连站点（选择 Docker 服务）' \
      4 '站点管理（开/关直连、证书、参数、删除）' \
      5 '安装依赖（nginx/certbot/fail2ban/ufw）' \
      6 '配置防火墙（带自动回滚）' \
      7 '配置 fail2ban' \
      8 '系统加固' \
      9 '刷新全部 Nginx 配置' \
      10 '测试证书自动续期' \
      11 'fail2ban 封禁列表 / 解封 IP' \
      12 '云厂商安全组放行说明' \
      13 '状态与诊断' \
      14 'SSH 登录 / 爆破记录（每天哪些 IP 在试密码）' \
      15 '证书邮箱' \
      16 "更新 dsite（当前 $DSITE_VERSION）" \
      0 '退出') || return 0
    case $choice in
      1) sub_action check || true ;;
      2) run_menu_action server-setup ;;
      3) run_menu_action add-site ;;
      4) site_menu ;;
      5) run_menu_action install ;;
      6) run_menu_action firewall ;;
      7) run_menu_action fail2ban ;;
      8) run_menu_action hardening ;;
      9) run_menu_action nginx ;;
      10) run_menu_action renew-test ;;
      11) run_menu_action bans ;;
      12) sub_action security-group || true ;;
      13) sub_action status || true ;;
      14) run_menu_action ssh-report ;;
      15) run_menu_action global-settings ;;
      16) clear 2>/dev/null || true
        if "$BASH" "$SELF" update; then pause; exec "$BASH" "$DSITE_BIN"; fi
        pause ;;
      0|'') return 0 ;;
    esac
  done
}

dispatch() {
  case $1 in
    check) action_check ;;
    server-setup) action_server_setup ;;
    add-site) action_add_site ;;
    direct) action_site_direct "$2" "$3" ;;
    site-cert) action_site_cert "$2" ;;
    site-settings) action_site_settings "$2" ;;
    site-delete) action_site_delete "$2" ;;
    install) action_install ;;
    nginx) action_nginx ;;
    renew-test) action_renew_test ;;
    firewall) action_firewall ;;
    fail2ban) action_fail2ban ;;
    hardening) action_hardening ;;
    bans) action_bans ;;
    security-group) action_security_group ;;
    status) action_status ;;
    global-settings) action_global_settings ;;
    f2b-refresh) f2b_apply "$(detect_ssh_ports)" ;;
    ssh-report) action_ssh_report ;;
    ssh-report-daily) action_ssh_report_daily ;;
    ssh-report-setup) action_ssh_report_setup ;;
    *) fail "未知操作：$1" ;;
  esac
}

# Offline rendering for tests/review; needs no root and changes nothing.
render_all() { # dir
  local dir=$1 name
  RENDER=1
  mkdir -p "$dir"
  R_DEFAULT=${RENDER_DEFAULT:-1} R_IPV6=${RENDER_IPV6:-1} R_HTTP2NEW=${RENDER_HTTP2NEW:-0} R_ANY_TLS=0
  any_tls_site && R_ANY_TLS=1
  render_nginx_http > "$dir/direct-sites-http.conf"
  render_nginx_default > "$dir/direct-sites-default.conf"
  for name in $(site_names); do render_site_by_name "$name" > "$dir/direct-site-$name.conf"; done
  render_f2b "${RENDER_SSH_PORTS:-22}" "$F2B_IGNORE" > "$dir/direct-sites.local"
  render_sysctl > "$dir/sysctl.conf"
  DRY_RUN=1 FW_SSH_PORTS=${RENDER_SSH_PORTS:-22} FW_NETS=${RENDER_DOCKER_NETS:-172.17.0.0/16} FW_HTTPS=off
  any_tls_site && FW_HTTPS=on
  fw_apply_ufw > "$dir/firewall-ufw.txt"
  fw_apply_firewalld > "$dir/firewall-firewalld.txt"
  security_group_text > "$dir/security-group.txt"
}

# ------------------------------------------------------- 安装与更新 ----
raw_url() { printf 'https://raw.githubusercontent.com/%s/%s/%s' "$DSITE_REPO" "$DSITE_REF" "$1"; }

fetch() { # url dest
  if has curl; then curl -fsSL --retry 2 --max-time 60 "$1" -o "$2"
  elif has wget; then wget -q -T 60 -O "$2" "$1"
  else fail '需要 curl 或 wget。'; fi
}

# Installs a downloaded/local copy as $DSITE_BIN atomically (a running copy
# keeps its old inode), then points the daily report timer at it.
install_self() { # source-file
  local src=$1 tmp
  grep -q '^DSITE_VERSION=' "$src" && bash -n "$src" || fail "$src 不是有效的 dsite 脚本。"
  tmp=$(mktemp "$DSITE_BIN.XXXXXX")
  cat "$src" > "$tmp"
  chmod 0755 "$tmp"
  mv -f "$tmp" "$DSITE_BIN"
  post_install
}

# The daily report timer used to run $OLD_REPORT_BIN; move it to $DSITE_BIN.
post_install() {
  local unit=/etc/systemd/system/$REPORT_UNIT.service
  if [[ -f $unit ]] && ! grep -q "ExecStart=$REPORT_BIN " "$unit"; then
    install_file "$unit" 0644 render_report_service
    systemctl daemon-reload
    log "每日 SSH 记录改用 $REPORT_BIN"
  fi
  if [[ -f $OLD_REPORT_BIN ]] && grep -q 'direct-access.sh' "$OLD_REPORT_BIN"; then
    rm -f "$OLD_REPORT_BIN"
    log "已移除旧副本 $OLD_REPORT_BIN"
  fi
  return 0
}

self_update() {
  local tmp new
  tmp=$(mktemp)
  log "下载 $(raw_url direct-access.sh)"
  fetch "$(raw_url direct-access.sh)" "$tmp" || { rm -f "$tmp"; fail '下载失败，现有版本不受影响。'; }
  new=$(sed -n 's/^DSITE_VERSION=//p' "$tmp" | head -1)
  install_self "$tmp"
  rm -f "$tmp"
  log "dsite 已更新：$DSITE_VERSION -> ${new:-未知}"
}

usage() {
  cat << 'EOF'
dsite：给 Docker 等本机服务加灰云（仅 DNS）直连，并统一做服务器防护。

用法（root）：
  dsite                      打开菜单
  dsite list                 列出直连站点
  dsite on|off 站点名        开启/关闭某个站点的直连
  dsite status | check       状态与诊断 / 环境检查（只读）
  dsite ssh-report [today|yesterday|7d|30d] [行数，0=全部]
                             SSH 登录 / 爆破记录
  dsite update               从 GitHub 更新到最新版
  dsite version              显示版本
离线（无需 root，不改系统）：
  DIRECT_SITES_ROOT=目录 dsite --render 输出目录
EOF
}

main() {
  load_global
  case ${1:-menu} in
    --render) [[ -n ${2:-} ]] || { usage; exit 1; }; render_all "$2"; return 0 ;;
    -h|--help|help) usage; return 0 ;;
    version|-v|--version) printf 'dsite %s（%s）\n' "$DSITE_VERSION" "$SELF"; return 0 ;;
  esac
  require_root
  # Actions re-run this file in child processes, so it must be a real file.
  [[ -f $SELF ]] || fail "请先安装再运行：curl -fsSL $(raw_url install.sh) | bash"
  case ${1:-menu} in
    --action) ui_init; shift; dispatch "$@" ;;
    --install-self) install_self "$SELF" ;;
    update) self_update ;;
    menu) ui_init
      if ((!HAVE_UI)) && [[ -t 0 ]] && ! has whiptail; then
        apt-get install -y whiptail >/dev/null 2>&1 && ui_init || true
      fi
      # Running a newer local copy updates the installed command and the timer.
      if [[ $SELF != "$DSITE_BIN" && -f $DSITE_BIN ]] && ! cmp -s "$SELF" "$DSITE_BIN"; then install_self "$SELF"; fi
      post_install
      main_menu ;;
    ssh-report) report_range "${2:-today}"
      [[ ${3:-200} =~ ^[0-9]+$ ]] || fail "显示行数必须是数字：$3"
      ssh_report "$R_SINCE" "$R_UNTIL" "$R_TITLE" "${3:-200}" ;;
    list) for name in $(site_names); do ( load_site "$name"; printf '%-12s %-32s -> %-16s 直连：%s\n' "$SITE_NAME" "$DOMAIN" "$UPSTREAM" "$DIRECT" ); done ;;
    on|off) ui_init
      [[ -n ${2:-} && -f $(site_file "$2") ]] || fail "站点不存在：${2:-未指定}（用 dsite list 查看）"
      dispatch direct "$2" "$1" ;;
    status|check) ui_init; dispatch "$1" ;;
    *) usage; exit 1 ;;
  esac
}

main "$@"
