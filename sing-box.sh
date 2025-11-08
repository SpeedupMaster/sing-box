#!/usr/bin/env bash
# 一键安装/更新/卸载 sing-box（VLESS + REALITY）+ 安装/启用 BBR+fq
# 支持远程短命令：sudo bash <(curl -fsSL https://your-domain/path/setup-vless-reality.sh)
# 或：sudo bash <(wget -qO- https://your-domain/path/setup-vless-reality.sh)
# 安装后快捷命令：singbox
# Tested on: Debian 11/12, Ubuntu 20.04/22.04/24.04, CentOS/Alma/Rocky 8/9
# Architecture: amd64, arm64

set -euo pipefail
umask 022

#-----------------------------
# Constants
#-----------------------------
BIN_PATH="/usr/local/bin/sing-box"
CFG_DIR="/etc/sing-box"
CFG_PATH="${CFG_DIR}/config.json"
META_PATH="${CFG_DIR}/reality.meta.json"
SVC_PATH="/etc/systemd/system/sing-box.service"
SYSCTL_FILE="/etc/sysctl.d/99-bbr-fq.conf"
SELF_PATH="/usr/local/bin/singboxctl"
LINK_PATH="/usr/local/bin/singbox"

#-----------------------------
# Helpers
#-----------------------------
is_root() { [ "${EUID:-$(id -u)}" -eq 0 ]; }
err() { echo -e "\033[31m[ERROR]\033[0m $*" >&2; exit 1; }
info() { echo -e "\033[32m[INFO]\033[0m $*"; }
warn() { echo -e "\033[33m[WARN]\033[0m $*"; }

detect_os() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=${ID:-}
    OS_VERSION_ID=${VERSION_ID:-}
    OS_CODENAME=${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}
  else
    err "无法检测操作系统，缺少 /etc/os-release"
  fi
}

detect_arch() {
  local m; m=$(uname -m)
  case "$m" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) err "不支持的架构: $m （仅支持 amd64/arm64）" ;;
  esac
}

install_deps() {
  info "安装必要依赖 (curl, tar, jq, openssl, ca-certificates, systemd, iproute/ss)..."
  case "${OS_ID}" in
    debian|ubuntu)
      apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y curl tar jq openssl ca-certificates systemd iproute2
      ;;
    centos|almalinux|rocky)
      yum install -y curl tar jq openssl ca-certificates systemd iproute || dnf install -y curl tar jq openssl ca-certificates systemd iproute
      ;;
    *)
      warn "未知系统 ${OS_ID}，尝试使用通用方案安装依赖"
      apt-get update -y || true
      apt-get install -y curl tar jq openssl ca-certificates systemd iproute2 || true
      ;;
  esac
}

ask_with_default() {
  local prompt default var
  prompt="$1"; default="$2"
  read -rp "$prompt [$default]: " var || true
  echo "${var:-$default}"
}

yes_or_no() {
  local prompt default ans
  prompt="$1"; default="${2:-Y}"
  read -rp "$prompt [$default]: " ans || true
  ans="${ans:-$default}"
  [[ "$ans" =~ ^[Yy]$ ]]
}

get_public_ip() {
  (curl -fsSL https://api.ipify.org || curl -fsSL https://ipinfo.io/ip || curl -fsSL https://ifconfig.me) 2>/dev/null || true
}

port_busy() {
  local port="$1"
  ss -tuln 2>/dev/null | awk '{print $5}' | grep -E "[:.]${port}\$" >/dev/null 2>&1
}

download_latest_singbox() {
  local tmpdir api_json url name bindir
  tmpdir=$(mktemp -d)
  info "获取 sing-box 最新版本..."
  api_json=$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest) || err "无法访问 GitHub API（可能网络受限或限速）"
  url=$(echo "$api_json" | jq -r --arg arch "$ARCH" '.assets[] | select(.name | (contains("linux-"+$arch) and endswith(".tar.gz"))) | .browser_download_url' | head -n1)
  name=$(echo "$api_json" | jq -r '.name')
  [ -n "$url" ] || err "未能找到 sing-box 的下载地址（assets 匹配失败）"
  info "下载：$name / $url"
  curl -fsSL "$url" -o "$tmpdir/singbox.tar.gz" || err "下载失败"
  tar -xzf "$tmpdir/singbox.tar.gz" -C "$tmpdir"
  bindir=$(find "$tmpdir" -type f -name "sing-box" -printf "%h\n" | head -n1)
  [ -n "$bindir" ] || err "未找到 sing-box 可执行文件"
  install -m 0755 "$bindir/sing-box" "$BIN_PATH"
  info "sing-box 已安装到 $BIN_PATH"
}

# --- vvv ROBUST PARSING FUNCTIONS vvv ---
# 解析 Reality key 输出（兼容彩色/同一行/下一行/JSON）
parse_reality_keys() {
  local text="$1"
  # 去除 CR 和 ANSI 颜色转义
  local clean
  clean=$(printf "%s" "$text" | tr -d '\r' | sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g')

  # 1) JSON 解析
  if echo "$clean" | jq -e . >/dev/null 2>&1; then
    SB_PRIV_KEY=$(echo "$clean" | jq -r '.private_key // .priv // empty')
    SB_PUB_KEY=$(echo "$clean"  | jq -r '.public_key  // .pub  // empty')
    if [ -n "${SB_PRIV_KEY:-}" ] && [ -n "${SB_PUB_KEY:-}" ]; then
      return 0
    fi
  fi

  # 2) 同一行 "Private Key: X" / "Public Key: Y"
  local priv pub
  priv=$(echo "$clean" | awk 'BEGIN{IGNORECASE=1} /private[[:space:]]*key/ { if (match($0, /:[[:space:]]*([A-Za-z0-9_\-+=/]+)/, m)) { print m[1]; exit } }')
  pub=$(echo "$clean" | awk 'BEGIN{IGNORECASE=1} /public[[:space:]]*key/ { if (match($0, /:[[:space:]]*([A-Za-z0-9_\-+=/]+)/, m)) { print m[1]; exit } }')
  if [ -n "$priv" ] && [ -n "$pub" ]; then
    SB_PRIV_KEY="$priv"
    SB_PUB_KEY="$pub"
    return 0
  fi

  # 3) 下一行才是值
  priv=$(echo "$clean" | awk 'BEGIN{IGNORECASE=1} /private[[:space:]]*key/ {getline; gsub(/^[[:space:]]+|[[:space:]]+$/,""); print; exit}')
  pub=$(echo "$clean" | awk 'BEGIN{IGNORECASE=1} /public[[:space:]]*key/ {getline; gsub(/^[[:space:]]+|[[:space:]]+$/,""); print; exit}')
  if [ -n "$priv" ] && [ -n "$pub" ]; then
    SB_PRIV_KEY="$priv"
    SB_PUB_KEY="$pub"
    return 0
  fi
}

generate_values() {
  info "正在生成节点参数..."
  # UUID
  if command -v uuidgen >/dev/null 2>&1; then
    SB_UUID=$(uuidgen)
  else
    SB_UUID=$(cat /proc/sys/kernel/random/uuid)
  fi

  # Reality keypair（安全执行，避免脚本中断）
  local rk_output
  rk_output=$(NO_COLOR=1 "$BIN_PATH" generate reality-keypair 2>&1 || true)
  
  if [ -z "$rk_output" ]; then
    err "sing-box generate reality-keypair 命令执行失败或无任何输出。"
  fi

  parse_reality_keys "$rk_output"

  if [ -z "${SB_PRIV_KEY:-}" ] || [ -z "${SB_PUB_KEY:-}" ]; then
    echo "[DEBUG] sing-box reality-keypair 输出如下：" >&2
    echo "--------------------------------" >&2
    echo "$rk_output" >&2
    echo "--------------------------------" >&2
    err "生成 Reality 密钥失败（无法从命令输出中解析到 Private/Public Key）"
  fi

  # short_id
  SB_SHORT_ID=$(openssl rand -hex 8)

  info "参数生成完成。"
}
# --- ^^^ ROBUST PARSING FUNCTIONS ^^^ ---

write_config() {
  mkdir -p "$CFG_DIR"
  cat > "$CFG_PATH" <<EOF
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality-in",
      "listen": "::",
      "listen_port": ${SB_LISTEN_PORT},
      "users": [
        { "uuid": "${SB_UUID}", "flow": "xtls-rprx-vision" }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${SB_SNI_DOMAIN}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "${SB_SNI_DOMAIN}", "server_port": ${SB_HANDSHAKE_PORT} },
          "private_key": "${SB_PRIV_KEY}",
          "short_id": ["${SB_SHORT_ID}"]
        }
      }
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ]
}
EOF
  info "配置文件已写入：$CFG_PATH"
  "$BIN_PATH" check -c "$CFG_PATH" || err "配置校验失败，请检查配置项"
}

persist_meta() {
  cat > "$META_PATH" <<EOF
{
  "uuid": "${SB_UUID}",
  "priv_key": "${SB_PRIV_KEY}",
  "pub_key": "${SB_PUB_KEY}",
  "short_id": "${SB_SHORT_ID}",
  "listen_port": ${SB_LISTEN_PORT},
  "sni_domain": "${SB_SNI_DOMAIN}",
  "handshake_port": ${SB_HANDSHAKE_PORT},
  "client_server_addr": "${CLIENT_SERVER_ADDR}",
  "updated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
  info "参数已保存：$META_PATH"
}

setup_systemd() {
  cat > "$SVC_PATH" <<'EOF'
[Unit]
Description=sing-box service (VLESS REALITY)
After=network.target

[Service]
Type=simple
User=root
Group=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now sing-box
  systemctl status sing-box --no-pager -l || true
  info "systemd 服务已启动：sing-box"
}

open_firewall_port() {
  local port="$1"
  if command -v ufw >/dev/null 2>&1; then
    warn "检测到 ufw，开放端口 $port"
    ufw allow "$port"/tcp || true
    ufw allow "$port"/udp || true
  elif command -v firewall-cmd >/dev/null 2>&1; then
    warn "检测到 firewalld，开放端口 $port"
    firewall-cmd --add-port="${port}/tcp" --permanent || true
    firewall-cmd --add-port="${port}/udp" --permanent || true
    firewall-cmd --reload || true
  else
    warn "未检测到常见防火墙（ufw/firewalld），如有其它防火墙请手动放行端口 $port"
  fi
}

close_firewall_port() {
  local port="$1"
  if command -v ufw >/dev/null 2>&1; then
    warn "尝试回收 ufw 端口 $port"
    ufw delete allow "$port"/tcp || true
    ufw delete allow "$port"/udp || true
  elif command -v firewall-cmd >/dev/null 2>&1; then
    warn "尝试回收 firewalld 端口 $port"
    firewall-cmd --remove-port="${port}/tcp" --permanent || true
    firewall-cmd --remove-port="${port}/udp" --permanent || true
    firewall-cmd --reload || true
  fi
}

gen_vless_link() {
  local name="${1:-VLESS-REALITY}"
  local pbk sid sni uuid addr port
  pbk=$(jq -r '.pub_key' "$META_PATH")
  sid=$(jq -r '.short_id' "$META_PATH")
  sni=$(jq -r '.sni_domain' "$META_PATH")
  uuid=$(jq -r '.uuid' "$META_PATH")
  addr=$(jq -r '.client_server_addr' "$META_PATH")
  port=$(jq -r '.listen_port' "$META_PATH")
  # URL encode the name
  name=$(echo "$name" | jq -sRr @uri)
  echo "vless://${uuid}@${addr}:${port}?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&pbk=${pbk}&sid=${sid}&sni=${sni}&fp=chrome#${name}"
}

print_client_guide() {
  local meta_addr meta_port meta_uuid meta_pub meta_sid meta_sni
  meta_addr=$(jq -r '.client_server_addr' "$META_PATH")
  meta_port=$(jq -r '.listen_port' "$META_PATH")
  meta_uuid=$(jq -r '.uuid' "$META_PATH")
  meta_pub=$(jq -r '.pub_key' "$META_PATH")
  meta_sid=$(jq -r '.short_id' "$META_PATH")
  meta_sni=$(jq -r '.sni_domain' "$META_PATH")

  cat <<EOF

============================================================
VLESS REALITY 节点信息（用于客户端）：
------------------------------------------------------------
地址（server）：    ${meta_addr}
端口（port）：       ${meta_port}
UUID（id）：         ${meta_uuid}
传输（transport）：  TCP
加密（security）：   reality（TLS 伪装）
flow：               xtls-rprx-vision
SNI（server_name）： ${meta_sni}
Reality public_key： ${meta_pub}
Reality short_id：   ${meta_sid}

vless 导入链接（可直接复制到 v2rayN/v2rayNG 等）：
$(gen_vless_link "VLESS-REALITY")

示例（sing-box 客户端 outbound 配置片段）：
{
  "type": "vless",
  "server": "${meta_addr}",
  "server_port": ${meta_port},
  "uuid": "${meta_uuid}",
  "flow": "xtls-rprx-vision",
  "tls": {
    "enabled": true,
    "server_name": "${meta_sni}",
    "reality": {
      "enabled": true,
      "public_key": "${meta_pub}",
      "short_id": "${meta_sid}"
    }
  }
}

提示：
- 握手域名应为可正常提供 TLS 的真实站点（如：www.cloudflare.com / www.bing.com / www.wikipedia.org）
- 如果服务器已有 Nginx 占用 443，建议使用 8443 或参考“与 Nginx 共享 443（进阶）”
- 查看日志：journalctl -u sing-box -f
============================================================
EOF
}

#-----------------------------
# BBR + fq
#-----------------------------
kernel_info() {
  uname -r
}

has_bbr() {
   # BBR 模块已加载
  if lsmod | grep -q "tcp_bbr"; then
    return 0
  fi
  # sysctl 可用列表里有 bbr
  if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    return 0
  fi
  # 模块文件存在
  if [ -f "/lib/modules/$(uname -r)/kernel/net/ipv4/tcp_bbr.ko" ]; then
    return 0
  fi
  return 1
}

enable_bbr_fq() {
  info "启用 BBR+fq..."
  modprobe tcp_bbr 2>/dev/null || true
  cat > "$SYSCTL_FILE" <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || sysctl --system >/dev/null 2>&1 || true

  local cc qdisc
  cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
  qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "")
  if [[ "$cc" == "bbr" && "$qdisc" == "fq" ]]; then
    info "BBR+fq 已成功启用。"
  else
    warn "BBR+fq 启用状态未确认（cc=$cc, qdisc=$qdisc）。"
  fi
}

upgrade_kernel_for_bbr() {
  info "尝试安装较新内核以支持 BBR..."
  case "${OS_ID}" in
    ubuntu|debian)
      apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y --install-recommends linux-generic
      ;;
    centos|almalinux|rocky)
      yum install -y https://www.elrepo.org/elrepo-release-$(rpm -E %{rhel}).el$(rpm -E %{rhel}).elrepo.noarch.rpm
      yum --enablerepo=elrepo-kernel install -y kernel-ml
      ;;
    *)
      warn "暂不支持为 ${OS_ID} 自动升级内核。"
      return 1
      ;;
  esac
  warn "内核已更新，请重启（reboot）后再次运行本脚本的菜单 6 来启用 BBR+fq。"
}

do_enable_bbr() {
  detect_os
  if has_bbr; then
    enable_bbr_fq
  else
    warn "当前内核 ($(kernel_info)) 可能不支持 BBR。"
    if yes_or_no "是否尝试自动升级到最新内核以支持 BBR？（需要重启）" "N"; then
      upgrade_kernel_for_bbr
    else
      warn "已取消内核升级。您可手动升级内核后再执行此选项。"
    fi
  fi
}

#-----------------------------
# Self-install
#-----------------------------
self_install() {
  local src="${BASH_SOURCE[0]:-}"
  if [ -z "$src" ]; then
    warn "无法确定脚本来源，跳过自安装。"
    return
  fi
  # 只有在常规文件或/dev/fd/存在时才安装
  if [ -f "$src" ] || [ -e "$src" ]; then
    if [ "$src" != "$SELF_PATH" ]; then
      mkdir -p /usr/local/bin
      cat "$src" > "$SELF_PATH"
      chmod +x "$SELF_PATH"
      ln -sf "$SELF_PATH" "$LINK_PATH"
      info "已安装快捷命令：singbox"
    fi
  fi
}

#-----------------------------
# Install / Setup
#-----------------------------
do_install() {
  detect_os
  detect_arch
  install_deps

  download_latest_singbox

  local default_port="443"
  if port_busy 443; then
    warn "443 端口已被占用，默认端口改为 8443"
    default_port="8443"
  fi
  local default_sni="www.cloudflare.com"
  local default_server_addr="$(get_public_ip)"
  [ -n "$default_server_addr" ] || default_server_addr="你的服务器域名或IP"

  SB_LISTEN_PORT=$(ask_with_default "请输入监听端口" "$default_port")
  SB_SNI_DOMAIN=$(ask_with_default "请输入握手域名（SNI）" "$default_sni")
  SB_HANDSHAKE_PORT=$(ask_with_default "请输入握手端口" "443")
  CLIENT_SERVER_ADDR=$(ask_with_default "客户端填写的服务器地址" "$default_server_addr")

  generate_values
  write_config
  persist_meta
  setup_systemd
  open_firewall_port "$SB_LISTEN_PORT"

  print_client_guide
  info "安装完成！"
  if yes_or_no "是否现在启用 BBR+fq 加速？" "Y"; then
    do_enable_bbr
  fi
}

#-----------------------------
# Main Functions
#-----------------------------
do_update() {
  [ -x "$BIN_PATH" ] || err "未检测到 sing-box，请先安装。"
  download_latest_singbox
  systemctl restart sing-box
  info "已更新并重启 sing-box。"
  "$BIN_PATH" version
}

do_uninstall() {
   if [ -f "$META_PATH" ]; then
    local port_to_close=$(jq -r '.listen_port' "$META_PATH")
    close_firewall_port "$port_to_close"
  fi
  systemctl disable --now sing-box 2>/dev/null || true
  rm -f "$SVC_PATH"
  systemctl daemon-reload
  if yes_or_no "是否删除所有 sing-box 文件（包括配置和二进制文件）？" "N"; then
      rm -f "$BIN_PATH" "$SELF_PATH" "$LINK_PATH"
      rm -rf "$CFG_DIR"
      info "已删除所有 sing-box 文件。"
  else
      info "仅停止服务，文件已保留。"
  fi
  info "卸载完成。"
}

restart_service() {
  systemctl restart sing-box
  info "服务已重启。"
  sleep 1
  systemctl status sing-box --no-pager -l
}

show_menu() {
  clear
  echo "========================================"
  echo " sing-box (VLESS REALITY) 管理菜单"
  echo "----------------------------------------"
  echo " 1) 安装/初始化"
  echo " 2) 更新 sing-box"
  echo " 3) 重启服务"
  echo " 4) 查看节点信息"
  echo " 5) 卸载"
  echo " 6) 安装/启用 BBR+fq"
  echo " 0) 退出"
  echo "========================================"
  read -rp "请选择操作 [0-6]: " ans
  case "$ans" in
    1) do_install ;;
    2) do_update ;;
    3) restart_service ;;
    4) show_info ;;
    5) do_uninstall ;;
    6) do_enable_bbr ;;
    0) exit 0 ;;
    *) warn "无效输入" && sleep 1 && show_menu ;;
  esac
}

main() {
  is_root || err "请使用 root 权限运行此脚本。"
  
  # 如果是通过 curl | bash 运行，首次执行时安装自己
  if [ -t 0 ]; then
    self_install
  fi

  if [ $# -gt 0 ]; then
    case $1 in
      install|update|uninstall|info|restart|bbr)
        "do_$1"
        ;;
      *)
        show_menu
        ;;
    esac
  else
    show_menu
  fi
}

main "$@"

#-----------------------------
# 进阶：与 Nginx 共享 443（可选）
#-----------------------------
# 如果你必须与 Nginx 共享 443，可以使用 Nginx stream 基于 SNI 分流：
# 在 /etc/nginx/nginx.conf 的 http {} 之外添加 stream {} 块：
#
# stream {
#   map $ssl_preread_server_name $backend_name {
#     www.your-website.com      web_backend;
#     www.cloudflare.com        singbox_backend;
#     default                   web_backend; # 默认给网站
#   }
#
#   upstream web_backend {
#     server 127.0.0.1:4430; # 假设你的网站现在监听 4430
#   }
#
#   upstream singbox_backend {
#     server 127.0.0.1:8443; # sing-box 监听的端口
#   }
#
#   server {
#     listen 443 reuseport;
#     listen [::]:443 reuseport;
#     proxy_pass $backend_name;
#     ssl_preread on;
#   }
# }
#
# 然后：nginx -t && systemctl reload nginx
