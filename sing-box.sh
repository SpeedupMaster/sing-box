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
  # 使用 contains + endswith，避免 jq 正则转义问题
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

# 解析 Reality key 输出（兼容同一行/下一行）
parse_reality_keys() {
  local text="$1"
  # 先尝试同一行（包含冒号后紧跟值）
  SB_PRIV_KEY=$(echo "$text" | awk 'BEGIN{IGNORECASE=1}
    /private[[:space:]]*key/ {
      if (match($0, /:[[:space:]]*([A-Za-z0-9_\-+=/]+)/, m)) { print m[1]; found=1; exit }
    }
    END { if (found!=1) exit 1 }' 2>/dev/null || true)
  SB_PUB_KEY=$(echo "$text" | awk 'BEGIN{IGNORECASE=1}
    /public[[:space:]]*key/ {
      if (match($0, /:[[:space:]]*([A-Za-z0-9_\-+=/]+)/, m)) { print m[1]; found=1; exit }
    }
    END { if (found!=1) exit 1 }' 2>/dev/null || true)

  # 若同一行未取到，再取下一行的值
  if [ -z "${SB_PRIV_KEY:-}" ]; then
    SB_PRIV_KEY=$(echo "$text" | awk 'BEGIN{IGNORECASE=1}
      /private[[:space:]]*key/ {getline; gsub(/^[[:space:]]+|[[:space:]]+$/,""); print; exit }' 2>/dev/null || true)
  fi
  if [ -z "${SB_PUB_KEY:-}" ]; then
    SB_PUB_KEY=$(echo "$text" | awk 'BEGIN{IGNORECASE=1}
      /public[[:space:]]*key/ {getline; gsub(/^[[:space:]]+|[[:space:]]+$/,""); print; exit }' 2>/dev/null || true)
  fi

  # 最后兜底：从所有行里抓“看起来像 key 的 token”
  if [ -z "${SB_PRIV_KEY:-}" ] || [ -z "${SB_PUB_KEY:-}" ]; then
    local tokens
    tokens=$(echo "$text" | tr -d '\r' | grep -Eo '[A-Za-z0-9_\-+/=]{32,}' | head -n2)
    SB_PRIV_KEY=${SB_PRIV_KEY:-$(echo "$tokens" | sed -n '1p')}
    SB_PUB_KEY=${SB_PUB_KEY:-$(echo "$tokens" | sed -n '2p')}
  fi
}

generate_values() {
  # UUID
  if command -v uuidgen >/dev/null 2>&1; then
    SB_UUID=$(uuidgen)
  else
    SB_UUID=$(cat /proc/sys/kernel/random/uuid)
  fi

  # Reality keypair（优先 reality-keypair，失败回退 reality-key）
  local rk_output
  rk_output=$("$BIN_PATH" generate reality-keypair 2>&1 || true)
  parse_reality_keys "$rk_output"
  if [ -z "${SB_PRIV_KEY:-}" ] || [ -z "${SB_PUB_KEY:-}" ]; then
    rk_output=$("$BIN_PATH" generate reality-key 2>&1 || true)
    parse_reality_keys "$rk_output"
  fi
  if [ -z "${SB_PRIV_KEY:-}" ] || [ -z "${SB_PUB_KEY:-}" ]; then
    echo "sing-box 输出如下，供排查：" >&2
    echo "--------------------------------" >&2
    echo "$rk_output" >&2
    echo "--------------------------------" >&2
    err "生成 Reality 密钥失败（解析不到 Private/Public Key）"
  fi

  # short_id（8~16 hex，取 16）。优先 sing-box 自带，失败则 openssl。
  if "$BIN_PATH" generate rand --hex 8 >/dev/null 2>&1; then
    SB_SHORT_ID=$("$BIN_PATH" generate rand --hex 8)
  else
    SB_SHORT_ID=$(openssl rand -hex 8)
  fi

  info "生成参数完成："
  echo "  UUID:         $SB_UUID"
  echo "  Public Key:   $SB_PUB_KEY"
  echo "  Private Key:  $SB_PRIV_KEY"
  echo "  Short ID:     $SB_SHORT_ID"
}
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
      "transport": { "type": "tcp" },
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
  "transport": { "type": "tcp" },
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
  sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr
}

enable_bbr_fq() {
  info "启用 BBR+fq..."
  modprobe tcp_bbr 2>/dev/null || true
  cat > "$SYSCTL_FILE" <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl --system >/dev/null 2>&1 || sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true

  local cc qdisc
  cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
  qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "")
  if [[ "$cc" == "bbr" && "$qdisc" == "fq" ]]; then
    info "BBR+fq 已启用（当前内核：$(kernel_info)）"
  else
    warn "BBR+fq 启用状态未确认（cc=$cc, qdisc=$qdisc）。如仍不生效，可能需要重启或升级内核。"
  fi
}

upgrade_kernel_for_bbr() {
  detect_os
  info "尝试安装较新内核以支持 BBR（将不会自动重启）..."
  case "${OS_ID}" in
    ubuntu)
      apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y linux-generic
      info "Ubuntu 已安装 linux-generic 内核，重启后再执行菜单 6 启用 BBR+fq。"
      ;;
    debian)
      apt-get update -y
      if ! DEBIAN_FRONTEND=noninteractive apt-get install -y linux-image-amd64; then
        if [ -n "${OS_CODENAME:-}" ]; then
          echo "deb http://deb.debian.org/debian ${OS_CODENAME}-backports main" > /etc/apt/sources.list.d/backports.list
          apt-get update -y
          DEBIAN_FRONTEND=noninteractive apt-get -t "${OS_CODENAME}-backports" install -y linux-image-amd64
          info "Debian 已安装 backports 内核，重启后再执行菜单 6 启用 BBR+fq。"
        else
          warn "无法识别 Debian codename，内核升级未完成。"
        fi
      else
        info "Debian 已安装最新 linux-image-amd64，重启后再执行菜单 6 启用 BBR+fq。"
      fi
      ;;
    centos|almalinux|rocky)
      local major
      major=$(echo "$OS_VERSION_ID" | awk -F'.' '{print $1}')
      if [[ "$major" == "9" ]]; then
        yum install -y https://www.elrepo.org/elrepo-release-9.el9.elrepo.noarch.rpm || dnf install -y https://www.elrepo.org/elrepo-release-9.el9.elrepo.noarch.rpm
      else
        yum install -y https://www.elrepo.org/elrepo-release-8.el8.elrepo.noarch.rpm || dnf install -y https://www.elrepo.org/elrepo-release-8.el8.elrepo.noarch.rpm
      fi
      yum --enablerepo=elrepo-kernel install -y kernel-ml || dnf --enablerepo=elrepo-kernel install -y kernel-ml
      info "EL 系列已安装 kernel-ml（主线内核）。重启后再执行菜单 6 启用 BBR+fq。"
      ;;
    *)
      warn "暂不支持自动升级该系统的内核，请手动升级到 >= 4.9 的内核以支持 BBR。"
      ;;
  esac
  warn "注意：更换内核需重启生效。请执行 reboot 后再次运行本脚本启用 BBR+fq。"
}

do_enable_bbr() {
  detect_os
  if has_bbr; then
    enable_bbr_fq
  else
    warn "当前内核可能不支持 BBR（$(kernel_info)），或未启用 TCP BBR 模块。"
    if yes_or_no "是否自动尝试升级到较新内核以支持 BBR？（需要重启）" "N"; then
      upgrade_kernel_for_bbr
    else
      warn "已取消内核升级。你可手动升级内核后再执行菜单 6 启用 BBR+fq。"
    fi
  fi
}

#-----------------------------
# Self-install (首次运行自动安装为 singbox/singboxctl)
#-----------------------------
self_install() {
  local src="${BASH_SOURCE[0]:-}"
  if [ -z "$src" ]; then
    warn "无法确定脚本来源路径，跳过自安装。你可手动保存为 $SELF_PATH 并链接到 $LINK_PATH"
    return 0
  fi
  if [ "$src" != "$SELF_PATH" ]; then
    mkdir -p /usr/local/bin
    cat "$src" > "$SELF_PATH"
    chmod +x "$SELF_PATH"
    ln -sf "$SELF_PATH" "$LINK_PATH"
    info "已安装快捷命令：singbox（路径：$LINK_PATH）"
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

  # 默认端口逻辑：若 443 被占用则默认用 8443
  local default_port default_sni default_handshake_port default_server_addr
  if port_busy 443; then
    warn "检测到 443 端口已被占用（可能是 Nginx），默认监听端口改为 8443"
    default_port="8443"
  else
    default_port="443"
  fi
  default_sni="www.cloudflare.com"
  default_handshake_port="443"
  default_server_addr="$(get_public_ip)"
  [ -n "$default_server_addr" ] || default_server_addr="你的服务器域名或IP"

  SB_LISTEN_PORT=$(ask_with_default "请输入监听端口" "$default_port")
  SB_SNI_DOMAIN=$(ask_with_default "请输入握手域名（SNI）" "$default_sni")
  SB_HANDSHAKE_PORT=$(ask_with_default "请输入握手端口（一般为 443）" "$default_handshake_port")
  CLIENT_SERVER_ADDR=$(ask_with_default "客户端中填写的服务器地址（域名或IP）" "$default_server_addr")

  generate_values
  write_config
  persist_meta
  setup_systemd
  open_firewall_port "$SB_LISTEN_PORT"

  print_client_guide
  info "安装完成！如需查看日志：journalctl -u sing-box -f"

  # 询问是否启用 BBR+fq
  if yes_or_no "是否立刻安装/启用 BBR+fq 加速？" "Y"; then
    do_enable_bbr
  else
    warn "已跳过 BBR+fq 加速，你可在菜单中选择“安装/启用 BBR+fq”后续开启。"
  fi
}

#-----------------------------
# Update
#-----------------------------
do_update() {
  [ -x "$BIN_PATH" ] || err "未检测到 sing-box 已安装，请先安装"
  detect_os
  detect_arch
  install_deps
  download_latest_singbox
  systemctl restart sing-box || true
  info "已更新并重启 sing-box"
  if [ -f "$META_PATH" ]; then
    print_client_guide
  else
    warn "未找到元数据文件，无法输出节点信息。若需重建信息，请重新执行安装或手动更新 $META_PATH"
  fi
}

#-----------------------------
# Uninstall
#-----------------------------
do_uninstall() {
  local listen_port
  if [ -f "$META_PATH" ]; then
    listen_port=$(jq -r '.listen_port' "$META_PATH" 2>/dev/null || echo "")
  fi

  systemctl stop sing-box 2>/dev/null || true
  systemctl disable sing-box 2>/dev/null || true
  rm -f "$SVC_PATH"
  systemctl daemon-reload

  if [ -n "${listen_port:-}" ]; then
    close_firewall_port "$listen_port"
  fi

  echo
  warn "是否删除二进制和配置文件？此操作不可恢复。"
  echo "1) 删除全部（包含二进制 / 配置 / 元数据）"
  echo "2) 仅删除服务（保留二进制与配置）"
  read -rp "请选择 [1/2]: " choice || true
  case "${choice:-2}" in
    1)
      rm -f "$BIN_PATH"
      rm -rf "$CFG_DIR"
      info "已删除二进制与配置文件"
      ;;
    2)
      info "仅移除服务，保留二进制与配置"
      ;;
    *)
      info "未选择有效项，默认保留二进制与配置"
      ;;
  esac
  info "卸载完成"
}

#-----------------------------
# Show Info
#-----------------------------
show_info() {
  [ -f "$META_PATH" ] || err "未找到 ${META_PATH}，请先安装"
  print_client_guide
}

#-----------------------------
# Restart
#-----------------------------
restart_service() {
  systemctl restart sing-box
  info "已重启 sing-box 服务"
}

#-----------------------------
# Menu
#-----------------------------
show_menu() {
  echo "========================================"
  echo " sing-box (VLESS REALITY) 管理菜单"
  echo "----------------------------------------"
  echo " 1) 安装/初始化"
  echo " 2) 更新 sing-box 到最新版本"
  echo " 3) 重启服务"
  echo " 4) 查看节点信息与导入链接"
  echo " 5) 卸载"
  echo " 6) 安装/启用 BBR+fq"
  echo " 0) 退出"
  echo "========================================"
  read -rp "请选择操作 [0-6]: " ans || true
  case "${ans:-0}" in
    1) do_install ;;
    2) do_update ;;
    3) restart_service ;;
    4) show_info ;;
    5) do_uninstall ;;
    6) do_enable_bbr ;;
    0) exit 0 ;;
    *) warn "无效选择";;
  esac
}

#-----------------------------
# Entry
#-----------------------------
main() {
  is_root || err "请使用 root 权限运行此脚本（sudo 或直接 root）"
  self_install
  # 支持命令行参数：install/update/uninstall/info/restart/bbr/menu
  case "${1:-menu}" in
    install) shift; do_install ;;
    update) shift; do_update ;;
    uninstall) shift; do_uninstall ;;
    info) shift; show_info ;;
    restart) shift; restart_service ;;
    bbr) shift; do_enable_bbr ;;
    menu|*) show_menu ;;
  esac
}

main "$@"

#-----------------------------
# 进阶：与 Nginx 共享 443（可选）
#-----------------------------
# 如果你必须与 Nginx 共享 443，可以使用 Nginx stream 基于 SNI 分流：
# 注意：Reality 客户端的 SNI 是伪装域名（如 www.cloudflare.com），
# 你可以将此类 SNI 的连接转发给 sing-box，其他你的真实域名继续给 Nginx/网站。
#
# /etc/nginx/nginx.conf 里添加（需启用 stream 模块）：
#
# stream {
#   map $ssl_preread_server_name $route {
#     ~^(www\\.cloudflare\\.com|www\\.bing\\.com|www\\.wikipedia\\.org)$ singbox;
#     default web;
#   }
#   upstream singbox_backend { server 127.0.0.1:8443; } # sing-box 监听端口
#   upstream web_backend    { server 127.0.0.1:443; }   # 你原有的服务（或变更端口）
#
#   server {
#     listen 443 reuseport;
#     proxy_pass $route;
#     ssl_preread on;
#   }
# }
#
# 然后：nginx -t && systemctl reload nginx
# 这样客户端仍用 443，且按 SNI 分流至 sing-box 或 Web。
