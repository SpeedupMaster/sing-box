#!/usr/bin/env bash

set -u
umask 022

SCRIPT_VERSION="1.10.0"
SCRIPT_URL_BUILTIN="https://raw.githubusercontent.com/SpeedupMaster/sing-box/main/sing-box.sh"
SCRIPT_URL_ARG=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SINGBOX_CONFIG_PATH="/etc/sing-box"
SINGBOX_CONFIG_FILE="${SINGBOX_CONFIG_PATH}/config.json"
REALITY_PUB_KEY_FILE="${SINGBOX_CONFIG_PATH}/reality.pub"
SINGBOX_BINARY_PATH="/usr/local/bin/sing-box"
SINGBOX_SERVICE_FILE="/etc/systemd/system/sing-box.service"
SCRIPT_PATH="/usr/local/bin/singbox-manager"
SHORTCUT_PATH="/usr/local/bin/singbox"
SHORTCUT_NAME="singbox"
BACKUP_ROOT="/etc/sing-box-manager/backups"

DEFAULT_PORT="443"
LISTEN_PORT="${DEFAULT_PORT}"
SELECTED_SNI=""

SNI_LIST=(
  "gateway.icloud.com"
  "itunes.apple.com"
  "swdist.apple.com"
  "swcdn.apple.com"
  "updates.cdn-apple.com"
  "mensura.cdn-apple.com"
  "osxapps.itunes.apple.com"
  "aod.itunes.apple.com"
  "download-installer.cdn.mozilla.net"
  "addons.mozilla.org"
  "s0.awsstatic.com"
  "d1.awsstatic.com"
  "cdn-dynmedia-1.microsoft.com"
  "www.cloudflare.com"
  "images-na.ssl-images-amazon.com"
  "m.media-amazon.com"
  "dl.google.com"
  "www.google-analytics.com"
  "www.microsoft.com"
  "software.download.prss.microsoft.com"
  "player.live-video.net"
  "one-piece.com"
  "lol.secure.dyn.riotcdn.net"
  "www.lovelive-anime.jp"
  "www.swift.com"
  "academy.nvidia.com"
  "www.cisco.com"
  "www.samsung.com"
  "www.amd.com"
)

log_info() {
  printf "${CYAN}[INFO] %s${NC}\n" "$1"
}

log_success() {
  printf "${GREEN}[SUCCESS] %s${NC}\n" "$1"
}

log_warning() {
  printf "${YELLOW}[WARNING] %s${NC}\n" "$1"
}

log_error() {
  printf "${RED}[ERROR] %s${NC}\n" "$1" >&2
}

fatal_error() {
  log_error "$1"
  exit 1
}

pause_back() {
  if [ -t 0 ] && [ -t 1 ]; then
    read -r -n 1 -s -p $'\n按任意键返回主菜单...'
    printf '\n'
  fi
}

clear_screen() {
  if [ -t 1 ]; then
    clear 2>/dev/null || true
  fi
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    fatal_error "此脚本必须以 root 用户权限运行。"
  fi
}

check_os() {
  if [ ! -r /etc/os-release ]; then
    fatal_error "无法识别当前系统。"
  fi

  # shellcheck disable=SC1091
  source /etc/os-release
  if [[ ! "${ID:-}" =~ ^(debian|ubuntu|centos|fedora|rocky|almalinux)$ ]]; then
    fatal_error "此脚本仅支持主流 Linux 发行版。"
  fi
}

ensure_dirs() {
  mkdir -p "$SINGBOX_CONFIG_PATH" "$BACKUP_ROOT"
}

install_dependencies() {
  log_info "正在安装必要依赖..."

  if command_exists apt-get; then
    apt-get update -y &&
      apt-get install -y curl jq qrencode lsof openssl ca-certificates
  elif command_exists dnf; then
    dnf install -y curl jq qrencode lsof openssl ca-certificates
  elif command_exists yum; then
    yum install -y curl jq qrencode lsof openssl ca-certificates
  else
    log_error "无法找到受支持的包管理器。"
    return 1
  fi
}

resolve_arch() {
  case "$(uname -m)" in
    x86_64)
      printf 'amd64\n'
      ;;
    aarch64)
      printf 'arm64\n'
      ;;
    *)
      log_error "不支持的系统架构: $(uname -m)"
      return 1
      ;;
  esac
}

get_latest_version() {
  local effective_url version

  effective_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' \
    https://github.com/SagerNet/sing-box/releases/latest 2>/dev/null || true)"
  version="${effective_url##*/}"
  version="${version#v}"
  if [[ "$version" =~ ^[0-9] ]]; then
    printf '%s\n' "$version"
    return 0
  fi

  version="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null | jq -r '.tag_name' | sed 's/^v//')"
  if [[ "$version" =~ ^[0-9] ]]; then
    printf '%s\n' "$version"
    return 0
  fi

  log_error "无法获取 sing-box 最新版本号。"
  return 1
}

current_singbox_version() {
  if [ -x "$SINGBOX_BINARY_PATH" ]; then
    "$SINGBOX_BINARY_PATH" version 2>/dev/null | awk 'NR==1 {print $3}'
  fi
}

port_in_use() {
  lsof -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
}

list_occupied_ports() {
  local ports

  ports="$(lsof -i -P -n 2>/dev/null | awk '/LISTEN/ {split($9, a, ":"); print a[length(a)]}' | sort -nu | tr '\n' ' ')"
  printf '%s\n' "${ports:-无}"
}

prompt_for_port() {
  local default_port="$1"
  local empty_behavior="${2:-default}"
  local user_port confirm_answer

  printf '%s\n' "----------------------------------------------------"
  printf '%b当前已被占用的端口列表:%b\n' "$YELLOW" "$NC"
  printf '%b%s%b\n' "$YELLOW" "$(list_occupied_ports)" "$NC"
  printf '%s\n' "----------------------------------------------------"

  while true; do
    printf '%b请输入 sing-box 监听端口 (1-65535)%b\n' "$CYAN" "$NC"
    if [ "$empty_behavior" = "random" ]; then
      read -r -p "留空直接回车将随机选择可用端口，也可手动输入端口 [默认 ${default_port}]: " user_port
      if [ -z "$user_port" ]; then
        while true; do
          user_port=$((RANDOM % 63536 + 2000))
          if ! port_in_use "$user_port"; then
            LISTEN_PORT="$user_port"
            log_success "已随机生成可用端口: ${LISTEN_PORT}"
            return 0
          fi
        done
      fi
    else
      read -r -p "留空直接回车将使用默认值 [${default_port}]: " user_port
      user_port="${user_port:-$default_port}"
    fi

    if [[ ! "$user_port" =~ ^[0-9]+$ ]] || [ "$user_port" -lt 1 ] || [ "$user_port" -gt 65535 ]; then
      log_warning "输入无效，请输入 1-65535 之间的数字。"
      continue
    fi

    if port_in_use "$user_port"; then
      read -r -p "端口 ${user_port} 已被占用，是否仍然使用？[y/N]: " confirm_answer
      case "${confirm_answer:-n}" in
        y|Y|yes|YES)
          LISTEN_PORT="$user_port"
          return 0
          ;;
        *)
          continue
          ;;
      esac
    fi

    LISTEN_PORT="$user_port"
    return 0
  done
}

get_random_sni() {
  local idx
  idx=$((RANDOM % ${#SNI_LIST[@]}))
  printf '%s\n' "${SNI_LIST[$idx]}"
}

validate_domain() {
  local domain="$1"
  [[ "$domain" =~ ^[A-Za-z0-9.-]+$ ]] && [[ "$domain" == *.* ]]
}

prompt_for_sni() {
  local default_sni="$1"
  local suggested user_sni

  suggested="${default_sni:-$(get_random_sni)}"

  while true; do
    read -r -p "请输入 SNI，直接回车使用默认值 [${suggested}]: " user_sni
    user_sni="${user_sni:-$suggested}"

    if ! validate_domain "$user_sni"; then
      log_warning "SNI 域名格式无效，请重新输入。"
      continue
    fi

    SELECTED_SNI="$user_sni"
    return 0
  done
}

copy_running_script_to() {
  local destination="$1"
  local source_file tmp_file

  source_file="${BASH_SOURCE[0]}"
  tmp_file="$(mktemp)"

  if [ -f "$source_file" ] && [ -r "$source_file" ]; then
    cat "$source_file" >"$tmp_file"
  elif curl -fsSL -o "$tmp_file" "${SCRIPT_URL_ARG:-$SCRIPT_URL_BUILTIN}"; then
    log_warning "无法直接读取当前脚本，已改为从更新地址下载管理脚本。"
  else
    rm -f "$tmp_file"
    log_error "保存管理脚本失败。"
    return 1
  fi

  install -m 755 "$tmp_file" "$destination"
  rm -f "$tmp_file"
}

write_shortcut_wrapper() {
  cat >"$SHORTCUT_PATH" <<EOF
#!/usr/bin/env bash
exec bash "${SCRIPT_PATH}" "\$@"
EOF
  chmod 755 "$SHORTCUT_PATH"
}

update_shell_alias() {
  local bashrc url_to_save

  bashrc="${HOME}/.bashrc"
  url_to_save="${SCRIPT_URL_ARG:-$SCRIPT_URL_BUILTIN}"

  touch "$bashrc"
  sed -i "/alias ${SHORTCUT_NAME}=/d" "$bashrc"
  printf "alias %s='bash %s %s'\n" "$SHORTCUT_NAME" "$SCRIPT_PATH" "$url_to_save" >>"$bashrc"
}

save_script() {
  log_info "正在保存管理脚本..."
  mkdir -p "$(dirname "$SCRIPT_PATH")"

  if ! copy_running_script_to "$SCRIPT_PATH"; then
    return 1
  fi

  write_shortcut_wrapper
  update_shell_alias
  log_success "已创建或更新快捷命令 '${SHORTCUT_NAME}'。"
  log_info "如当前会话尚未生效，可重新登录 SSH 或执行 'source ~/.bashrc'。"
}

backup_current_files() {
  local timestamp backup_dir

  timestamp="$(date +%Y%m%d-%H%M%S)"
  backup_dir="${BACKUP_ROOT}/${timestamp}"
  mkdir -p "$backup_dir"

  [ -f "$SINGBOX_CONFIG_FILE" ] && cp -a "$SINGBOX_CONFIG_FILE" "${backup_dir}/config.json"
  [ -f "$REALITY_PUB_KEY_FILE" ] && cp -a "$REALITY_PUB_KEY_FILE" "${backup_dir}/reality.pub"
  [ -f "$SINGBOX_SERVICE_FILE" ] && cp -a "$SINGBOX_SERVICE_FILE" "${backup_dir}/sing-box.service"
  [ -x "$SINGBOX_BINARY_PATH" ] && cp -a "$SINGBOX_BINARY_PATH" "${backup_dir}/sing-box.bin"

  printf '%s\n' "$backup_dir"
}

download_and_install_singbox() {
  local version="$1"
  local arch="$2"
  local tmp_dir tarball extracted_dir download_url

  tmp_dir="$(mktemp -d)" || return 1
  tarball="${tmp_dir}/sing-box.tar.gz"
  extracted_dir="${tmp_dir}/sing-box-${version}-linux-${arch}"
  download_url="https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-${arch}.tar.gz"

  log_info "正在下载 sing-box v${version}..."
  if ! curl -fsSL --retry 3 --connect-timeout 15 -o "$tarball" "$download_url"; then
    rm -rf "$tmp_dir"
    log_error "下载 sing-box 失败。"
    return 1
  fi

  if ! tar -xzf "$tarball" -C "$tmp_dir"; then
    rm -rf "$tmp_dir"
    log_error "解压 sing-box 安装包失败。"
    return 1
  fi

  if [ ! -f "${extracted_dir}/sing-box" ]; then
    rm -rf "$tmp_dir"
    log_error "安装包中未找到 sing-box 可执行文件。"
    return 1
  fi

  install -m 755 "${extracted_dir}/sing-box" "$SINGBOX_BINARY_PATH"
  rm -rf "$tmp_dir"
  return 0
}

generate_config() {
  local uuid key_pair private_key public_key short_id

  ensure_dirs

  uuid="$("$SINGBOX_BINARY_PATH" generate uuid 2>/dev/null | tr -d '\r\n')"
  key_pair="$("$SINGBOX_BINARY_PATH" generate reality-keypair 2>/dev/null)"
  private_key="$(printf '%s\n' "$key_pair" | awk -F': *' '/PrivateKey/ {print $2; exit}' | tr -d '\r\n"')"
  public_key="$(printf '%s\n' "$key_pair" | awk -F': *' '/PublicKey/ {print $2; exit}' | tr -d '\r\n"')"
  short_id="$(openssl rand -hex 8 | tr -d '\r\n')"

  if [ -z "$uuid" ] || [ -z "$private_key" ] || [ -z "$public_key" ] || [ -z "$short_id" ]; then
    log_error "生成 sing-box Reality 配置所需参数失败。"
    return 1
  fi

  printf '%s\n' "$public_key" >"$REALITY_PUB_KEY_FILE"

  cat >"$SINGBOX_CONFIG_FILE" <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": ${LISTEN_PORT},
      "sniff": true,
      "users": [
        {
          "uuid": "${uuid}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${SELECTED_SNI}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${SELECTED_SNI}",
            "server_port": 443
          },
          "private_key": "${private_key}",
          "short_id": [
            "${short_id}"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ]
}
EOF
}

validate_config() {
  if ! jq empty "$SINGBOX_CONFIG_FILE" >/dev/null 2>&1; then
    log_error "生成的配置文件不是有效 JSON。"
    return 1
  fi

  if "$SINGBOX_BINARY_PATH" check -c "$SINGBOX_CONFIG_FILE" >/dev/null 2>&1; then
    return 0
  fi

  log_error "sing-box 配置校验失败。"
  return 1
}

create_service() {
  cat >"$SINGBOX_SERVICE_FILE" <<EOF
[Unit]
Description=sing-box service
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${SINGBOX_CONFIG_PATH}
ExecStart=${SINGBOX_BINARY_PATH} run -c ${SINGBOX_CONFIG_FILE}
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
}

restart_service() {
  systemctl daemon-reload
  if systemctl is-enabled sing-box >/dev/null 2>&1; then
    systemctl restart sing-box
  else
    systemctl enable --now sing-box
  fi

  if systemctl is-active --quiet sing-box; then
    log_success "sing-box 服务运行正常。"
    return 0
  fi

  systemctl status sing-box --no-pager || true
  log_error "sing-box 服务启动失败。"
  return 1
}

stop_service() {
  systemctl stop sing-box >/dev/null 2>&1 || true
  systemctl disable sing-box >/dev/null 2>&1 || true
}

remove_management_shortcuts() {
  rm -f "$SCRIPT_PATH" "$SHORTCUT_PATH"
  if [ -f "${HOME}/.bashrc" ]; then
    sed -i "/alias ${SHORTCUT_NAME}=/d" "${HOME}/.bashrc"
  fi
}

remove_singbox_components() {
  local keep_manager="${1:-no}"

  stop_service
  rm -f "$SINGBOX_SERVICE_FILE"
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -f "$SINGBOX_BINARY_PATH"
  rm -rf "$SINGBOX_CONFIG_PATH"

  if [ "$keep_manager" != "yes" ]; then
    remove_management_shortcuts
  fi
}

install_bbr() {
  log_info "检查并启用 BBR + FQ..."

  if ! sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -q '^bbr$'; then
    grep -q '^net.core.default_qdisc=fq$' /etc/sysctl.conf 2>/dev/null || echo "net.core.default_qdisc=fq" >>/etc/sysctl.conf
    grep -q '^net.ipv4.tcp_congestion_control=bbr$' /etc/sysctl.conf 2>/dev/null || echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.conf
    sysctl -p >/dev/null 2>&1 || true
  fi

  if sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -q '^bbr$'; then
    log_success "TCP 拥塞控制算法已设置为 bbr。"
  fi
  if sysctl -n net.core.default_qdisc 2>/dev/null | grep -q '^fq$'; then
    log_success "默认队列调度算法已设置为 fq。"
  fi
}

check_bbr_status() {
  local bbr_status qdisc_status

  clear_screen
  log_info "正在检查 BBR 和 FQ 状态..."
  bbr_status="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || printf 'unknown')"
  qdisc_status="$(sysctl -n net.core.default_qdisc 2>/dev/null || printf 'unknown')"

  printf '%s\n' "================ BBR + FQ 状态检查 ================"
  if [ "$bbr_status" = "bbr" ]; then
    printf '  %bTCP 拥塞控制算法: %s (已启用)%b\n' "$GREEN" "$bbr_status" "$NC"
  else
    printf '  %bTCP 拥塞控制算法: %s (未启用)%b\n' "$RED" "$bbr_status" "$NC"
  fi

  if [ "$qdisc_status" = "fq" ]; then
    printf '  %b默认队列调度算法: %s (已启用)%b\n' "$GREEN" "$qdisc_status" "$NC"
  else
    printf '  %b默认队列调度算法: %s (建议使用 fq)%b\n' "$YELLOW" "$qdisc_status" "$NC"
  fi
  printf '%s\n' "=================================================="
}

is_installed() {
  [ -x "$SINGBOX_BINARY_PATH" ] || [ -f "$SINGBOX_CONFIG_FILE" ] || [ -f "$SINGBOX_SERVICE_FILE" ]
}

get_config_value() {
  local jq_filter="$1"

  if [ ! -f "$SINGBOX_CONFIG_FILE" ]; then
    return 1
  fi

  jq -er "$jq_filter" "$SINGBOX_CONFIG_FILE" 2>/dev/null
}

get_current_port() {
  get_config_value '.inbounds[] | select(.type == "vless") | .listen_port' | head -n1
}

get_current_sni() {
  get_config_value '.inbounds[] | select(.type == "vless" and (.tls.reality.enabled // false)) | .tls.server_name' | head -n1
}

get_public_ip() {
  local ip
  for ip in \
    "$(curl -4fsSL --max-time 8 https://api64.ipify.org 2>/dev/null || true)" \
    "$(curl -4fsSL --max-time 8 https://ipv4.icanhazip.com 2>/dev/null || true)" \
    "$(curl -4fsSL --max-time 8 https://ifconfig.me/ip 2>/dev/null || true)"
  do
    ip="$(printf '%s' "$ip" | tr -d '[:space:]')"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      printf '%s\n' "$ip"
      return 0
    fi
  done

  return 1
}

display_node_info() {
  local cfg_port uuid public_key short_id server_name ip_addr node_name vless_link

  if [ ! -f "$SINGBOX_CONFIG_FILE" ] || [ ! -f "$REALITY_PUB_KEY_FILE" ]; then
    log_error "配置文件或公钥文件不存在。"
    return 1
  fi

  cfg_port="$(get_current_port)"
  uuid="$(get_config_value '.inbounds[] | select(.type == "vless") | .users[0].uuid' | head -n1)"
  short_id="$(get_config_value '.inbounds[] | select(.type == "vless" and (.tls.reality.enabled // false)) | .tls.reality.short_id[0]' | head -n1)"
  server_name="$(get_current_sni)"
  public_key="$(tr -d '\r\n' <"$REALITY_PUB_KEY_FILE")"
  ip_addr="$(get_public_ip || true)"
  ip_addr="${ip_addr:-<your_server_ip>}"
  node_name="sing-box-$(date +%Y%m%d)"

  if [ -z "$cfg_port" ] || [ -z "$uuid" ] || [ -z "$short_id" ] || [ -z "$server_name" ] || [ -z "$public_key" ]; then
    log_error "当前配置不完整，无法生成节点信息。"
    return 1
  fi

  vless_link="vless://${uuid}@${ip_addr}:${cfg_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${server_name}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp#${node_name}"

  clear_screen
  printf '%s\n' "================ 节点配置信息 ================"
  printf '  地址 (Address): %s\n' "$ip_addr"
  printf '  端口 (Port): %s\n' "$cfg_port"
  printf '  UUID: %s\n' "$uuid"
  printf '  流控 (Flow): xtls-rprx-vision\n'
  printf '  安全 (Security): reality\n'
  printf '  SNI: %s\n' "$server_name"
  printf '  公钥 (pbk): %s\n' "$public_key"
  printf '  Short ID (sid): %s\n' "$short_id"
  printf '  指纹 (fp): chrome\n'
  printf '%s\n' "================ VLESS 导入链接 ================"
  printf '%b%s%b\n' "$GREEN" "$vless_link" "$NC"

  if command_exists qrencode; then
    printf '%s\n' "===================== 二维码 ====================="
    qrencode -t ANSIUTF8 "$vless_link"
  fi
}

perform_install() {
  local default_port="$1"
  local default_sni="$2"
  local port_empty_behavior="${3:-random}"
  local arch latest_version

  if ! install_dependencies; then
    return 1
  fi

  if ! prompt_for_port "$default_port" "$port_empty_behavior"; then
    return 1
  fi

  if ! prompt_for_sni "$default_sni"; then
    return 1
  fi

  arch="$(resolve_arch)" || return 1
  latest_version="$(get_latest_version)" || return 1

  if ! download_and_install_singbox "$latest_version" "$arch"; then
    return 1
  fi

  if ! generate_config; then
    return 1
  fi

  if ! validate_config; then
    return 1
  fi

  create_service
  install_bbr
  if ! save_script; then
    return 1
  fi

  if ! restart_service; then
    return 1
  fi

  log_success "sing-box 安装完成。"
  display_node_info
}

install_sing_box() {
  log_info "开始安装 sing-box..."

  if is_installed; then
    log_error "检测到当前环境已存在 sing-box，请使用“重新安装”功能。"
    return 1
  fi

  perform_install "$DEFAULT_PORT" "" "random"
}

reinstall_sing_box() {
  local backup_dir current_port current_sni confirm

  log_info "开始重新安装 sing-box..."

  if ! is_installed; then
    log_warning "未检测到已安装环境，将直接进入安装流程。"
    perform_install "$DEFAULT_PORT" "" "random"
    return $?
  fi

  read -r -p "重新安装会生成新的 UUID、Reality 密钥和 short_id，是否继续？[y/N]: " confirm
  case "${confirm:-n}" in
    y|Y|yes|YES)
      ;;
    *)
      log_info "已取消重新安装。"
      return 0
      ;;
  esac

  current_port="$(get_current_port || printf '%s' "$DEFAULT_PORT")"
  current_sni="$(get_current_sni || true)"
  backup_dir="$(backup_current_files)"
  log_info "当前配置已备份到: ${backup_dir}"

  remove_singbox_components "yes"
  if ! perform_install "$current_port" "$current_sni" "default"; then
    log_error "重新安装失败，原始备份保存在: ${backup_dir}"
    return 1
  fi
}

update_sing_box() {
  local current_version latest_version arch

  clear_screen
  log_info "开始更新 sing-box 内核..."

  if [ ! -x "$SINGBOX_BINARY_PATH" ]; then
    log_error "sing-box 未安装，无法执行更新。"
    return 1
  fi

  current_version="$(current_singbox_version || true)"
  latest_version="$(get_latest_version)" || return 1

  if [ -n "$current_version" ] && [ "$current_version" = "$latest_version" ]; then
    log_success "当前已是最新版本: v${current_version}"
    return 0
  fi

  arch="$(resolve_arch)" || return 1
  if ! download_and_install_singbox "$latest_version" "$arch"; then
    return 1
  fi

  if [ -f "$SINGBOX_CONFIG_FILE" ] && ! validate_config; then
    return 1
  fi

  if ! restart_service; then
    return 1
  fi

  log_success "sing-box 已更新至 v${latest_version}。"
}

restart_sing_box() {
  if [ ! -f "$SINGBOX_SERVICE_FILE" ]; then
    log_error "未检测到 sing-box 服务。"
    return 1
  fi

  if systemctl restart sing-box; then
    log_success "sing-box 已重启。"
    return 0
  fi

  log_error "重启 sing-box 失败。"
  return 1
}

change_sni_domain() {
  local current_sni backup_dir backup_config tmp_file

  if [ ! -x "$SINGBOX_BINARY_PATH" ] || [ ! -f "$SINGBOX_CONFIG_FILE" ]; then
    log_error "当前未安装 sing-box，无法更换 SNI。"
    return 1
  fi

  current_sni="$(get_current_sni || true)"
  if [ -z "$current_sni" ]; then
    log_error "未在当前配置中找到 Reality SNI。"
    return 1
  fi

  log_info "当前 SNI: ${current_sni}"
  if ! prompt_for_sni ""; then
    return 1
  fi

  if [ "$SELECTED_SNI" = "$current_sni" ]; then
    log_info "SNI 未变化，无需修改。"
    return 0
  fi

  backup_dir="$(backup_current_files)"
  backup_config="${backup_dir}/config.json"
  tmp_file="$(mktemp)"

  if ! jq --arg sni "$SELECTED_SNI" '
    .inbounds = (
      .inbounds | map(
        if (.type == "vless" and (.tls.reality.enabled // false)) then
          .tls.server_name = $sni |
          .tls.reality.handshake.server = $sni
        else
          .
        end
      )
    )
  ' "$SINGBOX_CONFIG_FILE" >"$tmp_file"; then
    rm -f "$tmp_file"
    log_error "修改配置文件失败。"
    return 1
  fi

  mv "$tmp_file" "$SINGBOX_CONFIG_FILE"

  if ! validate_config; then
    cp -a "$backup_config" "$SINGBOX_CONFIG_FILE"
    log_error "新 SNI 配置校验失败，已恢复原配置。"
    return 1
  fi

  if ! restart_service; then
    cp -a "$backup_config" "$SINGBOX_CONFIG_FILE"
    restart_service >/dev/null 2>&1 || true
    log_error "应用新 SNI 后服务启动失败，已恢复原配置。"
    return 1
  fi

  log_success "SNI 已从 ${current_sni} 更换为 ${SELECTED_SNI}。"
  display_node_info
}

uninstall_sing_box() {
  local confirm

  read -r -p "确定要卸载 sing-box 吗？这将删除服务、配置和管理快捷命令。[y/N]: " confirm
  case "${confirm:-n}" in
    y|Y|yes|YES)
      ;;
    *)
      log_info "卸载操作已取消。"
      return 0
      ;;
  esac

  remove_singbox_components
  log_success "sing-box 已成功卸载。"
}

update_script() {
  local url tmp_file

  clear_screen
  log_info "准备更新管理脚本..."
  url="${SCRIPT_URL_ARG:-$SCRIPT_URL_BUILTIN}"
  tmp_file="$(mktemp)"

  if ! curl -fsSL -o "$tmp_file" "$url"; then
    rm -f "$tmp_file"
    log_error "下载脚本失败，请检查网络或 URL。"
    return 1
  fi

  if ! grep -q '^#!/usr/bin/env bash' "$tmp_file" && ! grep -q '^#!/bin/bash' "$tmp_file"; then
    rm -f "$tmp_file"
    log_error "下载的文件不是有效的 Bash 脚本。"
    return 1
  fi

  install -m 755 "$tmp_file" "$SCRIPT_PATH"
  rm -f "$tmp_file"
  write_shortcut_wrapper
  update_shell_alias
  log_success "管理脚本已更新。"
  log_info "可以重新运行 'singbox' 使用新版本脚本。"
}

print_help() {
  printf '%s\n' "用法:"
  printf '  %s\n' "$(basename "$0")"
  printf '  %s install\n' "$(basename "$0")"
  printf '  %s reinstall\n' "$(basename "$0")"
  printf '  %s uninstall\n' "$(basename "$0")"
  printf '  %s update\n' "$(basename "$0")"
  printf '  %s restart\n' "$(basename "$0")"
  printf '  %s info\n' "$(basename "$0")"
  printf '  %s change-sni\n' "$(basename "$0")"
  printf '  %s check-bbr\n' "$(basename "$0")"
  printf '  %s update-script\n' "$(basename "$0")"
  printf '  %s help\n' "$(basename "$0")"
}

main_menu() {
  local choice

  while true; do
    clear_screen
    printf '%s\n' "===================================================="
    printf '  Sing-Box VLESS Reality 一键管理脚本 (v%s)\n' "$SCRIPT_VERSION"
    printf '%s\n' "===================================================="
    printf '%s\n' "  1. 安装 Sing-Box         2. 重新安装 Sing-Box"
    printf '%s\n' "  3. 卸载 Sing-Box         4. 更新 Sing-Box (内核)"
    printf '%s\n' "  5. 重启 Sing-Box         6. 查看节点信息"
    printf '%s\n' "  7. 更换 Reality SNI      8. 检查 BBR+FQ 状态"
    printf '%s\n' "  9. 更新管理脚本"
    printf '%s\n' "  --------------------------------------------------"
    printf '%s\n' "  0. 退出脚本"
    printf '%s\n' "===================================================="
    read -r -p "请输入选项 [0-9]: " choice

    case "${choice}" in
      1)
        install_sing_box
        ;;
      2)
        reinstall_sing_box
        ;;
      3)
        uninstall_sing_box
        ;;
      4)
        update_sing_box
        ;;
      5)
        restart_sing_box
        ;;
      6)
        display_node_info
        ;;
      7)
        change_sni_domain
        ;;
      8)
        check_bbr_status
        ;;
      9)
        update_script
        ;;
      0)
        exit 0
        ;;
      *)
        log_warning "无效选项，请重新输入。"
        ;;
    esac

    pause_back
  done
}

main() {
  local subcommand

  if [[ "${1:-}" == http* ]]; then
    SCRIPT_URL_ARG="$1"
    shift
  fi

  subcommand="${1:-menu}"
  case "$subcommand" in
    install)
      install_sing_box
      ;;
    reinstall)
      reinstall_sing_box
      ;;
    uninstall|remove)
      uninstall_sing_box
      ;;
    update)
      update_sing_box
      ;;
    restart)
      restart_sing_box
      ;;
    info)
      display_node_info
      ;;
    change-sni)
      change_sni_domain
      ;;
    check-bbr|bbr)
      check_bbr_status
      ;;
    update-script)
      update_script
      ;;
    help|-h|--help)
      print_help
      ;;
    menu)
      main_menu
      ;;
    *)
      log_error "未知命令: $subcommand"
      print_help
      return 1
      ;;
  esac
}

check_root
check_os
main "$@"
