#!/usr/bin/env bash

#====================================================
# Script to install Sing-Box VLESS Reality on VPS
# Author: Your Name
# Version: 1.5.1 (Expanded SNI list with user contribution)
#====================================================

#--- Colors ---#
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

#--- Global Variables ---#
SINGBOX_CONFIG_PATH="/etc/sing-box"
SINGBOX_CONFIG_FILE="${SINGBOX_CONFIG_PATH}/config.json"
SINGBOX_BINARY_PATH="/usr/local/bin/sing-box"
SINGBOX_SERVICE_FILE="/etc/systemd/system/sing-box.service"
SCRIPT_PATH="/usr/local/bin/singbox-manager"
SHORTCUT_NAME="singbox"
LISTEN_PORT=443
SCRIPT_URL=""
SELECTED_SNI=""

# A comprehensive list of high-availability domains for random SNI
SNI_LIST=(
    # Apple
    "gateway.icloud.com"
    "itunes.apple.com"
    "swdist.apple.com"
    "swcdn.apple.com"
    "updates.cdn-apple.com"
    "mensura.cdn-apple.com"
    "osxapps.itunes.apple.com"
    "aod.itunes.apple.com"
    # Mozilla
    "download-installer.cdn.mozilla.net"
    "addons.mozilla.org"
    # CDN & Cloud
    "s0.awsstatic.com"
    "d1.awsstatic.com"
    "cdn-dynmedia-1.microsoft.com"
    "www.cloudflare.com"
    # Amazon
    "images-na.ssl-images-amazon.com"
    "m.media-amazon.com"
    # Google
    "dl.google.com"
    "www.google-analytics.com"
    # Microsoft
    "www.microsoft.com"
    "software.download.prss.microsoft.com"
    # Others
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

#--- Helper Functions ---#
log_info() { echo -e "${CYAN}[INFO] ${1}${NC}"; }
log_success() { echo -e "${GREEN}[SUCCESS] ${1}${NC}"; }
log_warning() { echo -e "${YELLOW}[WARNING] ${1}${NC}"; }
log_error() { echo -e "${RED}[ERROR] ${1}${NC}"; exit 1; }

#--- Prerequisite Checks ---#
check_root() { [ "$(id -u)" -ne 0 ] && log_error "此脚本必须以 root 用户权限运行。"; }
check_os() {
    source /etc/os-release
    [[ ! "$ID" =~ ^(debian|ubuntu|centos|fedora|rocky|almalinux)$ ]] && log_error "此脚本仅支持 Debian, Ubuntu, CentOS, Fedora, Rocky, AlmaLinux 系统。"
}

#--- Core Logic ---#
install_dependencies() {
    log_info "正在安装必要的依赖包 (curl, jq, qrencode, lsof)..."
    if command -v apt-get &>/dev/null; then
        apt-get update -y && apt-get install -y curl jq qrencode lsof
    elif command -v dnf &>/dev/null; then
        dnf install -y curl jq qrencode lsof
    elif command -v yum &>/dev/null; then
        yum install -y curl jq qrencode lsof
    else
        log_error "无法找到包管理器。请手动安装 curl, jq, qrencode, lsof。"
    fi
}
check_and_set_port() {
    if lsof -i:"${LISTEN_PORT}" &>/dev/null; then
        log_warning "默认端口 ${LISTEN_PORT} 已被占用。"
        while true; do
            read -r -p "请输入一个新的可用端口 (例如 8443): " NEW_PORT
            if [[ "$NEW_PORT" =~ ^[0-9]+$ ]] && [ "$NEW_PORT" -gt 0 ] && [ "$NEW_PORT" -lt 65536 ] && ! lsof -i:"${NEW_PORT}" &>/dev/null; then
                LISTEN_PORT=${NEW_PORT}
                log_success "将使用新端口: ${LISTEN_PORT}"
                break
            else
                log_warning "无效或已被占用的端口，请重试。"
            fi
        done
    else
        log_info "默认端口 ${LISTEN_PORT} 可用。"
    fi
}
prompt_for_sni() {
    log_info "您可以指定一个 SNI (Server Name Indication) 用来伪装流量。"
    read -r -p "请输入您要伪装的 SNI，或直接按回车随机选择: " USER_SNI

    if [ -z "$USER_SNI" ]; then
        log_info "未输入 SNI，将从列表中随机选择一个..."
        RANDOM_INDEX=$((RANDOM % ${#SNI_LIST[@]}))
        SELECTED_SNI=${SNI_LIST[$RANDOM_INDEX]}
        log_success "已随机选择 SNI: ${SELECTED_SNI}"
    else
        SELECTED_SNI=$USER_SNI
        log_success "将使用您指定的 SNI: ${SELECTED_SNI}"
    fi
}
install_bbr() {
    if ! sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        log_info "正在启用 BBR + fq..."
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p &>/dev/null
        log_success "BBR + fq 已启用。"
    else
        log_info "BBR 已经启用。"
    fi
}
generate_config() {
    log_info "正在生成配置文件..."
    mkdir -p "${SINGBOX_CONFIG_PATH}"
    local UUID=$(${SINGBOX_BINARY_PATH} generate uuid)
    local KEY_PAIR=$(${SINGBOX_BINARY_PATH} generate reality-keypair)
    local PRIVATE_KEY=$(echo "${KEY_PAIR}" | awk '/PrivateKey/ {print $2}' | tr -d '"')
    local PUBLIC_KEY=$(echo "${KEY_PAIR}" | awk '/PublicKey/ {print $2}' | tr -d '"')
    local SHORT_ID=$(openssl rand -hex 8)
    
    cat > "${SINGBOX_CONFIG_FILE}" <<EOF
{
  "log": {"level": "info", "timestamp": true},
  "x_public_key": "${PUBLIC_KEY}",
  "inbounds": [{
    "type": "vless", "tag": "vless-in", "listen": "::", "listen_port": ${LISTEN_PORT},
    "sniff": true, "sniff_override_destination": true,
    "users": [{"uuid": "${UUID}", "flow": "xtls-rprx-vision"}],
    "tls": {
      "enabled": true, "server_name": "${SELECTED_SNI}",
      "reality": {
        "enabled": true, "handshake": {"server": "${SELECTED_SNI}", "server_port": 443},
        "private_key": "${PRIVATE_KEY}", "short_id": ["${SHORT_ID}"]
      }
    }
  }],
  "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}]
}
EOF
}
create_service() {
    log_info "正在创建 systemd 服务..."
    cat > "${SINGBOX_SERVICE_FILE}" <<EOF
[Unit]
Description=sing-box service
After=network.target nss-lookup.target
[Service]
User=root
WorkingDirectory=${SINGBOX_CONFIG_PATH}
ExecStart=${SINGBOX_BINARY_PATH} run -c ${SINGBOX_CONFIG_FILE}
Restart=on-failure
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF
}
save_script() {
    log_info "正在保存管理脚本..."
    if [ -z "$SCRIPT_URL" ]; then
        log_warning "无法确定脚本的下载 URL，无法创建快捷命令。"
        return
    fi
    if curl -fsSL -o "${SCRIPT_PATH}" "${SCRIPT_URL}"; then
        chmod +x "${SCRIPT_PATH}"
        if ! grep -q "alias ${SHORTCUT_NAME}=" ~/.bashrc; then
            echo "alias ${SHORTCUT_NAME}='bash ${SCRIPT_PATH} ${SCRIPT_URL}'" >> ~/.bashrc
            log_success "已创建快捷命令 '${SHORTCUT_NAME}'。"
            log_info "请运行 'source ~/.bashrc' 或重新登录SSH以使命令生效。"
        fi
    else
        log_error "从 ${SCRIPT_URL} 下载脚本失败，无法保存管理脚本。"
    fi
}
install_sing-box() {
    log_info "开始安装 sing-box..."
    [ -f "${SINGBOX_CONFIG_FILE}" ] && log_error "sing-box 已安装，请不要重复执行。"
    install_dependencies
    check_and_set_port
    prompt_for_sni
    ARCH=$(uname -m)
    case ${ARCH} in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) log_error "不支持的系统架构: ${ARCH}" ;;
    esac
    LATEST_VERSION=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r ".tag_name" | sed 's/v//')
    [ -z "$LATEST_VERSION" ] && log_error "获取 sing-box 版本号失败。"
    DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/sing-box-${LATEST_VERSION}-linux-${ARCH}.tar.gz"
    log_info "正在下载 sing-box v${LATEST_VERSION}..."
    curl -fsSL -o /tmp/sing-box.tar.gz "${DOWNLOAD_URL}" || log_error "下载失败。"
    tar -xzf /tmp/sing-box.tar.gz -C /tmp
    mv "/tmp/sing-box-${LATEST_VERSION}-linux-${ARCH}/sing-box" "${SINGBOX_BINARY_PATH}"
    chmod +x "${SINGBOX_BINARY_PATH}"
    generate_config
    create_service
    install_bbr
    save_script
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    if systemctl is-active --quiet sing-box; then
        log_success "sing-box 安装并启动成功！"
        display_node_info
    else
        log_error "sing-box 启动失败，请检查日志：journalctl -u sing-box --no-pager -l"
    fi
    rm -rf /tmp/sing-box*
}
uninstall_sing-box() {
    log_warning "确定要卸载 sing-box 吗? [y/N]"
    read -r -p "请输入: " confirm
    [[ ! "$confirm" =~ ^[yY]$ ]] && log_info "卸载操作已取消。" && return
    systemctl stop sing-box
    systemctl disable sing-box
    rm -f "${SINGBOX_SERVICE_FILE}" "${SINGBOX_BINARY_PATH}" "${SCRIPT_PATH}"
    rm -rf "${SINGBOX_CONFIG_PATH}"
    if grep -q "alias ${SHORTCUT_NAME}=" ~/.bashrc; then
        sed -i "/alias ${SHORTCUT_NAME}=/d" ~/.bashrc
        log_info "已移除快捷命令。请运行 'source ~/.bashrc' 或重新登录。"
    fi
    systemctl daemon-reload
    log_success "sing-box 已成功卸载。"
}
display_node_info() {
    [ ! -f "${SINGBOX_CONFIG_FILE}" ] && log_error "配置文件不存在或 sing-box 未安装。" && return
    CFG_PORT=$(jq -r '.inbounds[0].listen_port' "${SINGBOX_CONFIG_FILE}")
    UUID=$(jq -r '.inbounds[0].users[0].uuid' "${SINGBOX_CONFIG_FILE}")
    PUBLIC_KEY=$(jq -r '.x_public_key' "${SINGBOX_CONFIG_FILE}")
    SHORT_ID=$(jq -r '.inbounds[0].tls.reality.short_id[0]' "${SINGBOX_CONFIG_FILE}")
    SERVER_NAME=$(jq -r '.inbounds[0].tls.server_name' "${SINGBOX_CONFIG_FILE}")
    IP_ADDR=$(curl -s4 ip.sb || curl -s4 ifconfig.me)
    NODE_NAME="vps-$(date +%s)"
    [ -z "$PUBLIC_KEY" ] || [ "$PUBLIC_KEY" == "null" ] && log_error "无法读取公钥，请卸载后重装。" && return
    VLESS_LINK="vless://${UUID}@${IP_ADDR}:${CFG_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SERVER_NAME}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp#${NODE_NAME}"
    clear ; echo -e "================ 节点配置信息 ================"
    echo -e "  地址 (Address): ${IP_ADDR}\n  端口 (Port): ${CFG_PORT}\n  UUID: ${UUID}\n  流控 (Flow): xtls-rprx-vision\n  安全 (Security): reality\n  SNI: ${SERVER_NAME}\n  公钥 (pbk): ${PUBLIC_KEY}\n  Short ID (sid): ${SHORT_ID}\n  指纹 (fp): chrome"
    echo -e "================ VLESS 导入链接 ================" ; echo -e "${GREEN}${VLESS_LINK}${NC}"
    echo -e "===================== 二维码 =====================" ; qrencode -t ANSIUTF8 "${VLESS_LINK}"
}
main_menu() {
    clear
    echo "===================================================="
    echo "  Sing-Box VLESS Reality 一键管理脚本 (v1.5.1)"
    echo "===================================================="
    echo "  1. 安装 Sing-Box    2. 卸载 Sing-Box"
    echo "  --------------------------------------------------"
    echo "  3. 更新 Sing-Box    4. 重启 Sing-Box"
    echo "  5. 查看节点信息   0. 退出脚本"
    echo "===================================================="
    read -r -p "请输入选项 [0-5]: " choice
    case ${choice} in
        1) install_sing-box ;;
        2) uninstall_sing-box ;;
        3) log_warning "更新功能正在开发中..." ;;
        4) systemctl restart sing-box && log_success "Sing-box 已重启。" || log_error "操作失败或服务未安装。" ;;
        5) display_node_info ;;
        0) exit 0 ;;
        *) log_error "无效选项。" ;;
    esac
}

#--- Script Entry Point ---#
check_root
check_os

if [[ "$1" == http* ]]; then
    SCRIPT_URL="$1"
    shift 
fi

main_menu
