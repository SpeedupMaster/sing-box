#!/usr/bin/env bash

#====================================================
# Script to install Sing-Box VLESS Reality on VPS
# Author: Your Name
# Version: 1.2.0
#====================================================

#--- Colors ---#
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

#--- Global Variables ---#
SINGBOX_CONFIG_PATH="/etc/sing-box"
SINGBOX_CONFIG_FILE="${SINGBOX_CONFIG_PATH}/config.json"
SINGBOX_BINARY_PATH="/usr/local/bin/sing-box"
SINGBOX_SERVICE_FILE="/etc/systemd/system/sing-box.service"
SCRIPT_PATH="/usr/local/bin/singbox-manager" # Path to save this script
SHORTCUT_NAME="singbox"

#--- Helper Functions ---#
log_info() {
    echo -e "${CYAN}[INFO] ${1}${NC}"
}

log_success() {
    echo -e "${GREEN}[SUCCESS] ${1}${NC}"
}

log_warning() {
    echo -e "${YELLOW}[WARNING] ${1}${NC}"
}

log_error() {
    echo -e "${RED}[ERROR] ${1}${NC}"
    exit 1
}

#--- Prerequisite Checks ---#
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "此脚本必须以 root 用户权限运行。"
    fi
}

check_os() {
    source /etc/os-release
    if [[ ! "$ID" =~ ^(debian|ubuntu|centos|fedora|rocky|almalinux)$ ]]; then
        log_error "此脚本仅支持 Debian, Ubuntu, CentOS, Fedora, Rocky, AlmaLinux 系统。"
    fi
}

check_port() {
    local port=$1
    if lsof -i:"${port}" &>/dev/null; then
        log_error "端口 ${port} 已被占用。请先停止占用该端口的程序再运行此脚本。"
    fi
}

#--- Dependency Installation ---#
install_dependencies() {
    log_info "正在安装必要的依赖包 (curl, jq, qrencode)..."
    if command -v apt-get &>/dev/null; then
        apt-get update -y && apt-get install -y curl jq qrencode lsof
    elif command -v dnf &>/dev/null; then
        dnf install -y curl jq qrencode lsof
    elif command -v yum &>/dev/null; then
        yum install -y curl jq qrencode lsof
    else
        log_error "无法找到包管理器 (apt/dnf/yum)。请手动安装 curl, jq, qrencode, lsof。"
    fi
}

#--- BBR Installation ---#
install_bbr() {
    log_info "正在检查并安装最新版 BBR..."
    if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        log_success "BBR 已经启用。"
    else
        log_info "正在启用 BBR + fq..."
        echo "net.core.default_qdisc=fq" | sudo tee -a /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" | sudo tee -a /etc/sysctl.conf
        sysctl -p
        if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
            log_success "BBR + fq 已成功启用！"
        else
            log_warning "BBR 启用失败。可能需要重启系统或内核不支持。"
        fi
    fi
}

#--- Core Functions ---#
install_sing-box() {
    log_info "开始安装 sing-box..."
    check_port 443
    install_dependencies

    # Get system architecture
    ARCH=$(uname -m)
    case ${ARCH} in
    x86_64)
        ARCH="amd64"
        ;;
    aarch64)
        ARCH="arm64"
        ;;
    esac
    LATEST_VERSION=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r ".tag_name" | sed 's/v//')
    if [ -z "$LATEST_VERSION" ]; then
        log_error "无法从 GitHub API 获取最新的 sing-box 版本号。"
    fi
    DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/sing-box-${LATEST_VERSION}-linux-${ARCH}.tar.gz"

    log_info "正在下载 sing-box v${LATEST_VERSION} for ${ARCH}..."
    curl -fsSL -o /tmp/sing-box.tar.gz "${DOWNLOAD_URL}"
    
    # Extract and install
    tar -xzf /tmp/sing-box.tar.gz -C /tmp
    mv "/tmp/sing-box-${LATEST_VERSION}-linux-${ARCH}/sing-box" "${SINGBOX_BINARY_PATH}"
    chmod +x "${SINGBOX_BINARY_PATH}"

    # Generate config
    generate_config

    # Create systemd service
    create_service

    # Install BBR
    install_bbr

    # Save script for management
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

    # Cleanup
    rm -rf /tmp/sing-box*
}

generate_config() {
    log_info "正在生成配置文件..."
    mkdir -p "${SINGBOX_CONFIG_PATH}"
    
    local UUID=$(sing-box generate uuid)
    local KEY_PAIR=$(sing-box generate reality-keypair)
    local PRIVATE_KEY=$(echo "${KEY_PAIR}" | awk '/PrivateKey/ {print $2}')
    local PUBLIC_KEY=$(echo "${KEY_PAIR}" | awk '/PublicKey/ {print $2}')
    local SHORT_ID=$(openssl rand -hex 8)
    local IP_ADDR=$(curl -s4 ip.sb)

    cat > "${SINGBOX_CONFIG_FILE}" <<EOF
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
      "listen_port": 443,
      "sniff": true,
      "sniff_override_destination": true,
      "users": [
        {
          "uuid": "${UUID}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "www.bing.com",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.bing.com",
            "server_port": 443
          },
          "private_key": "${PRIVATE_KEY}",
          "short_id": ["${SHORT_ID}"]
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

create_service() {
    log_info "正在创建 systemd 服务..."
    cat > "${SINGBOX_SERVICE_FILE}" <<EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org/
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=${SINGBOX_CONFIG_PATH}
ExecStart=${SINGBOX_BINARY_PATH} run
Restart=on-failure
RestartSec=10
LimitNPROC=infinity
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
}

uninstall_sing-box() {
    log_warning "确定要卸载 sing-box 吗? [y/N]"
    read -r -p "请输入: " confirm
    if [[ ! "$confirm" =~ ^[yY]$ ]]; then
        log_info "卸载操作已取消。"
        return
    fi

    log_info "正在停止并禁用 sing-box 服务..."
    systemctl stop sing-box
    systemctl disable sing-box
    
    log_info "正在删除文件..."
    rm -f "${SINGBOX_SERVICE_FILE}"
    rm -rf "${SINGBOX_CONFIG_PATH}"
    rm -f "${SINGBOX_BINARY_PATH}"
    rm -f "${SCRIPT_PATH}"
    
    # Remove alias
    if grep -q "alias ${SHORTCUT_NAME}=" ~/.bashrc; then
        sed -i "/alias ${SHORTCUT_NAME}=/d" ~/.bashrc
        log_info "已从 ~/.bashrc 中移除快捷命令。"
    fi

    systemctl daemon-reload
    log_success "sing-box 已成功卸载。"
}

update_sing-box() {
    log_info "正在检查更新..."
    CURRENT_VERSION=$(${SINGBOX_BINARY_PATH} version | awk 'NR==1{print $3}')
    LATEST_VERSION=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r ".tag_name" | sed 's/v//')

    if [ "$CURRENT_VERSION" == "$LATEST_VERSION" ]; then
        log_success "您已安装最新版本: v${CURRENT_VERSION}"
        return
    fi

    log_info "发现新版本 v${LATEST_VERSION}，正在更新..."
    ARCH=$(uname -m)
    case ${ARCH} in
    x86_64)
        ARCH="amd64"
        ;;
    aarch64)
        ARCH="arm64"
        ;;
    esac
    DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/sing-box-${LATEST_VERSION}-linux-${ARCH}.tar.gz"

    curl -fsSL -o /tmp/sing-box.tar.gz "${DOWNLOAD_URL}"
    tar -xzf /tmp/sing-box.tar.gz -C /tmp
    
    systemctl stop sing-box
    mv "/tmp/sing-box-${LATEST_VERSION}-linux-${ARCH}/sing-box" "${SINGBOX_BINARY_PATH}"
    chmod +x "${SINGBOX_BINARY_PATH}"
    systemctl start sing-box
    
    if systemctl is-active --quiet sing-box; then
        log_success "sing-box 已成功更新至 v${LATEST_VERSION}！"
    else
        log_error "更新后启动失败，请检查日志。"
    fi

    rm -rf /tmp/sing-box*
}

save_script() {
    log_info "正在保存管理脚本以便后续使用..."
    # Copy self to a permanent location
    cp -f "$0" "${SCRIPT_PATH}"
    chmod +x "${SCRIPT_PATH}"

    # Add alias to .bashrc if not already present
    if ! grep -q "alias ${SHORTCUT_NAME}=" ~/.bashrc; then
        echo "alias ${SHORTCUT_NAME}='${SCRIPT_PATH}'" >> ~/.bashrc
        log_success "已创建快捷命令 '${SHORTCUT_NAME}'。"
        log_info "请运行 'source ~/.bashrc' 或重新登录SSH以使命令生效。"
    fi
}

display_node_info() {
    if [ ! -f "${SINGBOX_CONFIG_FILE}" ]; then
        log_error "配置文件不存在，无法显示节点信息。"
        return
    fi
    
    UUID=$(jq -r '.inbounds[0].users[0].uuid' "${SINGBOX_CONFIG_FILE}")
    PRIVATE_KEY=$(jq -r '.inbounds[0].tls.reality.private_key' "${SINGBOX_CONFIG_FILE}")
    PUBLIC_KEY=$(sing-box generate reality-keypair --private-key "${PRIVATE_KEY}" | awk '/PublicKey/ {print $2}')
    SHORT_ID=$(jq -r '.inbounds[0].tls.reality.short_id[0]' "${SINGBOX_CONFIG_FILE}")
    IP_ADDR=$(curl -s4 ip.sb)
    SERVER_NAME=$(jq -r '.inbounds[0].tls.server_name' "${SINGBOX_CONFIG_FILE}")
    
    NODE_NAME="vless-reality-$(date +%s)"
    
    # vless://<uuid>@<host>:<port>?encryption=none&flow=xtls-rprx-vision&security=reality&sni=<sni>&fp=chrome&pbk=<pbk>&sid=<sid>&type=tcp&headerType=none#<name>
    VLESS_LINK="vless://${UUID}@${IP_ADDR}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SERVER_NAME}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp#${NODE_NAME}"

    echo -e "=================================================="
    log_success "节点配置信息:"
    echo -e "  ${YELLOW}地址 (Address):${NC} ${IP_ADDR}"
    echo -e "  ${YELLOW}端口 (Port):${NC} 443"
    echo -e "  ${YELLOW}UUID:${NC} ${UUID}"
    echo -e "  ${YELLOW}流控 (Flow):${NC} xtls-rprx-vision"
    echo -e "  ${YELLOW}加密 (Encryption):${NC} none"
    echo -e "  ${YELLOW}传输安全 (Security):${NC} reality"
    echo -e "  ${YELLOW}SNI:${NC} ${SERVER_NAME}"
    echo -e "  ${YELLOW}公钥 (Public Key):${NC} ${PUBLIC_KEY}"
    echo -e "  ${YELLOW}Short ID:${NC} ${SHORT_ID}"
    echo -e "  ${YELLOW}指纹 (Fingerprint):${NC} chrome"
    echo -e "=================================================="
    log_success "VLESS 导入链接:"
    echo -e "${GREEN}${VLESS_LINK}${NC}"
    echo -e "=================================================="
    log_success "二维码 (请使用客户端扫描):"
    qrencode -t ANSIUTF8 "${VLESS_LINK}"
    echo -e "=================================================="
}

#--- Main Menu ---#
main_menu() {
    clear
    echo "===================================================="
    echo -e "  ${CYAN}Sing-Box VLESS Reality 一键管理脚本${NC}"
    echo "===================================================="
    echo -e "  ${GREEN}1. 安装 Sing-Box${NC}"
    echo -e "  ${GREEN}2. 卸载 Sing-Box${NC}"
    echo "----------------------------------------------------"
    echo -e "  ${YELLOW}3. 更新 Sing-Box${NC}"
    echo -e "  ${YELLOW}4. 重启 Sing-Box${NC}"
    echo -e "  ${YELLOW}5. 查看节点信息${NC}"
    echo "----------------------------------------------------"
    echo -e "  ${RED}0. 退出脚本${NC}"
    echo "===================================================="
    
    read -r -p "请输入选项 [0-5]: " choice
    case ${choice} in
    1)
        install_sing-box
        ;;
    2)
        uninstall_sing-box
        ;;
    3)
        update_sing-box
        ;;
    4)
        systemctl restart sing-box
        log_success "Sing-box 已重启。"
        ;;
    5)
        display_node_info
        ;;
    0)
        exit 0
        ;;
    *)
        log_error "无效的选项，请输入正确的数字。"
        ;;
    esac
}

#--- Script Entry Point ---#
check_root
check_os

if [[ $# -gt 0 ]]; then
    case $1 in
        install)
            install_sing-box
            ;;
        uninstall)
            uninstall_sing-box
            ;;
        update)
            update_sing-box
            ;;
        info)
            display_node_info
            ;;
        *)
            main_menu
            ;;
    esac
else
    main_menu
fi
