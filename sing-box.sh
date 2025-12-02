#!/usr/bin/env bash

#====================================================
# Script to install Sing-Box VLESS Reality on VPS
# Author: Your Name
# Version: 1.9.4 (Fixed Update Error for Pipe/Curl execution) 
#====================================================

#--- Colors & Global Variables ---# 
RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[0;33m' CYAN='\033[0;36m' NC='\033[0m' 
SINGBOX_CONFIG_PATH="/etc/sing-box" 
SINGBOX_CONFIG_FILE="${SINGBOX_CONFIG_PATH}/config.json" 
REALITY_PUB_KEY_FILE="${SINGBOX_CONFIG_PATH}/reality.pub" 
SINGBOX_BINARY_PATH="/usr/local/bin/sing-box" 
SINGBOX_SERVICE_FILE="/etc/systemd/system/sing-box.service" 
SCRIPT_PATH="/usr/local/bin/singbox-manager" 
SHORTCUT_NAME="singbox" 
LISTEN_PORT=443
# 请确保此 URL 指向您 GitHub raw 真实文件地址
SCRIPT_URL_BUILTIN="https://raw.githubusercontent.com/SpeedupMaster/sing-box/main/sing-box.sh" 
SCRIPT_URL_ARG="" 
SELECTED_SNI="" 
SNI_LIST=( 
    "gateway.icloud.com" "itunes.apple.com" "swdist.apple.com" "swcdn.apple.com" 
    "updates.cdn-apple.com" "mensura.cdn-apple.com" "osxapps.itunes.apple.com" 
    "aod.itunes.apple.com" "download-installer.cdn.mozilla.net" "addons.mozilla.org" 
    "s0.awsstatic.com" "d1.awsstatic.com" "cdn-dynmedia-1.microsoft.com" "www.cloudflare.com" 
    "images-na.ssl-images-amazon.com" "m.media-amazon.com" "dl.google.com" 
    "www.google-analytics.com" "www.microsoft.com" "software.download.prss.microsoft.com" 
    "player.live-video.net" "one-piece.com" "lol.secure.dyn.riotcdn.net" 
    "www.lovelive-anime.jp" "www.swift.com" "academy.nvidia.com" "www.cisco.com" 
    "www.samsung.com" "www.amd.com" 
) 

#--- Helper Functions & Prerequisite Checks ---# 
log_info() { echo -e "${CYAN}[INFO] ${1}${NC}"; } 
log_success() { echo -e "${GREEN}[SUCCESS] ${1}${NC}"; } 
log_warning() { echo -e "${YELLOW}[WARNING] ${1}${NC}"; } 
log_error() { echo -e "${RED}[ERROR] ${1}${NC}"; exit 1; } 
check_root() { [ "$(id -u)" -ne 0 ] && log_error "此脚本必须以 root 用户权限运行。"; } 
check_os() { source /etc/os-release; [[ ! "$ID" =~ ^(debian|ubuntu|centos|fedora|rocky|almalinux)$ ]] && log_error "此脚本仅支持主流 Linux 发行版。"; } 
pause_back() { read -n 1 -s -r -p $'\n按任意键返回主菜单...'; }

#--- Core Logic ---# 
install_dependencies() { 
    log_info "正在安装必要的依赖包..."; 
    if command -v apt-get &>/dev/null; then 
        apt-get update -y && apt-get install -y curl jq qrencode lsof; 
    elif command -v dnf &>/dev/null; then 
        dnf install -y curl jq qrencode lsof; 
    elif command -v yum &>/dev/null; then 
        yum install -y curl jq qrencode lsof; 
    else 
        log_error "无法找到包管理器。"; 
    fi; 
} 

# Check and Set Port
check_and_set_port() { 
    log_info "正在检测系统端口占用情况..."
    local occupied_ports=$(lsof -i -P -n | grep LISTEN | awk '{print $9}' | rev | cut -d':' -f1 | rev | sort -nu | tr '\n' ' ')
    
    echo -e "----------------------------------------------------"
    echo -e "${YELLOW}当前已被占用的端口列表:${NC}"
    echo -e "${YELLOW}${occupied_ports}${NC}"
    echo -e "----------------------------------------------------"

    while true; do 
        echo -e "${CYAN}请输入 sing-box 运行端口 (1-65535)${NC}"
        read -r -p "留空后直接回车将随机选择一个可用端口: " USER_PORT
        
        if [ -z "$USER_PORT" ]; then
            while true; do
                local rand_port=$((RANDOM % 63536 + 2000))
                if ! lsof -i:"${rand_port}" &>/dev/null; then
                    LISTEN_PORT=$rand_port
                    log_success "已随机生成可用端口: ${LISTEN_PORT}"
                    break 2
                fi
            done
        else
            if [[ "$USER_PORT" =~ ^[0-9]+$ ]] && [ "$USER_PORT" -gt 0 ] && [ "$USER_PORT" -lt 65536 ]; then
                if lsof -i:"${USER_PORT}" &>/dev/null; then
                    log_warning "端口 ${USER_PORT} 已被占用，请选择其他端口！"
                else
                    LISTEN_PORT=$USER_PORT
                    log_success "将使用端口: ${LISTEN_PORT}"
                    break
                fi
            else
                log_warning "输入无效，请输入 1-65535 之间的数字。"
            fi
        fi
    done 
} 

prompt_for_sni() { log_info "您可以指定一个 SNI 用于伪装流量。"; read -r -p "请输入 SNI，或直接按回车随机选择: " USER_SNI; if [ -z "$USER_SNI" ]; then RANDOM_INDEX=$((RANDOM % ${#SNI_LIST[@]})); SELECTED_SNI=${SNI_LIST[$RANDOM_INDEX]}; log_success "已随机选择 SNI: ${SELECTED_SNI}"; else SELECTED_SNI=$USER_SNI; log_success "将使用您指定的 SNI: ${SELECTED_SNI}"; fi; } 
install_bbr() { log_info "检查并安装 BBR..."; if ! sysctl -n net.ipv4.tcp_congestion_control | grep -q "bbr"; then echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf; echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf; sysctl -p &>/dev/null; fi; if sysctl -n net.ipv4.tcp_congestion_control | grep -q "bbr"; then log_success "TCP 拥塞控制算法已设置为 bbr。"; fi; if sysctl -n net.core.default_qdisc | grep -q "fq"; then log_success "队列调度算法已设置为 fq。"; fi; } 
check_bbr_status() { clear; log_info "正在检查 BBR 和 FQ 状态..."; sleep 1; local bbr_status=$(sysctl -n net.ipv4.tcp_congestion_control); local qdisc_status=$(sysctl -n net.core.default_qdisc); echo -e "================ BBR + FQ 状态检查 ================"; if [[ "$bbr_status" == "bbr" ]]; then echo -e "  ${GREEN}✅ TCP 拥塞控制算法: bbr (已启用)${NC}"; else echo -e "  ${RED}❌ TCP 拥塞控制算法: ${bbr_status} (BBR 未启用)${NC}"; fi; if [[ "$qdisc_status" == "fq" ]]; then echo -e "  ${GREEN}✅ 默认队列调度算法: fq (已启用)${NC}"; else echo -e "  ${YELLOW}⚠️  默认队列调度算法: ${qdisc_status} (建议使用 fq)${NC}"; fi; echo -e "=================================================="; pause_back; } 
generate_config() { log_info "正在生成密钥对和配置文件..."; mkdir -p "${SINGBOX_CONFIG_PATH}"; local UUID=$(${SINGBOX_BINARY_PATH} generate uuid); local KEY_PAIR=$(${SINGBOX_BINARY_PATH} generate reality-keypair); local PRIVATE_KEY=$(echo "${KEY_PAIR}" | awk '/PrivateKey/ {print $2}' | tr -d '"'); local PUBLIC_KEY=$(echo "${KEY_PAIR}" | awk '/PublicKey/ {print $2}' | tr -d '"'); local SHORT_ID=$(openssl rand -hex 8); echo "${PUBLIC_KEY}" > "${REALITY_PUB_KEY_FILE}"; cat > "${SINGBOX_CONFIG_FILE}" <<EOF
{ "log": {"level": "info", "timestamp": true}, "inbounds": [{"type": "vless", "tag": "vless-in", "listen": "::", "listen_port": ${LISTEN_PORT}, "sniff": true, "users": [{"uuid": "${UUID}", "flow": "xtls-rprx-vision"}], "tls": { "enabled": true, "server_name": "${SELECTED_SNI}", "reality": { "enabled": true, "handshake": {"server": "${SELECTED_SNI}", "server_port": 443}, "private_key": "${PRIVATE_KEY}", "short_id": ["${SHORT_ID}"] } } }], "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}] } 
EOF
} 
create_service() { log_info "正在创建 systemd 服务..."; cat > "${SINGBOX_SERVICE_FILE}" <<EOF
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

update_sing-box() { 
    clear
    log_info "开始更新 sing-box 内核..." 
    if [ ! -f "${SINGBOX_BINARY_PATH}" ]; then
        log_error "sing-box 未安装，无法执行更新。请先安装。" 
        pause_back
        return
    fi

    local CURRENT_VERSION=$(${SINGBOX_BINARY_PATH} version | awk 'NR==1{print $3}') 
    log_info "当前版本: v${CURRENT_VERSION}" 

    log_info "正在从 GitHub 获取最新版本信息..." 
    local LATEST_VERSION=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r ".tag_name" | sed 's/v//') 
    if [ -z "$LATEST_VERSION" ]; then
        log_error "无法获取最新的 sing-box 版本号，请检查网络或稍后再试。" 
        pause_back
        return
    fi
    log_info "最新版本: v${LATEST_VERSION}" 

    if [ "$CURRENT_VERSION" == "$LATEST_VERSION" ]; then
        log_success "您已安装最新版本，无需更新。" 
        pause_back
        return
    fi

    log_info "发现新版本，准备更新..." 
    
    local ARCH=$(uname -m) 
    case ${ARCH} in
        x86_64) ARCH="amd64" ;; 
        aarch64) ARCH="arm64" ;; 
        *) log_error "不支持的系统架构: ${ARCH}" ;; 
    esac
    
    local DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/sing-box-${LATEST_VERSION}-linux-${ARCH}.tar.gz" 
    log_info "正在下载新版本..." 
    curl -fsSL -o /tmp/sing-box.tar.gz "${DOWNLOAD_URL}" || log_error "下载失败。" 
    
    log_info "停止当前 sing-box 服务..." 
    systemctl stop sing-box
    
    log_info "解压并替换二进制文件..." 
    tar -xzf /tmp/sing-box.tar.gz -C /tmp
    mv "/tmp/sing-box-${LATEST_VERSION}-linux-${ARCH}/sing-box" "${SINGBOX_BINARY_PATH}" 
    chmod +x "${SINGBOX_BINARY_PATH}" 
    
    log_info "清理临时文件..." 
    rm -rf /tmp/sing-box* 
    
    log_info "启动 sing-box 服务..." 
    systemctl start sing-box
    
    if systemctl is-active --quiet sing-box; then
        local NEW_VERSION=$(${SINGBOX_BINARY_PATH} version | awk 'NR==1{print $3}') 
        log_success "sing-box 已成功更新至 v${NEW_VERSION} 并已启动！" 
    else
        log_error "更新后启动 sing-box 失败，请使用 'journalctl -u sing-box' 查看日志。" 
    fi
    pause_back 
} 

# Function: Update the Script Itself (Safe Mode)
update_script() {
    clear
    log_info "准备更新管理脚本..."
    
    local url="${SCRIPT_URL_BUILTIN}"
    if [ -n "$SCRIPT_URL_ARG" ]; then
        url="$SCRIPT_URL_ARG"
    fi
    
    # 检测是否是通过 pipe / curl 运行的 (fd 模式)
    # 如果 $0 包含 /dev/fd 或者只是 "bash"，说明不是实体文件
    local is_piped=false
    if [[ "$0" == *"/dev/fd"* ]] || [[ "$0" == "bash" ]]; then
        is_piped=true
    else
        # 尝试获取真实路径
        if ! realpath "$0" &>/dev/null; then
             is_piped=true
        fi
    fi

    log_info "正在获取最新脚本: ${url}"
    if curl -fsSL -o /tmp/singbox_new.sh "${url}"; then
        # 简单检查内容
        if grep -q "#!/usr/bin/env bash" /tmp/singbox_new.sh || grep -q "#!/bin/bash" /tmp/singbox_new.sh; then
            
            if [ "$is_piped" = true ]; then
                # 管道模式：无法覆盖 $0，直接更新到默认安装路径
                log_warning "检测到当前脚本通过 URL 直接运行。"
                log_info "新脚本将安装到系统路径: ${SCRIPT_PATH}"
                mv /tmp/singbox_new.sh "${SCRIPT_PATH}"
                chmod +x "${SCRIPT_PATH}"
                log_success "脚本已更新！"
                log_info "请使用命令 '${SHORTCUT_NAME}' 重新启动脚本。"
                exit 0
            else
                # 实体文件模式：覆盖当前文件
                mv /tmp/singbox_new.sh "$0"
                chmod +x "$0"
                log_success "脚本文件已更新！"
                log_info "正在重新加载新脚本..."
                sleep 2
                exec "$0" "$@"
            fi
        else
            log_error "下载的文件验证失败，更新取消。"
            rm -f /tmp/singbox_new.sh
            pause_back
        fi
    else
        log_error "下载失败，请检查网络。"
        pause_back
    fi
}

save_script() { log_info "正在保存管理脚本..."; local final_url_to_save=""; if [ -n "$SCRIPT_URL_ARG" ]; then final_url_to_save="$SCRIPT_URL_ARG"; log_info "检测到外部 URL 参数，将使用该地址。"; else final_url_to_save="$SCRIPT_URL_BUILTIN"; log_info "将使用内置地址进行保存。"; fi; if curl -fsSL -o "${SCRIPT_PATH}" "${final_url_to_save}"; then chmod +x "${SCRIPT_PATH}"; sed -i "/alias ${SHORTCUT_NAME}=/d" ~/.bashrc; echo "alias ${SHORTCUT_NAME}='bash ${SCRIPT_PATH} ${final_url_to_save}'" >> ~/.bashrc; log_success "已创建或更新快捷命令 '${SHORTCUT_NAME}'。"; log_info "请运行 'source ~/.bashrc' 或重新登录SSH。"; else log_error "从 ${final_url_to_save} 下载脚本失败。"; fi; } 
install_sing-box() { log_info "开始安装 sing-box..."; [ -f "${SINGBOX_CONFIG_FILE}" ] && log_error "sing-box 已安装，请不要重复执行。"; install_dependencies; check_and_set_port; prompt_for_sni; ARCH=$(uname -m); case ${ARCH} in x86_64) ARCH="amd64" ;; aarch64) ARCH="arm64" ;; *) log_error "不支持的系统架构: ${ARCH}" ;; esac; LATEST_VERSION=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r ".tag_name" | sed 's/v//'); [ -z "$LATEST_VERSION" ] && log_error "获取 sing-box 版本号失败。"; DOWNLOAD_URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/sing-box-${LATEST_VERSION}-linux-${ARCH}.tar.gz"; log_info "正在下载 sing-box v${LATEST_VERSION}..."; curl -fsSL -o /tmp/sing-box.tar.gz "${DOWNLOAD_URL}" || log_error "下载失败。"; tar -xzf /tmp/sing-box.tar.gz -C /tmp; mv "/tmp/sing-box-${LATEST_VERSION}-linux-${ARCH}/sing-box" "${SINGBOX_BINARY_PATH}"; chmod +x "${SINGBOX_BINARY_PATH}"; generate_config; create_service; install_bbr; save_script; systemctl daemon-reload; systemctl enable sing-box; systemctl start sing-box; if systemctl is-active --quiet sing-box; then log_success "sing-box 安装并启动成功！"; display_node_info; else log_error "sing-box 启动失败，请检查日志：journalctl -u sing-box --no-pager -l"; fi; rm -rf /tmp/sing-box*; } 
uninstall_sing-box() { log_warning "确定要卸载 sing-box 吗? [y/N]"; read -r -p "请输入: " confirm; [[ ! "$confirm" =~ ^[yY]$ ]] && log_info "卸载操作已取消。" && pause_back && return; systemctl stop sing-box; systemctl disable sing-box; rm -f "${SINGBOX_SERVICE_FILE}" "${SINGBOX_BINARY_PATH}" "${SCRIPT_PATH}"; rm -rf "${SINGBOX_CONFIG_PATH}"; if grep -q "alias ${SHORTCUT_NAME}=" ~/.bashrc; then sed -i "/alias ${SHORTCUT_NAME}=/d" ~/.bashrc; log_info "已移除快捷命令。"; fi; systemctl daemon-reload; log_success "sing-box 已成功卸载。"; pause_back; } 
display_node_info() { if [ ! -f "${SINGBOX_CONFIG_FILE}" ] || [ ! -f "${REALITY_PUB_KEY_FILE}" ]; then log_error "配置文件或公钥文件不存在。"; return; fi; local CFG_PORT=$(jq -r '.inbounds[0].listen_port' "${SINGBOX_CONFIG_FILE}"); local UUID=$(jq -r '.inbounds[0].users[0].uuid' "${SINGBOX_CONFIG_FILE}"); local PUBLIC_KEY=$(cat "${REALITY_PUB_KEY_FILE}"); local SHORT_ID=$(jq -r '.inbounds[0].tls.reality.short_id[0]' "${SINGBOX_CONFIG_FILE}"); local SERVER_NAME=$(jq -r '.inbounds[0].tls.server_name' "${SINGBOX_CONFIG_FILE}"); local IP_ADDR=$(curl -s4 ip.sb || curl -s4 ifconfig.me); local NODE_NAME="vps-$(date +%s)"; if [ -z "$PUBLIC_KEY" ]; then log_error "无法读取公钥，请卸载后重装。"; return; fi; local VLESS_LINK="vless://${UUID}@${IP_ADDR}:${CFG_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SERVER_NAME}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp#${NODE_NAME}"; clear ; echo -e "================ 节点配置信息 ================"; echo -e "  地址 (Address): ${IP_ADDR}\n  端口 (Port): ${CFG_PORT}\n  UUID: ${UUID}\n  流控 (Flow): xtls-rprx-vision\n  安全 (Security): reality\n  SNI: ${SERVER_NAME}\n  公钥 (pbk): ${PUBLIC_KEY}\n  Short ID (sid): ${SHORT_ID}\n  指纹 (fp): chrome"; echo -e "================ VLESS 导入链接 ================" ; echo -e "${GREEN}${VLESS_LINK}${NC}"; echo -e "===================== 二维码 =====================" ; qrencode -t ANSIUTF8 "${VLESS_LINK}"; pause_back; } 

main_menu() { 
    while true; do
        clear
        echo "====================================================" 
        echo "  Sing-Box VLESS Reality 一键管理脚本 (v1.9.4)" 
        echo "====================================================" 
        echo "  1. 安装 Sing-Box         2. 卸载 Sing-Box" 
        echo "  3. 更新 Sing-Box (内核)  4. 重启 Sing-Box" 
        echo "  5. 查看节点信息        6. 检查 BBR+FQ 状态" 
        echo "  7. 更新管理脚本 (本脚本)"
        echo "  --------------------------------------------------" 
        echo "  0. 退出脚本" 
        echo "====================================================" 
        read -r -p "请输入选项 [0-7]: " choice
        case ${choice} in
            1) install_sing-box ;; 
            2) uninstall_sing-box ;; 
            3) update_sing-box ;; 
            4) systemctl restart sing-box && log_success "Sing-box 已重启。" || log_error "操作失败或服务未安装。"; pause_back ;; 
            5) display_node_info ;; 
            6) check_bbr_status ;; 
            7) update_script ;; 
            0) exit 0 ;; 
            *) log_error "无效选项。"; pause_back ;; 
        esac
    done
} 

#--- Script Entry Point ---# 
check_root; check_os; if [[ "$1" == http* ]]; then SCRIPT_URL_ARG="$1"; shift; fi; main_menu
