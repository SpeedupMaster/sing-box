# Sing-Box VLESS Reality 一键管理脚本

[![Sing-Box](https://img.shields.io/badge/Sing--Box-Latest-blue?logo=github)](https://github.com/SagerNet/sing-box)
[![Shell](https://img.shields.io/badge/Language-Bash-green?logo=gnu-bash)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/License-GPLv3-orange)](https://www.gnu.org/licenses/gpl-3.0)

这是一个功能强大的 Linux Bash 脚本，用于在该 VPS 上一键部署和管理 **Sing-Box** 核心，并配置目前最先进的 **VLESS + Reality + XTLS-Vision** 协议。

脚本集成了端口占用检测、BBR 优化、自动更新、二维码生成等实用功能。

## ✨ 功能特性

*   **🚀 极速部署**: 采用 Sing-Box 官方核心，配置高性能 VLESS 协议。
*   **🔒 安全抗封**: 使用 Reality 协议 + Vision 流控，有效通过 GFW 防火墙检测，无需域名。
*   **🛠 端口智能管理**:
    *   自动扫描并列出系统当前已占用的端口。
    *   支持用户自定义端口（自动检测冲突）。
    *   支持**随机生成**未占用端口（2000-65535）。
*   **🔄 版本管理**: 自动检测 GitHub 最新版本并进行无缝升级。
*   **📡 伪装管理**: 内置常见的 Apple, Microsoft, Amazon 等大厂 SNI 域名，支持随机或自定义。
*   **⚡ 性能优化**: 内置各种 BBR + FQ 拥塞控制算法检测与启用功能。
*   **📱 便捷管理**: 生成 VLESS 链接及二维码，支持生成快捷指令 `singbox` 随时唤醒菜单。

## 🖥️ 系统要求

*   **操作系统**: Debian, Ubuntu, CentOS, Fedora, Rocky Linux, AlmaLinux 等主流 Linux 发行版。
*   **架构**: AMD64 (x86_64) 或 ARM64 (aarch64)。
*   **权限**: 需要 `root` 用户权限。

## 📥 安装与使用

### 方式一：一键安装（推荐）

```bash
wget -N --no-check-certificate https://raw.githubusercontent.com/SpeedupMaster/sing-box/main/sing-box.sh && bash sing-box.sh
```

### 方式二：手动下载运行

```bash
# 下载脚本
curl -O https://raw.githubusercontent.com/SpeedupMaster/sing-box/main/sing-box.sh

# 赋予执行权限
chmod +x sing-box.sh

# 运行脚本
./sing-box.sh
```

### 快捷命令

脚本安装成功后，系统会自动创建快捷别名。以后只需输入以下命令即可呼出管理菜单：

```bash
singbox
```

## 📋 菜单功能说明

运行脚本后，您将看到以下菜单：

1.  **安装 Sing-Box**: 引导式安装，选择端口、SNI，自动配置 Reality。
2.  **卸载 Sing-Box**: 彻底清除服务、二进制文件及配置文件。
3.  **更新 Sing-Box**: 检查 Sing-Box 官方 GitHub Release，保留配置升级内核。
4.  **重启 Sing-Box**: 重新加载服务。
5.  **查看节点信息**: 显示当前节点配置、VLESS 链接以及**二维码**。
6.  **检查 BBR+FQ 状态**: 检查系统 TCP 拥塞控制状态，并自动开启 BBR。

## 📱 客户端支持

本脚本配置的节点协议为 `VLESS + Reality + XTLS-Vision`，请确保您的客户端支持此协议：

*   **Android**: [v2rayNG](https://github.com/2dust/v2rayNG), [Sing-Box](https://github.com/SagerNet/sing-box-for-android), [Hiddify](https://github.com/hiddify/hiddify-app), [CMFA](https://github.com/MetaCubeX/ClashMetaForAndroid), [FlClash](https://github.com/chen08209/FlClash), [NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid)
*   **iOS**: Shadowrocket, Sing-Box, FoXray, Egern, Stash, Clash Mi, Hidify
*   **Windows**: [v2rayN](https://github.com/2dust/v2rayN), [Hiddify](https://github.com/hiddify/hiddify-app), [FlClash](https://github.com/chen08209/FlClash), [Clash Party](https://github.com/mihomo-party-org/clash-party), [Sparkle](https://github.com/xishang0128/sparkle), [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev)
*   **macOS**: [V2Box](https://apps.apple.com/us/app/v2box-v2ray-client/id6446814690), [Clash Party](https://github.com/mihomo-party-org/clash-party), [Sparkle](https://github.com/xishang0128/sparkle), [Hiddify](https://github.com/hiddify/hiddify-app), [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev), [FlClash](https://github.com/chen08209/FlClash)

## ⚠️ 免责声明

*   本脚本仅供网络技术研究和学习使用。
*   请勿用于非法用途，请遵守服务器所在国家及您所在国家的法律法规。
*   作者不对使用本脚本造成的任何后果负责。
