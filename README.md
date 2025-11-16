# Sing-Box VLESS Reality 一键管理脚本

一个 **完整、稳定、自动化** 的 sing-box VLESS + Reality 一键安装 / 升级 / 管理脚本。

脚本包含：

- Sing-Box 一键安装（自动生成 Reality 密钥、UUID、ShortID、配置文件）
- 自动开启 BBR + FQ
- 自带更新功能（从 GitHub 自动下载最新版本）
- 节点信息展示（含二维码）
- 自动端口占用检查与修改
- 自动生成 VLESS Reality 链接
- 自带快捷命令 `singbox`
- 支持 Debian / Ubuntu / CentOS / Rocky / AlmaLinux 等主流发行版

脚本版本：**v1.9.0**  
支持架构：**amd64 / arm64**

---

## ✨ 功能特性

### ✔ 一键安装 Sing-Box（VLESS + Reality）
- 自动检测 CPU 架构
- 自动从 GitHub 获取最新版 sing-box
- 自动生成 Reality keypair
- 自动随机选择高质量 SNI（支持手动自定义）
- 自动创建 systemd 服务

### ✔ 一键更新 sing-box（完整实现）
- 自动检测本地版本与最新版本
- 自动下载、替换、重启
- 无损更新配置文件

### ✔ 管理能力
- 重启 Sing-Box 服务
- 删除（卸载）Sing-Box + 配置 + 服务
- 查看配置信息（含二维码）
- 查看 BBR/FQ 状态
- 自动生成快捷命令 `singbox`

---

## 🚀 一键安装

复制粘贴即可运行（实时拉取最新脚本）：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/SpeedupMaster/sing-box/main/sing-box.sh)
```

安装完成后，你可以直接使用：

```bash
singbox
```

快速打开管理菜单。

---

## 📌 使用方法（主菜单）

运行：
```bash
singbox
```

你将看到如下菜单：

```
====================================================
  Sing-Box VLESS Reality 一键管理脚本 (v1.9.0)
====================================================
  1. 安装 Sing-Box         2. 卸载 Sing-Box
  3. 更新 Sing-Box         4. 重启 Sing-Box
  5. 查看节点信息        6. 检查 BBR+FQ 状态
----------------------------------------------------
  0. 退出脚本
====================================================
```

---

## 🔧 节点信息展示示例

脚本会自动生成：

- IP
- 端口
- UUID
- Reality 公钥
- Short ID
- SNI
- 完整的 VLESS Reality 链接
- 导入二维码

示例：

```
================ 节点配置信息 ================
  地址: 1.2.3.4
  端口: 443
  UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  Flow: xtls-rprx-vision
  Security: reality
  SNI: gateway.icloud.com
  公钥: XXXXXXXXXXXXXXXXXXXXX
  Short ID: abcd1234
================ VLESS 导入链接 ================
vless://UUID@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=gateway.icloud.com&fp=chrome&pbk=PUBLIC_KEY&sid=abcd1234&type=tcp#vps-xxxxxx
===================== 二维码 =====================
（ASCII二维码）
```

---

## 🔄 更新 Sing-Box

脚本已内置完整更新功能，自动检测最新版本：

```bash
singbox
```

选择：

```
3. 更新 Sing-Box
```

脚本会自动下载最新版并安全替换运行中的版本。

---

## ❌ 卸载 Sing-Box

非常干净的卸载流程：

- 删除二进制文件
- 删除 systemd 服务
- 删除配置目录
- 删除快捷命令

在菜单中选择：

```
2. 卸载 Sing-Box
```

---

## ⚙ BBR + FQ 自动优化

安装过程中会自动启用：

- net.core.default_qdisc=fq  
- net.ipv4.tcp_congestion_control=bbr  

你也可以随时检查：

```
6. 检查 BBR+FQ 状态
```

---

## 🧩 支持的系统

| 系统 | 支持 |
|------|------|
| Debian 9/10/11/12 | ✔ |
| Ubuntu 18/20/22/24 | ✔ |
| CentOS 7/Stream | ✔ |
| Rocky Linux | ✔ |
| AlmaLinux | ✔ |
| 其他 systemd Linux | ✔ |

---

## ⚙ 支持的架构

- amd64（x86_64）
- arm64（aarch64）

---

## 📄 常见问题 FAQ

### 1. 我能自定义 SNI 吗？
可以，安装时会询问输入，你可以填任意 TLS 网站。

### 2. 不填 SNI 会怎样？
脚本会从内置的高质量网站池中随机选择。

### 3. 能否重新查看节点信息？
可以，运行：

```
singbox -> 5
```

### 4. 如何重新生成密钥？
建议卸载后重新安装：

```
singbox -> 2
```

---

## 🧑‍💻 开发者说明

脚本安装后会保存到：

```
/usr/local/bin/singbox-manager
```

并设置快捷命令：

```
alias singbox='bash /usr/local/bin/singbox-manager'
```

---

## ⭐ 推荐用法

### 查看状态
```bash
systemctl status sing-box
```

### 查看日志
```bash
journalctl -u sing-box -f
```

---

## 📜 许可证

本项目采用 MIT License。
