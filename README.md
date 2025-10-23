# 一键安装 sing-box（VLESS + REALITY）并启用 BBR+fq

本项目提供一份在常见 Linux VPS 上的一键脚本，快速搭建 sing-box（内核）服务，使用 VLESS + REALITY 协议，并支持一键安装/启用 BBR+fq 网络加速。脚本包含管理菜单，支持安装、更新、卸载、查看节点信息等。同时提供“远程短命令”与本地快捷命令“singbox”。

## 功能特性

- 一键安装/更新/卸载 sing-box（VLESS + REALITY）
- 自动检测 443 端口占用（如被 Nginx 占用则默认改用 8443）
- 自动生成并持久化节点参数（UUID、Reality 私钥/公钥、short_id）
- 输出完整客户端参数与 vless 导入链接（可直接导入 v2rayN/v2rayNG）
- 安装并启用 BBR+fq 网络加速（内核不支持时可选升级内核并提示重启）
- 自动创建快捷命令：输入 `singbox` 即可打开管理菜单
- 防火墙自动放行端口（支持 ufw 或 firewalld）

## 支持环境

- 系统：Debian 11/12、Ubuntu 20.04/22.04/24.04、CentOS/AlmaLinux/Rocky 8/9
- 架构：amd64、arm64
- 需要 root 权限执行（使用 sudo 或 root 用户）

## 快速开始

一键远程执行（短命令，脚本会自安装并创建快捷命令 singbox）：

- 使用 curl：
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/SpeedupMaster/sing-box/main/sing-box.sh)
```

- 使用 wget：
```bash
bash <(wget -qO- https://raw.githubusercontent.com/SpeedupMaster/sing-box/main/sing-box.sh)
```

首次执行后，脚本会将自身安装到 `/usr/local/bin/singboxctl`，并创建快捷命令 `/usr/local/bin/singbox`。之后可以直接运行：

```bash
singbox
```

## 管理菜单与命令

运行 `singbox` 或执行脚本，将看到管理菜单：

- 1) 安装/初始化
- 2) 更新 sing-box 到最新版本
- 3) 重启服务
- 4) 查看节点信息与导入链接
- 5) 卸载
- 6) 安装/启用 BBR+fq
- 0) 退出

也可以使用命令行参数直接操作：
```bash
# 查看菜单
singbox

# 直接安装/初始化
sudo singbox install

# 更新 sing-box 到最新版本
sudo singbox update

# 重启服务
sudo singbox restart

# 查看节点信息与导入链接
singbox info

# 安装/启用 BBR+fq
sudo singbox bbr

# 卸载
sudo singbox uninstall
```

## 安装流程简述

- 检测系统与架构，安装依赖（curl、tar、jq、openssl、systemd、iproute 等）
- 下载 sing-box 最新版本并安装到 `/usr/local/bin/sing-box`
- 根据交互输入，生成并写入服务端配置 `/etc/sing-box/config.json`
- 生成 UUID、Reality 私钥/公钥、short_id，写入元数据 `/etc/sing-box/reality.meta.json`
- 创建并启动 systemd 服务 `/etc/systemd/system/sing-box.service`
- 开放防火墙端口（如 ufw/firewalld）
- 输出客户端使用信息与 vless 导入链接（可直接复制到 v2rayN/v2rayNG）

注：
- 如果检测到 443 端口被占用（例如 Nginx），脚本默认监听端口改为 8443。
- 握手域名（SNI）应为可正常提供 TLS 的真实网站域名，例如：www.cloudflare.com、www.bing.com、www.wikipedia.org。

## 客户端配置示例

安装完成后，脚本会打印节点信息与 vless 导入链接。例如：

- vless 导入链接（示例，实际以脚本输出为准）：
```
vless://UUID@地址:端口?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&pbk=PUBLIC_KEY&sid=SHORT_ID&sni=SNI_DOMAIN&fp=chrome#VLESS-REALITY
```

- sing-box 客户端 outbound 配置片段（示例）：
```json
{
  "type": "vless",
  "server": "你的服务器域名或IP",
  "server_port": 8443,
  "uuid": "你的UUID",
  "flow": "xtls-rprx-vision",
  "transport": { "type": "tcp" },
  "tls": {
    "enabled": true,
    "server_name": "握手域名（SNI）",
    "reality": {
      "enabled": true,
      "public_key": "Reality 公钥",
      "short_id": "Reality short_id"
    }
  }
}
```

## 与 Nginx 共享 443（可选进阶）

若你必须继续使用 443 并同时提供 Web 与 Reality，可使用 Nginx stream 的 SNI 分流，将特定 SNI（如伪装域名）转发到 sing-box，其它域名转发到 Web。

示例（需启用 Nginx stream 模块）：
```nginx
stream {
  map $ssl_preread_server_name $route {
    ~^(www\.cloudflare\.com|www\.bing\.com|www\.wikipedia\.org)$ singbox;
    default web;
  }
  upstream singbox_backend { server 127.0.0.1:8443; } # sing-box 监听端口
  upstream web_backend    { server 127.0.0.1:443; }   # 你的原有服务（或更改端口）

  server {
    listen 443 reuseport;
    proxy_pass $route;
    ssl_preread on;
  }
}
# 验证并重载
# nginx -t && systemctl reload nginx
```

注意：
- Reality 客户端的 SNI 是伪装域名（你在安装时输入的 SNI），将此域名分流到 sing-box 即可。
- 如果不需要共享 443，建议直接使用 8443（或其他未占用端口），配置更简单。

## BBR+fq 加速

脚本提供一键安装/启用 BBR+fq 的选项：

- 已支持 BBR 的内核：直接写入 sysctl 参数并启用。
- 不支持 BBR 的内核：可选择自动安装较新内核（Ubuntu 安装 linux-generic，Debian 可选 backports 的 linux-image-amd64，EL 系列通过 elrepo 安装 kernel-ml），安装后需要重启，再运行菜单 6 启用。

验证 BBR+fq 是否启用：
```bash
sysctl -n net.ipv4.tcp_congestion_control   # 应为 bbr
sysctl -n net.core.default_qdisc            # 应为 fq
uname -r                                    # 查看当前内核版本
```

## 常见问题

- 443 端口被占用怎么办？
  - 脚本会检测并默认改用 8443。也可参考“与 Nginx 共享 443（可选进阶）”实现共用 443。

- 安装后无法连接？
  - 检查防火墙是否放行端口（脚本已尝试自动放行）。
  - 确认客户端的 SNI 与服务端 handshake.server 一致，且为真实 TLS 网站。
  - 查看服务日志：`journalctl -u sing-box -f`
  - 检查配置文件：`/etc/sing-box/config.json`，修改后重启服务：`sudo systemctl restart sing-box`

- GitHub 下载失败或速度慢？
  - 尝试使用网络代理或镜像源，或在国内服务器上使用中转/加速服务。
  - 你也可以将 sing-box 二进制预先上传到你的服务器并替换脚本的下载逻辑。

- IPv6/IPv4 访问问题？
  - 脚本默认监听 `::`（IPv6 any）；一般情况下可同时接收 IPv4/IPv6。如你的环境不兼容，可将配置中的 `listen` 改为 `"0.0.0.0"` 并重启服务。

## 更新与卸载

- 更新：
```bash
sudo singbox update
```
会下载 sing-box 最新版本并重启服务。

- 卸载：
```bash
sudo singbox uninstall
```
提供两种卸载方式：删除全部（二进制与配置）或仅删除服务（保留二进制与配置）。

## 文件结构

- 二进制：`/usr/local/bin/sing-box`
- 配置目录：`/etc/sing-box/`
  - 主配置：`/etc/sing-box/config.json`
  - 元数据：`/etc/sing-box/reality.meta.json`
- systemd 服务：`/etc/systemd/system/sing-box.service`
- 脚本本体：`/usr/local/bin/singboxctl`
- 快捷命令：`/usr/local/bin/singbox`
- BBR 配置：`/etc/sysctl.d/99-bbr-fq.conf`

## 安全与建议

- 请妥善保管 Reality 私钥与 UUID。脚本不会将私钥对外输出。
- 握手域名请选用稳定的 TLS 网站，且尽量避免与真实业务域名冲突。
- 若在高限制网络环境，尽量使用 443 端口，配合 Nginx stream 分流；或选择常见开放端口（如 8443/2053）。
- 定期更新 sing-box 至最新版本，以获得修复与性能提升。

## 许可证与致谢

- 脚本依赖于 sing-box 项目（SagerNet/sing-box）。感谢开源社区的贡献。
- 本脚本以“按现状”提供，使用风险自负。欢迎自行修改与扩展菜单功能（如多用户、端口变更、重生成密钥等）。
