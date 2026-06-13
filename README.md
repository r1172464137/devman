# devman — OpenWrt 设备管理器

实时设备监控与网络控制面板。

## 功能特性

| 功能 | 说明 |
|------|------|
| 自动发现 | `ip neigh` + conntrack，零主动探测 |
| DHCP 指纹 | eBPF AF_PACKET 原始套接字捕获 DHCP Option 60+55 |
| 设备识别 | MAC OUI 厂商识别（Apple/Samsung/Xiaomi/Huawei 等）+ 随机 MAC 检测 |
| 速度监控 | 基于 conntrack 字节差分的实时流量统计 |
| 封禁 | nftables set，O(1) 匹配，毫秒级生效 |
| 限速 | nft mark + tc HTB + IFB 双方向精确限速 |
| 设备合并 | DHCP 指纹自动去重，隐私随机 MAC 下保持设备历史 |
| 持久化 | SQLite /etc/devman/devman.db |

## 项目结构

```
devman/
├── devman/                  # Go 守护进程（纯 Go，零 shell 脚本）
│   ├── src/main.go          # ~1100 行，单文件
│   └── src/go.mod           # SQLite 依赖
├── luci-app-devman/         # LuCI 卡片式前端
│   ├── luasrc/controller/   # Lua API 代理
│   ├── root/usr/share/luci/ # 视图 + 菜单
│   └── po/                  # 中文翻译
├── Makefile                 # 顶层构建
└── README.md
```

## 编译

```bash
# Go 守护进程
make

# OpenWrt 软件包
make package/new/devman/compile V=s
make package/new/luci-app-devman/compile V=s
```

## API 接口

| 路由 | 方法 | 说明 |
|------|------|------|
| `/api/devices` | GET | 设备列表（触发速度计算） |
| `/api/block` | POST | 封禁/解封 `{device_id, block}` |
| `/api/limit` | POST | 限速/重命名 `{device_id, rate_limit, rate_limit_down, alias}` |
| `/api/dhcp-event` | POST | DHCP 指纹上报 |

## 依赖

| 类型 | 包名 | 用途 |
|------|------|------|
| 内核模块 | `kmod-ifb` | IFB 虚拟网卡，上路限速 |
| 内核模块 | `kmod-sched-core` | HTB 队列 + fw 过滤器 |
| 内核模块 | `kmod-sched-act-police` | ingress police 丢包动作 |
| 内核模块 | `kmod-sched-act-mirred` | mirred 流量重定向 |
| 用户空间 | `tc-tiny` 或 `tc-full` | tc 命令行工具 |
| 用户空间 | `nftables` (firewall4) | 封禁 + mark |
| 内核 | eBPF (CONFIG_DEBUG_INFO_BTF) | DHCP 嗅探（可选，回退 AF_PACKET） |
| 数据库 | `libsqlite3` | 设备持久化 |

## 编译依赖

- Go 1.21+
- OpenWrt SDK / Buildroot

## 许可

MIT
