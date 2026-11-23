# SysPro Linux Deep Infrastructure Optimizer（v6.1）使用文档

## 1. 项目简介

**SysPro** 是一个面向 Linux 服务器的深度基础设施优化脚本，支持 x86_64 与 ARM 架构（Oracle Cloud ARM、树莓派、Apple Silicon 虚拟机等）。

版本沿革：

- **v5.9**：以"可回滚"为目标重写。所有内核参数在改动前先记快照，卸载时按原值逐条回放，不再套用硬编码的发行版默认值。
- **v6.0**：新增 bbrplus 内核的安装 / 验证 / 回退（限 amd64 + Debian/Ubuntu），提供非交互 CLI 子命令，修复内核卸载后引导假成功等缺陷。
- **v6.1**：DNS 选优从 nftx 迁入——探测驱动、协议族无关，只剔除实测不可达的 nameserver；`configure_dns` 自动应用，并提供 `dns check/apply` CLI。

### 核心亮点

- **可回滚**：改动前记录原值快照（`/var/lib/syspro/state.env`），卸载时逐条还原，不误删用户已有配置。
- **全架构支持**：amd64、arm64、armhf 无缝兼容。
- **存储保护**：针对 SD 卡/eMMC 优化 I/O 调度，延长寿命并减少卡顿。
- **内存增强**：智能配置 ZRAM 内存压缩和动态 Swap 文件。
- **连接稳定**：SSH 防断连优化、DoH 加密解析，以及探测驱动的 DNS 选优。
- **bbrplus 内核**：带预检、下载校验、一次性启动项与安全回退的完整流程。
- **安全操作**：内核级隐私保护、危险操作拦截。

---

## 2. 适用系统

脚本支持以下 Linux 发行版（需 Root 权限）：

- **Debian**：10 / 11 / 12 / 13
- **Ubuntu**：20.04 / 22.04 / 24.04
- **CentOS / AlmaLinux / Rocky**：7 / 8 / 9
- **Fedora**（已适配，但未做完整验证，请谨慎使用）

---

## 3. 快速开始

### 3.1 下载与运行

```bash
curl -fsSL https://raw.githubusercontent.com/baichal/syspro/main/syspro.sh -o syspro.sh && chmod +x syspro.sh && sudo ./syspro.sh
```

查看非交互子命令：

```bash
bash syspro.sh help
```

### 3.2 界面交互

运行脚本后的主菜单：

| 选项 | 功能 |
| --- | --- |
| `0` | 一键执行所有优化（推荐：先运行此项，重启后再跑 nftx_auto.sh） |
| `1` | I/O 优化（Noatime、Udev 调度） |
| `2` | CPU 与熵池（调度器参数、BBR 适配） |
| `3` | 进程与内存（禁用 Auditd、智能 ZRAM、文件句柄） |
| `4` | 安全配置（隐藏内核地址、dmesg 限制） |
| `5` | 接入与 DNS（SSH、DoH/UDP 双模 + DNS 探测选优） |
| `6` | 维护与清理（常用工具、时区、缓存清理） |
| `7` | 手动管理工具（bbrplus 内核 / 卸载内核 / 其他 BBR） |
| `a` | 网络底座（模块预载 / 容量地板，为 nftx 预留空间） |
| `9` | 关闭日志系统（停 syslog/kdump，journald 只转发不落盘） |
| `8` | 卸载 / 还原（还原系统默认状态） |
| `q` | 退出 |

---

## 4. 功能模块详解

### [1] 深度 I/O 优化

- **Noatime**：修改 `/etc/fstab`，禁止文件访问时间写入，大幅减少磁盘 I/O。
- **智能调度器**：NVMe 使用 `none`；SSD / MMC（SD 卡）使用 `mq-deadline`；HDD 使用 `bfq`。
- **Fstrim**：自动配置 Flash 存储的 TRIM 操作。

### [2] 算力与熵池

- **Haveged**：智能检测内核版本，旧内核（<5.6）安装 Haveged 补充随机数熵池。
- **CPU 模式**：物理机锁定 CPU 为 `performance` 并记下原 governor，卸载时按原值还原（跳过虚拟机）；可选 C0 状态优化，同样可撤回。

### [3] 进程与内存

- **Systemd 优化**：缩短服务停止超时时间，禁用 Core Dump；只记录被改动单元的原状态，卸载时只恢复到这个状态。
- **OOM 保护**：为 SSH 和 Systemd 进程设置 `oom_score_adj = -1000`，防止内存耗尽时服务器失联。
- **ZRAM**：启用内存压缩；卸载前读回换出页，避免丢失仍在 swap 中的数据。
- **智能 Swap**：按内存情况创建 Swap 文件，支持 Btrfs（No-CoW）与 Ext4（fallocate），并标记"由本脚本创建"以免误删。

### [4] 安全加固

- **内核参数**：隐藏内核指针地址，限制非特权用户读取 dmesg，禁用危险的 SysRq 键。
- **日志系统**：可选关闭 syslog / kdump，journald 只转发不落盘。

### [5] 接入与 DNS

- **SSH 优化**：关闭 DNS 反查和 GSSAPI 认证，加快登录；重启前校验配置。
- **DNS 模式**：标准 UDP 与 DoH 双模，自动处理 systemd-resolved 冲突。DoH 后端自动选择：新版 cloudflared 已移除 proxy-dns，脚本会自动切换到 dnscrypt-proxy（apt 源提供、活跃维护）；两者对外一致（syspro-doh.service 监听 127.0.0.1:53）。
- **DNS 选优（v6.1）**：逐个实测 nameserver，只剔除实测不可达的项，IPv4 / IPv6 一视同仁；全不可达时保守不动，apply 前自动备份，原子重写配置文件。

### [6] 维护与清理

- **常用工具**：安装 curl、wget、htop、nano、vim、unzip 等。
- **时间同步**：安装 Chrony 并配置激进同步策略。
- **时区设置**：交互式选择常用时区（北京、香港、东京、美西、美东等）。
- **日志清理**：限制 Systemd 日志体积为 100M。

### [7] 手动管理工具与 bbrplus

- **卸载旧内核**：可视化列表选择，禁止卸载当前运行内核，自动修正 GRUB 默认项。
- **bbrplus 内核（v6.0+）**：完整流程具备预检、下载解包校验、一次性启动项、重启后确认与回退信息独立持久化。
  - 仅限 amd64 + Debian/Ubuntu。
  - 第三方 BBR 内核在 ARM 机器上有无法开机的风险，请务必留意脚本内的警告。

---

## 5. 非交互 CLI（自动化 / 巡检 / 测试）

除 `bbrplus-install` 会实际改动系统外，其余子命令均为只读：

```bash
bash syspro.sh help
bash syspro.sh bbrplus-status                  # 只读查看内核 / cc / grub 默认项 / 回滚信息
bash syspro.sh bbrplus-check                   # 真实预检 + 下载并解包校验 bbrplus deb（不安装）
bash syspro.sh bbrplus-install [--yes] [--force] [--reboot]
bash syspro.sh bbrplus-confirm                 # 重启进新内核后验证并设为持久默认
bash syspro.sh bbrplus-rollback                # 恢复原 GRUB 默认项，清一次性启动项
bash syspro.sh dns [check|apply] [文件]         # 默认 check；只剔除实测不可达的 nameserver
bash syspro.sh selftest                        # 只读自检（函数完整性 / 语法 / 环境）
bash syspro.sh plan                            # dry-run 预览：列出一键优化将执行的模块（不改系统）
bash syspro.sh status-json                     # 巡检用 JSON 格式状态输出（只读）
```

`dns check` 只报告不修改配置；`dns apply` 会写入 resolv.conf（默认 `/etc/resolv.conf`），不支持软链接。
`plan` 只打印执行计划、不做任何写操作，适合先看清楚再决定是否执行优化。`status-json` 输出 kernel / cc / bbrplus 状态与阶段等字段，便于巡检系统采集。

关于 bbrplus 阶段：`bbrplus-status` 与 `status-json` 中的 `阶段` 字段取值 `installed`（已安装待重启确认）→ `confirmed`（已设为持久默认）→ `rolled-back`（已回退）；旧版本安装的机器该字段显示 `unknown`，不影响回退功能。

---

## 6. 自定义 DNS

运行前用文本编辑器修改脚本顶部的**用户配置区**：

```bash
DNS_IPV4_LIST="..."
DNS_IPV6_LIST="..."
DOH_URL_LIST="..."
```

---

## 7. 卸载与还原

主菜单选择 `8. 卸载/还原`。脚本依据 `/var/lib/syspro/state.env` 中的快照逐条还原：

1. 移除 DoH 客户端和 ZRAM 配置（ZRAM 卸载前读回换出页）。
2. 删除由本脚本创建的 Swap 文件（保留系统原有分区 / 用户自有文件）。
3. 还原 `/etc/resolv.conf`、`/etc/fstab` 和 `/etc/ssh/sshd_config` 的备份。
4. 恢复被改动单元、内核参数、CPU governor 的原始状态。
5. 清理所有添加的定时任务和脚本。

---

## 8. 离线回归测试

上传真机之前可先运行只读静态检查（不修改系统、不产生假数据）：

```bash
bash tests/offline_selftest.sh
```

测试覆盖语法、结构、危险命令模式、heredoc 配对、v5.9 原有函数保留，以及 DNS 选优的桩测试等。真机运行时另用 `syspro.sh selftest`。

---

## 9. 常见问题（FAQ）

**Q1：为什么在树莓派上无法锁定 CPU 频率？**
A：树莓派的 CPU 频率调节通常由固件控制，或缺少相应内核模块。脚本检测不可写时会跳过，不会报错。

**Q2：开启 DoH 后 `/etc/resolv.conf` 指向 127.0.0.1 正常吗？**
A：正常。DoH 模式下本地运行加密 DNS 代理，上游走 DoH（新版 cloudflared 已废弃 proxy-dns，脚本会自动切换到 dnscrypt-proxy，上游 cloudflare DoH）。

**Q3：脚本卡在"安装 Cloudflared"？**
A：新版会自动切换到 dnscrypt-proxy（通过 apt 安装，无需 GitHub）。若卡在 apt 下载，请检查软件源连通性；旧环境仍需从 GitHub 下载 cloudflared 时，可配置代理或手动安装。

**Q4：可以在 Oracle ARM 机器上安装 BBR 吗？**
A：不建议使用第三方 BBR 内核，Oracle ARM 默认内核已足够优秀，随意换内核可能导致引导失败。

---

**版权说明**：本脚本为开源工具，请在理解代码的基础上使用。作者不对因使用本脚本造成的系统损坏或数据丢失承担责任。
