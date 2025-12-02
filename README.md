# SysPro Linux Deep Infrastructure Optimizer (v5.3 ARM 增强版) 使用文档

## 1. 项目简介

**SysPro v5.3** 是一个专为 Linux 服务器设计的深度基础设施优化脚本。此版本特别针对 **ARM 架构**（如 Oracle Cloud ARM 实例、Raspberry Pi 树莓派、Apple Silicon 虚拟机）进行了全量适配，同时也完美支持标准的 x86_64 服务器。

它不仅仅是简单的参数修改，更包含了对存储调度、内存压缩 (ZRAM)、DNS 安全 (DoH)、进程防杀 (OOM Protect) 等底层机制的深度调优。

### 核心亮点
*   **全架构支持**：amd64, arm64, armhf (树莓派) 无缝兼容。
*   **存储保护**：针对 SD 卡/eMMC 优化 I/O 调度，延长寿命并减少卡顿。
*   **内存增强**：智能配置 ZRAM 内存压缩和动态 Swap 文件。
*   **连接稳定**：SSH 防断连优化与 DoH (DNS over HTTPS) 加密解析。
*   **安全加固**：内核级隐私保护与危险操作拦截。

---

## 2. 适用系统

脚本支持以下 Linux 发行版（需 Root 权限）：
*   **Debian**: 10, 11, 12
*   **Ubuntu**: 20.04, 22.04, 24.04
*   **CentOS/Alma/Rocky**: 7, 8, 9

---

## 3. 快速开始

### 3.1 下载与运行
您可以使用以下命令直接下载并运行脚本（推荐）：

```bash
curl -fsSL https://raw.githubusercontent.com/baichal/syspro/main/syspro.sh -o syspro.sh && chmod +x syspro.sh && sudo ./syspro.sh
```

### 3.2 界面交互
运行脚本后，您将看到交互式主菜单：

*   输入数字 **`0`**：推荐选项。自动执行所有基础优化模块（1-6）。
*   输入数字 **`1-7`**：单独执行特定模块。
*   输入 **`8`**：卸载优化并还原系统。
*   输入 **`q`**：退出脚本。

---

## 4. 功能模块详解

### [1] 深度 I/O 优化 (Disk I/O)
*   **Noatime**: 修改 `/etc/fstab`，禁止文件访问时间写入，大幅减少磁盘 I/O。
*   **智能调度器**:
    *   **NVMe**: 使用 `none` (由硬件处理)。
    *   **SSD/MMC (SD卡)**: 使用 `mq-deadline`，优化闪存读写。
    *   **HDD**: 使用 `bfq`，优化机械硬盘吞吐。
*   **Fstrim**: 自动配置 Flash 存储的 TRIM 操作，保持磁盘性能。

### [2] 算力与熵池 (Compute & Entropy)
*   **Haveged**: 智能检测内核版本。如果是旧内核（<5.6），安装 Haveged 补充随机数熵池，解决服务启动阻塞问题。
*   **CPU 模式**: 在物理机环境下，强制锁定 CPU 频率为 `performance` 模式，拒绝降频，减少延迟（跳过虚拟机）。

### [3] 进程与内存 (Systemd & Swap)
*   **Systemd 优化**: 缩短服务停止超时时间，禁用 Core Dump 节省空间。
*   **OOM 保护**: 自动为 SSH 和 Systemd 进程设置 `oom_score_adj = -1000`，防止在内存耗尽时服务器失联。
*   **ZRAM**: 启用内存压缩技术。将部分内存划分为压缩交换区，在小内存机器（如 1GB/2GB VPS）上效果显著。
*   **智能 Swap**: 自动检测是否需要创建 Swap 文件。支持 Btrfs (自动关闭 CoW) 和 Ext4 文件系统。

### [4] 安全加固 (Security)
*   **内核参数**: 隐藏内核指针地址，限制非特权用户读取 dmesg 日志，禁用危险的 SysRq 键。

### [5] 接入与 DNS (Access & DNS)
*   **SSH 优化**: 关闭 SSH 的 DNS 反查和 GSSAPI 认证，显著加快 SSH 登录速度。
*   **Shell 体验**: 优化命令历史记录（增加时间戳、容量），Root 用户提示符标红。
*   **DNS 模式选择**:
    1.  **标准 UDP**: 使用 Cloudflare/Google DNS，速度快。
    2.  **DoH (加密 DNS)**: 自动部署 Cloudflared 客户端（自动适配 ARM），防止 DNS 劫持和污染。脚本会自动处理 systemd-resolved 冲突。

### [6] 维护与清理 (Maintenance)
*   **常用工具**: 安装 curl, wget, htop, nano, vim, unzip 等。
*   **时间同步**: 安装 Chrony 并配置激进同步策略。
*   **时区设置**: 交互式菜单选择常用时区（北京、香港、东京、美西、美东等）。
*   **日志清理**: 限制 Systemd 日志体积为 100M。

### [7] 手动管理工具 (Manual Tools)
*   **卸载旧内核**: 可视化列表，选择并卸载不再使用的旧内核，释放 `/boot` 空间。
*   **安装第三方 BBR**: 集成外部 BBR 脚本。
    *   **警告**: 脚本内含 ARM 架构检测。在 ARM 机器上随意安装第三方 BBR 内核极大概率导致**无法开机**，请务必留意脚本内的红色警告。

---

## 5. 高级配置 (自定义 DNS)

如果您希望使用自定义的 DNS 上游地址，可以在运行脚本前，使用文本编辑器打开脚本文件，修改顶部的 **用户配置区**：

```bash
# 修改这些变量即可
DNS_IPV4_LIST="..."
DNS_IPV6_LIST="..."
DOH_URL_LIST="..."
```

---

## 6. 卸载与还原

如果您想撤销所有更改，只需在主菜单选择 **`8. 卸载/还原`**。
脚本会执行以下操作：
1.  移除 DoH 客户端和 ZRAM 配置。
2.  删除创建的 Swap 文件（保留系统原有分区）。
3.  还原 `/etc/resolv.conf` 为默认 DNS (1.1.1.1)。
4.  还原 `/etc/fstab` 和 `/etc/ssh/sshd_config` 的备份文件。
5.  清理所有添加的定时任务和脚本。

---

## 7. 常见问题 (FAQ)

**Q1: 为什么在树莓派上无法锁定 CPU 频率？**
A: 树莓派的 CPU 频率调节通常由固件控制，或者缺少特定的内核模块。脚本会自动检测，如果不可写则跳过，不会报错。

**Q2: 开启 DoH 后，使用 `cat /etc/resolv.conf` 看到的不是 IP？**
A: 是的。DoH 模式下，本地会运行一个 DNS 代理（Cloudflared），`resolv.conf` 会指向 `127.0.0.1`。这是正常现象。

**Q3: 脚本卡在 "安装 Cloudflared"？**
A: 这通常是由于国内服务器连接 GitHub Release 下载速度慢导致的。请检查网络连接，或手动配置代理。

**Q4: 我可以在 Oracle ARM 机器上安装 BBR 吗？**
A: **强烈不建议**使用选项 7 中的第三方 BBR 脚本，除非您非常确定该内核支持 ARM64。Oracle ARM 默认内核已足够优秀且稳定，随意换内核会导致引导失败。

---

**版权说明**: 本脚本为开源工具，请在理解代码的基础上使用。作者不对因使用本脚本造成的系统损坏或数据丢失承担责任。
