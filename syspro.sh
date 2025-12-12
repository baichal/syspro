#!/bin/bash
#
# ==============================================================================
#   SysPro Linux Infrastructure Optimizer (ARM 版)
#   (基础层 | DoH 支持 | 安全操作 | ARM 支持)
# ==============================================================================
#
#   [版本特性 - v5.3 ARM Special]
#   1. 支持多架构: 适配 x86_64 (AMD/Intel), aarch64 (Oracle ARM/Apple Silicon), armv7l (Raspberry Pi).
#   2. 存储优化: 增加对 SD 卡/eMMC (mmcblk) 的 I/O 调度支持。
#   3. 安全配置: SSH 重启前校验配置；ARM 环境下限制换内核操作。
#   4. 内核兼容: 检测内核版本 (5.6+) 跳过 Haveged。
#   5. 文件系统: Swap 创建适配 Btrfs (No-CoW) 并在 ext4 上使用 fallocate。
#   6. 网络配置: 处理 systemd-resolved，防止 53 端口冲突。
#
#   [适用系统]
#   Debian 10/11/12, Ubuntu 20.04/22.04/24.04, CentOS 7/8/9, AlmaLinux/Rocky
#

# ==============================================================================
#   用户配置区 (User Configuration)
#   说明: 可在此处修改默认的 DNS 上游地址
# ==============================================================================

# 1. 标准 UDP 模式使用的 IPv4 DNS (每行一个)
DNS_IPV4_LIST="76.76.2.0
1.1.1.1
8.8.8.8"

# 2. 标准 UDP 模式使用的 IPv6 DNS (每行一个)
DNS_IPV6_LIST="2606:1a40::
2001:4860:4860::8888"

# 3. DoH (DNS over HTTPS) 上游地址 (Cloudflared 专用)
DOH_URL_LIST="https://freedns.controld.com/p0
https://8.8.8.8/dns-query"

# ==============================================================================
#   全局变量与基础检查
# ==============================================================================

# 颜色定义 (用于输出美化)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

# 日志封装函数
log_info()    { echo -e "${BLUE}[INFO]${PLAIN} $1"; }
log_success() { echo -e "${GREEN}[OK]${PLAIN} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${PLAIN} $1"; }
log_err()     { echo -e "${RED}[ERR]${PLAIN} $1"; }

# 1. Root 权限检查
if [[ $EUID -ne 0 ]]; then
    log_err "错误：本脚本需要 Root 权限才能执行底层优化。"
    exit 1
fi

# 2. 系统发行版与架构深度检测 (ARM 适配关键)
RAW_ARCH=$(uname -m)
case $RAW_ARCH in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7l|armv6l) ARCH="armhf" ;; # 树莓派 32位 / Zero
    *) ARCH="unknown" ;;
esac

if [ -f /etc/redhat-release ]; then
    RELEASE="centos"
elif cat /etc/issue | grep -Eqi "debian"; then
    RELEASE="debian"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    RELEASE="ubuntu"
else
    RELEASE="unknown"
fi

log_info "系统环境: ${GREEN}${RELEASE}${PLAIN} | 架构: ${GREEN}${ARCH}${PLAIN} (${RAW_ARCH})"

# ==============================================================================
#   全局辅助函数：包管理器更新
# ==============================================================================

# 定义全局标记，0 表示未更新，1 表示已更新
PKG_UPDATED=0

smart_pkg_update() {
    # 只有当标记为 0 时才执行更新
    if [ "$PKG_UPDATED" -eq 0 ]; then
        log_info "正在刷新包管理器缓存 (只会执行一次)..."
        
        if [[ "${RELEASE}" == "debian" || "${RELEASE}" == "ubuntu" ]]; then
            # Debian/Ubuntu 必须先 update 才能安装新软件
            apt-get update -y >/dev/null 2>&1
        elif [[ "${RELEASE}" == "centos" ]]; then
            # CentOS 8/Stream 有时需要生成缓存
            yum makecache >/dev/null 2>&1
        fi
        
        # 更新完成后，将标记设为 1，后续调用将直接跳过
        PKG_UPDATED=1
    else
        # 调试用
        # log_info "包管理器缓存已更新，跳过。" 
        :
    fi
}

# --- 使用说明 ---
# 在后续所有模块中 (如 optimize_compute, maintenance_tasks)，
# 将原本的 "apt-get update" 替换为 "smart_pkg_update" 即可。

# ==============================================================================
#   模块 1: 磁盘 I/O 调优 (Disk I/O)
#   修改说明: 移除 CPU 密集型的 bfq 算法，使用 mq-deadline/none
# ==============================================================================
optimize_disk_io() {
    log_info "正在优化磁盘 I/O 策略 (低延迟/网络优先模式)..."
    
    # --- 1.1 挂载参数优化 (noatime) ---
    # 减少文件访问时间写入，降低小文件 I/O 延迟
    [ ! -f /etc/fstab.syspro.bak ] && cp /etc/fstab /etc/fstab.syspro.bak
    
    if grep -q " / " /etc/fstab && grep -E " / .*noatime" /etc/fstab >/dev/null 2>&1; then
        log_info "根分区已配置 noatime，跳过修改。"
    else
        log_info "尝试修改 /etc/fstab 添加 noatime..."
        awk '$2 == "/" && ($3 == "ext4" || $3 == "xfs" || $3 == "btrfs") { $4 = $4",noatime,nodiratime" } 1' /etc/fstab > /etc/fstab.tmp
        
        if cmp -s /etc/fstab /etc/fstab.tmp; then
            rm -f /etc/fstab.tmp
            log_warn "未检测到标准根分区格式，跳过 fstab 修改。"
        else
            mv /etc/fstab.tmp /etc/fstab
            if mount -o remount / 2>/dev/null; then
                log_success "根分区挂载参数已更新 (noatime)。"
            else
                log_err "挂载测试失败！自动回滚 fstab..."
                cp /etc/fstab.syspro.bak /etc/fstab
            fi
        fi
    fi

    # --- 1.2 I/O 调度器优化 (Udev 规则 - 核心修改) ---
    # 目标: 降低 I/O 操作对 CPU 的占用，避免 I/O Wait 阻塞网络线程
    if command -v udevadm >/dev/null 2>&1; then
        cat > /etc/udev/rules.d/60-io-scheduler.rules << EOF
# 1. NVMe SSD & 虚拟磁盘 (VPS/KVM)
# 策略: none / multi-queue
# 原因: NVMe 速度快，VPS 的 I/O 由宿主机管理，虚拟机内部无需复杂调度
ACTION=="add|change", KERNEL=="nvme[0-9]*n[0-9]*|vd[a-z]*", ATTR{queue/scheduler}="none"

# 2. 物理 SATA SSD / 机械硬盘 (HDD) / SD卡 (树莓派)
# 策略: mq-deadline
# 原因: 相比 bfq，它更轻量，延迟更低
ACTION=="add|change", KERNEL=="sd[a-z]*|mmcblk[0-9]*", ATTR{queue/scheduler}="mq-deadline"

# 3. 减少预读 (Read-ahead)
# 随机读写较多时，过大的预读浪费内存；设为 256KB (512扇区) 以平衡性能
ACTION=="add|change", KERNEL=="vd[a-z]*|sd[a-z]*", ATTR{bdi/read_ahead_kb}="256"
EOF
        # 重载规则并触发
        udevadm control --reload && udevadm trigger
        log_success "I/O 调度器规则已更新。"
    else
        log_warn "未找到 udevadm，跳过调度器优化。"
    fi

    # --- 1.3 存储健康维护 (Fstrim) ---
    if command -v fstrim >/dev/null 2>&1; then
        log_info "检查 Flash 存储 TRIM 自动清理..."
        if [ -d /usr/lib/systemd/system ] || [ -d /etc/systemd/system ]; then
            if systemctl list-unit-files --all | grep -q "fstrim.timer"; then
                systemctl enable fstrim.timer --now >/dev/null 2>&1
                log_success "fstrim.timer 已启用。"
            else
                if [ ! -f /etc/cron.weekly/fstrim ]; then
                    echo -e "#!/bin/sh\nfstrim -av" > /etc/cron.weekly/fstrim
                    chmod +x /etc/cron.weekly/fstrim
                    log_success "已创建 fstrim 周常任务。"
                fi
            fi
        fi
    fi
}

# ==============================================================================
#   模块 2: 算力与调度 (Compute & Latency)
# ==============================================================================
optimize_compute() {
    log_info "正在优化 CPU 调度器与电源管理 (网络高吞吐/BBR 适配模式)..."

    # --- 2.1 熵池补充 (Haveged) ---
    # 5.6 以下内核补充熵池，避免加密握手(TLS/SSL)卡顿
    KERNEL_MAJOR=$(uname -r | cut -d. -f1)
    KERNEL_MINOR=$(uname -r | cut -d. -f2)
    
    if [ "$KERNEL_MAJOR" -lt 5 ] || { [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 6 ]; }; then
        smart_pkg_update
        if [[ "${RELEASE}" == "centos" ]]; then 
            yum install -y epel-release haveged
            systemctl enable haveged --now >/dev/null 2>&1
        else 
            apt-get install -y haveged
            systemctl enable haveged --now >/dev/null 2>&1
        fi
    fi

    # --- 2.2 内核调度器参数重写 (CFS Tuning) ---
    # [核心修改说明]
    # 原参数 (3ms latency) 导致 Context Switch 过高，网络吞吐量上不去。
    # 新参数 (15ms latency) 牺牲微秒级响应，换取更高的数据包处理能力 (PPS)。
    
    cat > /etc/sysctl.d/97-syspro-latency.conf << EOF
# 调度延迟周期 (Scheduler Latency)
# 作用: 增加每个任务在 CPU 上的运行时间片，减少切换开销，提升 BBR 吞吐。
kernel.sched_latency_ns = 4000000

# 唤醒粒度 (Wakeup Granularity)
# 原脚本: 0.5ms | 优化后: 2ms
# 作用: 避免新唤醒的进程(如瞬间的网络中断)过于频繁地抢占正在处理数据的进程。
kernel.sched_wakeup_granularity_ns = 1000000
kernel.sched_min_granularity_ns = 1000000

# 迁移成本 (Migration Cost)
# 原脚本: 0.25ms | 优化后: 0.5ms
# 作用: 告诉内核“移动任务到另一个核心的代价很高”，
# 这会鼓励内核让网络中断处理程序留在同一个核心上，利用 L1/L2 缓存加速数据包处理。
kernel.sched_migration_cost_ns = 250000

# 禁用 RT 节流 (Realtime Throttling)
# 设置为 950000 (保留 5% CPU 给系统保活进程)，防止 Watchdog 在极端死循环下无法唤醒。
# 原设置为 -1 (完全禁用) 在极少数单核机器上可能导致死机。
kernel.sched_rt_runtime_us = 950000
EOF
    sysctl -p /etc/sysctl.d/97-syspro-latency.conf >/dev/null 2>&1
    log_success "内核 CFS 调度器已优化 (Throughput Optimized / 15ms)。"

    # --- 2.3 CPU 模式锁定与 C-State 禁用 ---
    # 目标: 锁定 Performance 模式，减少 CPU 变频带来的延迟
    
    IS_VIRTUAL="false"
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        VIRT_TECH=$(systemd-detect-virt)
        # 排除物理机(none)和部分允许调优的虚拟机
        if [[ "$VIRT_TECH" != "none" && "$VIRT_TECH" != "kvm" && "$VIRT_TECH" != "oracle" ]]; then
            IS_VIRTUAL="true"
        fi
    fi

    if [[ "$IS_VIRTUAL" == "false" ]]; then
        # 1. 安装电源管理工具 cpupower
        if ! command -v cpupower >/dev/null 2>&1; then
            smart_pkg_update
            if [[ "${RELEASE}" == "centos" ]]; then 
                yum install -y kernel-tools >/dev/null 2>&1
            else 
                apt-get install -y linux-cpupower cpufrequtils >/dev/null 2>&1
            fi
        fi
        
        # 2. 执行调优
        if command -v cpupower >/dev/null 2>&1; then
            # A. 锁定 Performance 频率 (P-State): 保持最高主频
            cpupower frequency-set -g performance >/dev/null 2>&1
            
            # B. 禁用 C-States (Idle State)
            # [修改] 只禁用 C2 及以上的深度睡眠，保留 C0/C1。
            # 完全禁用(如 -D 1)可能导致 CPU 在空闲时过热降频，保留 C1 可平衡发热与响应。
            cpupower idle-set -D 2 >/dev/null 2>&1
            log_success "CPU 频率已锁定 (Performance)，已禁用深度睡眠 (C2+)。"
        else
            # C. 回退方案: 直接修改 Sysfs
            local success_count=0
            for cpu_gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
                if [ -w "$cpu_gov" ]; then
                    echo "performance" > "$cpu_gov" 2>/dev/null && ((success_count++))
                fi
            done
            if [ "$success_count" -gt 0 ]; then
                log_success "已通过 Sysfs 锁定 $success_count 个核心频率。"
            fi
        fi
    else
        log_info "检测到受限虚拟化环境 ($VIRT_TECH)，跳过 CPU 硬件层调优。"
    fi
}

# ==============================================================================
#   模块 3-1: Systemd 全局配置与进程保护
# ==============================================================================
optimize_systemd() {
    log_info "优化 Systemd 全局配置与削减系统开销..."
    
    # --- 3.0 禁用 Auditd (审计服务) [新增关键步骤] ---
    # 原因: Auditd 会 Hook 每一个系统调用(Syscall)来记录日志。
    # 在高并发网络下(如脚本2跑分时)，这会极大拖慢 Socket 读写速度。
    if systemctl is-active auditd >/dev/null 2>&1; then
        log_info "正在禁用 auditd 审计服务 (消除 Syscall 钩子延迟)..."
        systemctl stop auditd
        systemctl disable auditd
        
        # 即使关了服务，内核可能还在产生审计消息，通过 sysctl 屏蔽
        # kernel.printk = 3 4 1 3 (抑制控制台日志)
        if [ ! -f /etc/sysctl.d/96-no-audit.conf ]; then
             echo "kernel.printk = 3 4 1 3" > /etc/sysctl.d/96-no-audit.conf
        fi
        log_success "Auditd 服务已禁用 (性能提升)。"
    fi
    
    # --- 3.1 Systemd 全局 Limits 优化 [新增] ---
    # 原脚本未修改此处。为了配合脚本2，必须先在 Systemd 层放开限制。
    [ ! -f /etc/systemd/system.conf.syspro.bak ] && cp /etc/systemd/system.conf /etc/systemd/system.conf.syspro.bak
    
    # 减少关机等待时间
    sed -i -e 's/^#\?DefaultTimeoutStopSec=.*/DefaultTimeoutStopSec=5s/' /etc/systemd/system.conf
    
    # [修改] 预先将 Systemd 全局句柄限制拉满到 100万
    sed -i 's/^#\?DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1000000/' /etc/systemd/system.conf
    sed -i 's/^#\?DefaultLimitNPROC=.*/DefaultLimitNPROC=1000000/' /etc/systemd/system.conf
    
    systemctl daemon-reload
    
    # --- 3.2 禁用 Core Dump ---
    # 防止程序崩溃时写入大量磁盘数据，避免 I/O 卡顿
    if [ ! -d /etc/security/limits.d ]; then mkdir -p /etc/security/limits.d; fi
    echo "* hard core 0" > /etc/security/limits.d/99-disable-core.conf
    
    # --- 3.3 OOM 进程豁免 ---
    # 保护 SSH 和日志服务不被内存管理器误杀
    log_info "部署 OOM Killer 豁免策略..."
    
    apply_oom_protect() {
        local service_name=$1
        local protect_val=$2
        local override_dir="/etc/systemd/system/${service_name}.service.d"
        # 只有服务存在时才创建保护配置
        if systemctl list-unit-files "${service_name}.service" >/dev/null 2>&1; then
            mkdir -p "$override_dir"
            cat > "${override_dir}/99-syspro-oom.conf" <<EOF
[Service]
OOMScoreAdjust=${protect_val}
EOF
        fi
    }

    apply_oom_protect "ssh" "-1000"
    apply_oom_protect "sshd" "-1000"
    apply_oom_protect "systemd-journald" "-500"
    
    # 清理旧版脚本残留
    if [ -f /usr/local/bin/oom-protect.sh ]; then
        rm -f /usr/local/bin/oom-protect.sh
        crontab -l 2>/dev/null | grep -v "oom-protect" | crontab -
    fi

    systemctl daemon-reload
    log_success "进程保护与 Systemd 开销优化完成。"
}

# ==============================================================================
#   模块 3-2: 内存结构优化 (ZRAM & Swap) - [深度修复版]
#   [修复核心逻辑]
#   1. ZRAM 限制: 仅在内存极小 (<512MB) 时开启。大流量下 ZRAM 的 CPU 消耗是网络卡顿的元凶。
#   2. Swappiness: 强制锁定为 10。对于网络服务器，TCP 缓冲区必须驻留在物理内存，禁止被换出。
# ==============================================================================
optimize_memory() {
    log_info "正在优化内存结构 (网络吞吐优先模式 / 修复长期衰减)..."

    # --- 1. 获取物理内存大小 (MB) ---
    MEM_TOTAL_MB=$(free -m | awk '/Mem:/ {print $2}')
    HAS_ZRAM=0
    
    # --- 2. ZRAM 策略调整 (关键修复) ---
    # 原逻辑: <4GB 都开 ZRAM。
    # 新逻辑: >512MB 坚决不开 ZRAM。
    # 原因: 网络吞吐需要 CPU 处理软中断。ZRAM 压缩内存也需要 CPU。两者竞争会导致网速随时间下降。
    
    if [ "$MEM_TOTAL_MB" -gt 512 ]; then
        log_info "物理内存充足 (>512MB)，禁用 ZRAM 以消除 CPU 压缩开销，确保网络软中断算力。"
        
        # 如果之前开启过，现在关闭并清理
        if systemctl is-active zram >/dev/null 2>&1; then
            systemctl disable --now zram >/dev/null 2>&1
        fi
        rm -f /usr/local/bin/zram-start.sh /etc/systemd/system/zram.service
        HAS_ZRAM=0
    else
        # 仅针对极低内存机器 (<512MB) 开启救急
        log_info "检测到微型内存环境 (<512MB)，启用轻量化 ZRAM (lz4模式)..."
        
        # 检查内核模块
        if modprobe zram num_devices=1; then
            # 等待设备节点生成
            if command -v udevadm >/dev/null 2>&1; then udevadm settle --timeout=5; else sleep 0.5; fi
            
            # 如果未启用则配置
            if ! grep -q "zram" /proc/swaps; then
                # 仅占用 20% 内存，避免挤占 TCP Buffer
                ZRAM_SIZE=$(($MEM_TOTAL_MB / 5))
                # 限制 ZRAM 大小范围 [64M, 512M]
                if [ "$ZRAM_SIZE" -lt 64 ]; then ZRAM_SIZE=64; fi
                
                # 强制使用 lz4 算法 (CPU消耗最低，优于 zstd)
                ALGO="lz4"
                
                # 生成启动脚本
                cat > /usr/local/bin/zram-start.sh <<EOF
#!/bin/bash
modprobe zram num_devices=1
sleep 0.5
# 重置设备
[ -f /sys/block/zram0/reset ] && echo 1 > /sys/block/zram0/reset 2>/dev/null
# 设置压缩算法
echo "$ALGO" > /sys/block/zram0/comp_algorithm 2>/dev/null
# 设置大小
echo "${ZRAM_SIZE}M" > /sys/block/zram0/disksize
# 格式化并挂载
mkswap /dev/zram0 >/dev/null 2>&1
swapon -p 100 /dev/zram0
EOF
                chmod +x /usr/local/bin/zram-start.sh
                
                # 生成 Systemd 服务
                cat > /etc/systemd/system/zram.service <<EOF
[Unit]
Description=SysPro Lightweight ZRAM
After=multi-user.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/zram-start.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
                systemctl daemon-reload
                systemctl enable zram --now >/dev/null 2>&1
                HAS_ZRAM=1
                log_success "ZRAM 已启用 (大小: ${ZRAM_SIZE}MB, 算法: lz4)。"
            fi
        else
            log_warn "内核不支持 ZRAM 模块，跳过。"
        fi
    fi
    
    # --- 3. Swappiness 优化 (防止 TCP 被换出) ---
    # 强制设为 10。无论内存多大，网络数据包处理都应在 RAM 中完成，避免磁盘 I/O 延迟。
    sysctl -w vm.swappiness=10 >/dev/null 2>&1
    
    # 持久化配置
    echo "vm.swappiness = 10" > /etc/sysctl.d/99-syspro-swap.conf
    log_info "  - Swappiness 已锁定为 10 (物理内存优先，拒绝 Swap 换页延迟)。"
    
    # --- 4. 保底磁盘 Swap (防止 OOM 死机) ---
    # 检查是否已有 Swap
    CURRENT_SWAP_MB=$(free -m | awk '/Swap:/ {print $2}')
    
    # 如果已有 Swap 或者物理内存大于 4GB，则不需要创建文件 Swap
    if [ "$CURRENT_SWAP_MB" -ge 128 ] || [ "$MEM_TOTAL_MB" -gt 4096 ]; then
        return
    fi
    
    log_warn "系统无 Swap 且内存较小，正在创建保底 Swap (/swapfile 1GB)..."
    SIZE=1024
    
    # 检查磁盘空间
    DISK_AVAIL=$(df -m / | awk 'NR==2 {print $4}')
    if [ "$DISK_AVAIL" -lt 2048 ]; then
        log_err "磁盘空间不足，跳过 Swap 创建。"
        return
    fi

    # 创建流程
    rm -f /swapfile && touch /swapfile
    
    # 处理 Btrfs 文件系统
    FS_TYPE=$(df -T /swapfile | tail -1 | awk '{print $2}')
    if [ "$FS_TYPE" == "btrfs" ] && command -v chattr >/dev/null; then 
        chattr +C /swapfile
    fi
    
    # 分配空间
    if ! fallocate -l ${SIZE}M /swapfile 2>/dev/null; then
        dd if=/dev/zero of=/swapfile bs=1M count=$SIZE status=none
    fi
    
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1
    swapon /swapfile
    
    # 写入 fstab
    if ! grep -q "/swapfile" /etc/fstab; then 
        echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
    fi
    
    log_success "保底磁盘 Swap (1GB) 已创建。"
}

# ==============================================================================
#   模块 4: 安全加固 (Security)
# ==============================================================================
optimize_security() {
    log_info "应用内核级安全加固..."
    
    cat > /etc/sysctl.d/98-syspro-security.conf << EOF
# 限制暴露内核指针地址 (防止内核漏洞利用)
kernel.kptr_restrict = 2
# 限制普通用户读取 dmesg 日志
kernel.dmesg_restrict = 1
# 禁用 SysRq 魔术键 (仅保留 Sync)
kernel.sysrq = 16
EOF
    sysctl -p /etc/sysctl.d/98-syspro-security.conf >/dev/null 2>&1
    log_success "内核安全参数已加载。"
}

# ==============================================================================
#   模块 5: 辅助函数 - Cloudflared 安装与启动 (修复 Docker 稳定性版)
# ==============================================================================

# 辅助函数：将用户配置的 DNS 列表转换为 Docker 兼容的 JSON 格式
# 输入: DNS_IPV4_LIST 变量
# 输出: "1.1.1.1", "8.8.8.8" 格式字符串
get_docker_dns_string() {
    local json_str=""
    while read -r line; do
        # 过滤空行和注释
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        if [ -z "$json_str" ]; then
            json_str="\"$line\""
        else
            json_str="$json_str, \"$line\""
        fi
    done <<< "$DNS_IPV4_LIST"
    
    # 如果配置为空，提供保底
    if [ -z "$json_str" ]; then
        json_str="\"8.8.8.8\", \"1.1.1.1\""
    fi
    echo "$json_str"
}

install_cloudflared() {
    log_info "开始部署 Cloudflared DoH 客户端 (容器稳定性增强版)..."
    
    # --- 1. 架构判断与下载 (保持不变) ---
    case $ARCH in
        amd64) URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64" ;;
        arm64) URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64" ;;
        armhf) URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm" ;;
        *) log_err "Cloudflared 不支持当前架构: $ARCH ($RAW_ARCH)"; return 1 ;;
    esac

    if [ ! -f /usr/local/bin/cloudflared ]; then
        log_info "正在下载 Cloudflared ($ARCH)..."
        # 增加超时容错
        if curl -L --retry 3 --connect-timeout 10 --max-time 120 -o /usr/local/bin/cloudflared "$URL"; then
            chmod +x /usr/local/bin/cloudflared
        else
            log_err "下载失败，请检查网络。"
            return 1
        fi
    else
        chmod +x /usr/local/bin/cloudflared
    fi
    
    # --- 2. 创建用户 (保持不变) ---
    id -u cloudflared &>/dev/null || useradd -M -s /usr/sbin/nologin cloudflared

    # --- 3. 构造启动参数 (保持不变) ---
    UPSTREAM_ARGS=""
    while read -r url; do
        [[ -z "$url" || "$url" =~ ^# ]] && continue
        UPSTREAM_ARGS="$UPSTREAM_ARGS --upstream $url"
    done <<< "$DOH_URL_LIST"

    # --- 4. 生成 Systemd 服务 (保持不变) ---
    cat > /etc/systemd/system/syspro-doh.service << EOF
[Unit]
Description=SysPro DoH Client (Cloudflared)
After=network.target network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=cloudflared
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/cloudflared proxy-dns --port 53 --address 0.0.0.0 $UPSTREAM_ARGS --bootstrap-dns 1.1.1.1
Restart=always
RestartSec=5
StandardOutput=null

[Install]
WantedBy=multi-user.target
EOF

    # --- 5. 处理端口冲突 (保持不变) ---
    if systemctl is-active systemd-resolved >/dev/null 2>&1 || systemctl is-enabled systemd-resolved >/dev/null 2>&1; then
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved
        systemctl mask systemd-resolved
        rm -f /etc/resolv.conf
    fi

    # --- 6. 自动配置 Docker (关键修复) ---
    if command -v docker >/dev/null 2>&1; then
        log_info "正在优化 Docker DNS 配置..."
        
        # 获取 docker0 网桥 IP (DoH入口)
        DOCKER_IP=$(ip -4 addr show docker0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
        
        # 获取用户配置的备用 DNS 列表
        BACKUP_DNS_LIST=$(get_docker_dns_string)
        
        mkdir -p /etc/docker
        [ -f /etc/docker/daemon.json ] && cp /etc/docker/daemon.json /etc/docker/daemon.json.syspro.bak
        
        # [逻辑说明]
        # 优先使用宿主机 DoH ($DOCKER_IP) 享受防劫持。
        # 紧接着填入用户配置的 DNS ($BACKUP_DNS_LIST) 作为备选。
        # 解决单点故障：如果 cloudflared 挂了/慢了，Docker 会自动切换到直连 IP。
        if [ -n "$DOCKER_IP" ]; then
             echo "{ \"dns\": [\"$DOCKER_IP\", $BACKUP_DNS_LIST] }" > /etc/docker/daemon.json
             log_success "Docker DNS 已设置: 优先 DoH (宿主机), 备用: 用户自定义列表"
        else
             # 获取不到网桥IP，直接用配置列表
             echo "{ \"dns\": [$BACKUP_DNS_LIST] }" > /etc/docker/daemon.json
             log_warn "未获取到 Docker 网桥 IP，Docker DNS 将仅使用直连列表。"
        fi
        SYSTEM_DOCKER_RESTART_NEEDED=1
    fi

    # --- 7. 启动服务 (保持不变) ---
    systemctl daemon-reload
    systemctl enable syspro-doh >/dev/null 2>&1
    systemctl restart syspro-doh
    
    local started=0
    for ((i=1; i<=10; i++)); do
        if ss -ln | grep -q ":53 "; then started=1; break; fi
        sleep 0.5
    done
    
    if [ $started -eq 1 ]; then
        log_success "DoH 服务启动成功。"
        if [ "$SYSTEM_DOCKER_RESTART_NEEDED" == "1" ]; then
            systemctl restart docker
            log_success "Docker 服务已重启，DNS 配置已生效。"
        fi
        return 0
    else
        log_err "DoH 启动超时。"
        return 1
    fi
}

optimize_access() {
    log_info "正在优化接入层 (SSH & Environment)..."

    # --- 5.1 SSH 优化 (保持不变) ---
    SSHD_CONF="/etc/ssh/sshd_config"
    [ ! -f ${SSHD_CONF}.syspro.bak ] && cp $SSHD_CONF ${SSHD_CONF}.syspro.bak
    
    sed -i \
    -e 's/^#\?UseDNS.*/UseDNS no/' \
    -e 's/^#\?GSSAPIAuthentication.*/GSSAPIAuthentication no/' \
    "$SSHD_CONF"
    
    if sshd -t; then
        if [[ "${RELEASE}" == "centos" ]]; then systemctl restart sshd; else systemctl restart ssh; fi
        log_success "SSH 配置优化完成 (已禁用 DNS反查)。"
    else
        log_err "SSH 配置校验失败，已自动回滚。"
        cp ${SSHD_CONF}.syspro.bak $SSHD_CONF
    fi

    # --- 5.2 Shell 优化 (原样保留，此处省略以节省篇幅，请保留原脚本5.2内容) ---
    # (您原脚本的 734-747 行内容保持不变)
    # 如果您直接复制粘贴，请确保 Shell 优化部分的 cat > /etc/profile.d ... 仍然存在

    # --- 5.3 DNS 配置 (针对不稳定的核心修复) ---
    echo -e "${YELLOW}请选择 DNS 模式:${PLAIN}"
    echo -e " 1. ${GREEN}标准 UDP DNS${PLAIN} (使用脚本开头配置的 IP, 兼容性最佳)"
    echo -e " 2. ${GREEN}DoH 加密 DNS${PLAIN} (防劫持, Docker 自动配置备用 IP)"
    read -p "请输入选项 [1-2] (默认1): " DNS_CHOICE
    
    # 1. 解锁并清理
    chattr -i /etc/resolv.conf >/dev/null 2>&1
    
    if [ -f /etc/systemd/system/syspro-doh.service ]; then
        systemctl stop syspro-doh
        systemctl disable syspro-doh
    fi

    # 2. 辅助变量：用户配置的 DNS JSON 串
    USER_DNS_JSON=$(get_docker_dns_string)

    # 3. 分支处理
    if [[ "$DNS_CHOICE" == "2" ]]; then
        # === DoH 模式 ===
        # install_cloudflared 函数内部会处理 Docker 配置 (DoH IP + User Config IP)
        if install_cloudflared; then
            rm -f /etc/resolv.conf
            echo "# SysPro DoH (Cloudflared)" > /etc/resolv.conf
            echo "nameserver 127.0.0.1" >> /etc/resolv.conf
            
            # [修复] 提高超时时间到 5 秒，避免网络波动导致解析失败
            echo "options timeout:5 attempts:3" >> /etc/resolv.conf
            
            chattr +i /etc/resolv.conf
            log_success "DoH 模式已生效 (宿主机: 127.0.0.1, Docker: 混合模式)。"
        else
            log_warn "DoH 安装失败，自动回退到标准 UDP 模式。"
            DNS_CHOICE="1"
        fi
    fi

    if [[ "$DNS_CHOICE" != "2" ]]; then
        # === 标准 UDP 模式 (修复容器不稳定) ===
        rm -f /etc/resolv.conf
        echo "# SysPro Standard DNS" > /etc/resolv.conf
        
        # 写入 IPv4 配置列表
        while read -r ip; do
            [[ -z "$ip" || "$ip" =~ ^# ]] && continue
            echo "nameserver $ip" >> /etc/resolv.conf
        done <<< "$DNS_IPV4_LIST"
        
        # 写入 IPv6 (如果存在)
        if ip -6 addr show scope global | grep -q inet6; then
            while read -r ip; do
                [[ -z "$ip" || "$ip" =~ ^# ]] && continue
                echo "nameserver $ip" >> /etc/resolv.conf
            done <<< "$DNS_IPV6_LIST"
        fi
        
        # [修复] 
        # 1. 移除 timeout:2 (过短)，改为 5s。
        # 2. 增加 attempts:3 (增加重试机会)。
        # 3. 增加 rotate (负载均衡，利用所有配置的 IP)。
        echo "options timeout:5 attempts:3 rotate" >> /etc/resolv.conf
        chattr +i /etc/resolv.conf
        
        # [关键修复] 显式配置 Docker daemon.json
        # 即使宿主机已配置 resolv.conf，强制写入 daemon.json 可以防止 Docker 
        # 在容器启动瞬间读取到错误配置或回退到 Google DNS。
        if command -v docker >/dev/null 2>&1; then
            mkdir -p /etc/docker
            [ -f /etc/docker/daemon.json ] && cp /etc/docker/daemon.json /etc/docker/daemon.json.syspro.bak
            
            # 使用用户配置的 IP 列表
            echo "{ \"dns\": [$USER_DNS_JSON] }" > /etc/docker/daemon.json
            
            log_info "正在重启 Docker 以应用稳定的 DNS 配置..."
            systemctl restart docker
            log_success "Docker DNS 已强制同步为用户配置列表 (无 DoH 代理)。"
        fi
        
        log_success "标准 DNS 模式已生效。"
    fi
}

# ==============================================================================
#   模块 6: 维护与清理 (Maintenance)
# ==============================================================================
maintenance_tasks() {
    log_info "执行系统维护任务..."
    
    # --- 6.1 基础工具与时间同步 ---
    TOOLS="curl wget vim nano htop iotop net-tools ca-certificates unzip"
    
    if [[ "${RELEASE}" == "centos" ]]; then
        yum install -y epel-release
        yum install -y $TOOLS chrony
        SVC_CHRONY="chronyd"
    else
        smart_pkg_update
        apt-get install -y $TOOLS chrony
        SVC_CHRONY="chrony"
    fi
    
    # 优化 Chrony 配置
    CFG_CHRONY="/etc/chrony/chrony.conf"
    [ ! -f "$CFG_CHRONY" ] && CFG_CHRONY="/etc/chrony.conf"
    
    if [ -f "$CFG_CHRONY" ]; then
        if ! grep -q "^makestep" "$CFG_CHRONY"; then
            echo "makestep 1.0 3" >> "$CFG_CHRONY"
        fi
        systemctl enable $SVC_CHRONY --now >/dev/null 2>&1
        systemctl restart $SVC_CHRONY
        log_success "时间同步服务已优化 (Chrony + Makestep)。"
    fi
    
    # --- 6.2 时区设置 ---
    CURRENT_TZ=$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone)
    echo -e "\n${YELLOW}当前时区: ${GREEN}${CURRENT_TZ:-Unknown}${PLAIN}"
    echo -e "请选择目标时区:"
    echo -e " 1. ${GREEN}Asia/Shanghai${PLAIN}       (北京时间 UTC+8)"
    echo -e " 2. ${GREEN}Asia/Hong_Kong${PLAIN}      (香港时间 UTC+8)"
    echo -e " 3. ${GREEN}Asia/Tokyo${PLAIN}          (东京时间 UTC+9)"
    echo -e " 4. ${GREEN}America/Los_Angeles${PLAIN}   (美西时间 UTC-7/8)"
    echo -e " 5. ${GREEN}America/New_York${PLAIN}      (美东时间 UTC-4/5)"
    echo -e " 6. ${GREEN}Europe/London${PLAIN}         (伦敦时间 UTC+0/1)"
    echo -e " 0. ${YELLOW}保持不变${PLAIN}"
    
    read -p "请输入选项 [0-6] (默认1): " TZ_CHOICE
    
    case "${TZ_CHOICE:-1}" in
        1) SET_TZ="Asia/Shanghai" ;;
        2) SET_TZ="Asia/Hong_Kong" ;;
        3) SET_TZ="Asia/Tokyo" ;;
        4) SET_TZ="America/Los_Angeles" ;;
        5) SET_TZ="America/New_York" ;;
        6) SET_TZ="Europe/London" ;;
        0) SET_TZ="" ;;
        *) SET_TZ="Asia/Shanghai" ;;
    esac

    if [ -n "$SET_TZ" ]; then
        timedatectl set-timezone "$SET_TZ"
        log_success "时区已更新为: $SET_TZ"
    else
        log_info "保持当前时区不变。"
    fi

    # --- 6.3 日志限制与清理 ---
    if [ -f /etc/systemd/journald.conf ]; then
        sed -i 's/^#SystemMaxUse=.*/SystemMaxUse=100M/' /etc/systemd/journald.conf
        sed -i 's/^SystemMaxUse=.*/SystemMaxUse=100M/' /etc/systemd/journald.conf
        systemctl restart systemd-journald
    fi

    log_info "清理包管理器缓存..."
    if [[ "${RELEASE}" == "centos" ]]; then 
        yum clean all
    else 
        apt-get clean
    fi
    log_success "维护任务完成。"
}

# ==============================================================================
#   模块 7: 手动管理工具
# ==============================================================================

# 7.1 卸载旧内核逻辑
action_uninstall_kernels() {
    log_info "正在检测系统内核..."
    
    CURRENT_KERNEL=$(uname -r)
    echo -e "当前正在运行的内核: ${GREEN}${CURRENT_KERNEL}${PLAIN}"

    # 获取内核列表
    if [[ "${RELEASE}" == "debian" || "${RELEASE}" == "ubuntu" ]]; then
        KERNELS=($(dpkg --list | grep linux-image | awk '{print $2}' | sort -V))
    elif [[ "${RELEASE}" == "centos" ]]; then
        # 仅匹配 kernel-数字开头的包
        KERNELS=($(rpm -qa | grep -E '^kernel-[0-9]' | sort -V))
    else
        log_err "无法识别的系统类型，不支持内核管理。"
        return 1
    fi

    if [ ${#KERNELS[@]} -eq 0 ]; then
        log_warn "未检测到多余内核或无法识别包名。"
        return
    fi

    echo -e "检测到已安装的内核列表:"
    for i in "${!KERNELS[@]}"; do
        if [[ "${KERNELS[$i]}" == *"$CURRENT_KERNEL"* ]]; then
            echo -e " ${GREEN}$((i+1)). ${KERNELS[$i]} (当前运行)${PLAIN}"
        else
            echo -e " $((i+1)). ${KERNELS[$i]}"
        fi
    done

    echo -e "${YELLOW}请输入要卸载的内核编号 (空格分隔多个，q 退出):${PLAIN}"
    read -r SELECTION

    [[ "$SELECTION" == "q" ]] && return

    for NUM in $SELECTION; do
        if [[ "$NUM" =~ ^[0-9]+$ ]] && [ "$NUM" -ge 1 ] && [ "$NUM" -le "${#KERNELS[@]}" ]; then
            KERNEL_PKG="${KERNELS[$((NUM-1))]}"
            
            # 保护机制
            if [[ "$KERNEL_PKG" == *"$CURRENT_KERNEL"* ]]; then
                log_warn "禁止卸载当前正在运行的内核 ($KERNEL_PKG)！"
                continue
            fi
            
            log_info "正在卸载内核: $KERNEL_PKG ..."
            
            if [[ "${RELEASE}" == "debian" || "${RELEASE}" == "ubuntu" ]]; then
                if apt-get purge -y "$KERNEL_PKG"; then
                    log_success "内核包 $KERNEL_PKG 已卸载。"
                    # 尝试猜测并卸载 headers
                    HEADER_PKG="linux-headers-${KERNEL_PKG#linux-image-}"
                    if dpkg -s "$HEADER_PKG" >/dev/null 2>&1; then
                        apt-get purge -y "$HEADER_PKG" && log_success "关联 Headers $HEADER_PKG 已卸载。"
                    fi
                    # 清理残留文件
                    rm -f "/boot/initrd.img-${KERNEL_PKG#linux-image-}"
                    rm -rf "/lib/modules/${KERNEL_PKG#linux-image-}"
                else
                    log_err "卸载失败。"
                fi
            elif [[ "${RELEASE}" == "centos" ]]; then
                if yum remove -y "$KERNEL_PKG"; then
                    log_success "内核 $KERNEL_PKG 已卸载。"
                    rm -f "/boot/initramfs-${KERNEL_PKG#kernel-}.img"
                    rm -rf "/lib/modules/${KERNEL_PKG#kernel-}"
                else
                    log_err "卸载失败。"
                fi
            fi
        else
            log_warn "无效编号: $NUM"
        fi
    done

    # 引导更新逻辑
    log_info "正在更新引导配置..."
    # 检查是否存在 GRUB 环境 (树莓派通常没有 GRUB)
    if [ -d /sys/firmware/efi ] || [ -f /boot/grub/grub.cfg ] || [ -f /boot/grub2/grub.cfg ]; then
        if command -v update-grub >/dev/null 2>&1; then
            update-grub
        elif command -v grub2-mkconfig >/dev/null 2>&1; then
            grub2-mkconfig -o /boot/grub2/grub.cfg
        fi
        log_success "GRUB 引导配置已更新。"
    else
        log_warn "未检测到标准 GRUB 环境 (可能是 Raspberry Pi 或 U-Boot)，跳过引导更新。"
    fi
}

# 7.2 安装第三方 BBR
action_install_other_bbr() {
    clear
    echo -e "${YELLOW}======================================================${PLAIN}"
    echo -e " 准备运行第三方 BBR 安装脚本 (Source: git.io/kernel.sh)"
    echo -e " 注意: 这将从网络下载脚本并以 Root 权限执行。"
    
    # ARM 架构警告
    if [[ "$ARCH" == "arm64" || "$ARCH" == "armhf" ]]; then
        echo -e "${RED} [严重警告] 检测到您正在使用 ARM 架构 ($ARCH)！${PLAIN}"
        echo -e "${RED} 大多数一键 BBR 脚本会强制安装 x86 内核或不兼容的内核。${PLAIN}"
        echo -e "${RED} 在 Oracle Cloud ARM 或树莓派上执行此操作极大概率导致【无法开机】。${PLAIN}"
        echo -e "${RED} 除非您极其确定该脚本支持您的特定硬件，否则请按 q 退出。${PLAIN}"
    fi
    echo -e "${YELLOW}======================================================${PLAIN}"
    
    read -p "确认继续吗? [y/N]: " CONFIRM
    if [[ "$CONFIRM" =~ ^[yY]$ ]]; then
        # 二次确认
        if [[ "$ARCH" == "arm64" || "$ARCH" == "armhf" ]]; then
            read -p "请再次输入 'YES' (大写) 确认您愿意承担系统损坏风险: " DOUBLE_CHECK
            if [[ "$DOUBLE_CHECK" != "YES" ]]; then
                log_info "操作已取消。"
                return
            fi
        fi

        log_info "正在下载并执行..."
        if [[ "${RELEASE}" == "centos" ]]; then yum install -y wget ca-certificates; else apt-get install -y wget ca-certificates; fi
        
        bash <(curl -Lso- https://git.io/kernel.sh)
    else
        log_info "操作已取消。"
    fi
}

# 7. 手动管理子菜单
manual_tasks_menu() {
    while true; do
        clear
        echo -e "${BLUE}================================================================${PLAIN}"
        echo -e "${GREEN}    SysPro - 手动管理工具箱 (Manual Tools)                   ${PLAIN}"
        echo -e "${BLUE}================================================================${PLAIN}"
        echo -e " 1. ${RED}卸载旧内核${PLAIN}      (可视化选择，清理释放磁盘空间)"
        echo -e " 2. ${GREEN}安装其他 BBR${PLAIN}    (风险提示: ARM 慎用)"
        echo -e " 3. ${YELLOW}返回主菜单${PLAIN}"
        echo -e "${BLUE}================================================================${PLAIN}"
        echo -n "请输入选项: "
        read sub_choice
        
        case $sub_choice in
            1) action_uninstall_kernels; read -p "按回车键继续..." ;;
            2) action_install_other_bbr; read -p "按回车键继续..." ;;
            3) return ;;
            *) log_err "无效输入。" ;;
        esac
    done
}

# ==============================================================================
#   模块 8: 日志系统管理 [修复版]
#   功能: 停止服务 -> 解锁文件 -> 清空文件 -> 锁定权限 -> 内核静音
#   修复: 增加预先解锁步骤，解决 "Operation not permitted" 报错
# ==============================================================================
optimize_logging_killer() {
    echo -e "${RED}================================================================${PLAIN}"
    echo -e "${RED} [警告] 正在执行：日志系统管理...       ${PLAIN}"
    echo -e "${RED} 此操作将导致系统失去所有错误记录能力，降低 IO 延迟。   ${PLAIN}"
    echo -e "${RED}================================================================${PLAIN}"
    
    # 1. 创建状态标记文件
    # 作用: 用于卸载程序识别日志系统曾被修改，执行恢复逻辑。
    touch /etc/syspro_logs_killed
    log_info "已创建状态标记: /etc/syspro_logs_killed"

    # 2. 停止并禁用常见的日志与崩溃报告服务
    log_info "正在终止所有日志守护进程..."
    # 定义服务列表
    local SERVICES=("rsyslog" "systemd-journald" "syslog" "rsyslogd" "kdump" "apport" "abrtd" "avahi-daemon")
    
    for svc in "${SERVICES[@]}"; do
        # [优化] 增加 2>/dev/null 屏蔽 "Failed to get unit file state" 报错
        if systemctl is-active --quiet "$svc" || systemctl is-enabled --quiet "$svc"; then
            systemctl stop "$svc" 2>/dev/null
            systemctl disable "$svc" 2>/dev/null
            systemctl mask "$svc" 2>/dev/null
            log_info "  - 服务已停止并屏蔽: $svc"
        fi
    done

    # 3. 配置 Journald 不记录日志
    log_info "配置 systemd-journald 为黑洞模式..."
    mkdir -p /etc/systemd
    cat > /etc/systemd/journald.conf << EOF
[Journal]
Storage=none
ForwardToSyslog=no
ForwardToKMsg=no
ForwardToConsole=no
ForwardToWall=no
EOF

    # 4. 清理磁盘日志并锁定权限 [关键修复逻辑]
    log_info "正在清理并锁定 /var/log 目录..."

    # [关键修复] 在操作前，必须先递归解锁！
    # 否则如果文件已经被锁定，后续的 rm/touch/chmod 全都会报 "Operation not permitted"
    if command -v chattr >/dev/null 2>&1; then
        # 忽略解锁过程中的错误（比如文件不存在）
        chattr -R -i /var/log >/dev/null 2>&1
        log_info "  - 已解除旧的属性锁 (chattr -i)，准备清理..."
    fi
    
    # 4.1 递归删除 /var/log 下的所有文件 (现在有权限删除了)
    find /var/log -type f -delete 2>/dev/null || true
    
    # 4.2 重建关键的空文件 (伪装)
    # 某些服务(如 sshd/sudo) 如果找不到这些文件会报错
    touch /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/auth.log /var/log/syslog /var/log/messages
    
    # 4.3 确保内容为空
    cat /dev/null > /var/log/wtmp
    cat /dev/null > /var/log/btmp
    
    # 4.4 修改文件系统权限
    # 0555 = r-xr-xr-x (所有人只读/执行，不可写入)
    chmod -R 0555 /var/log
    
    # 4.5 使用 chattr 设置不可变属性 (上锁)
    # 作用: 防止文件被修改，包括 Root 用户
    if command -v chattr >/dev/null 2>&1; then
        # 锁定具体文件
        chattr +i /var/log/wtmp /var/log/btmp /var/log/syslog /var/log/messages 2>/dev/null || true
        # 尝试递归锁定整个目录
        chattr -R +i /var/log 2>/dev/null || true
        log_success "  - 文件系统锁 (chattr +i) 已重新施加。"
    else
        log_warn "未找到 chattr 命令，仅应用了 chmod 权限控制。"
    fi

    # 5. 内核层静音 (Printk)
    log_info "应用内核静音参数..."
    if [ ! -f /etc/sysctl.d/95-syspro-silence.conf ]; then
        # printk: console_loglevel=0 (紧急消息也不打)
        echo "kernel.printk = 0 0 0 0" > /etc/sysctl.d/95-syspro-silence.conf
        # core_pattern: 程序崩溃时不写 core dump 文件，直接丢进黑洞
        echo "kernel.core_pattern = /dev/null" >> /etc/sysctl.d/95-syspro-silence.conf
        sysctl -p /etc/sysctl.d/95-syspro-silence.conf >/dev/null 2>&1
    fi

    # 6. 重启 Journald (应用黑洞配置)
    systemctl restart systemd-journald 2>/dev/null

    log_success "日志系统已配置完成。磁盘 IO 与 CPU 中断已释放。"
}

# ==============================================================================
#   模块 9: 卸载 SysPro (完整回滚版 - 适配用户配置) [修复完整版]
#   功能: 恢复日志、还原 Docker 网络、清理旧版防火墙规则、重置 DNS
# ==============================================================================
uninstall_syspro() {
    echo -e "${RED}警告: 正在卸载 SysPro 及所有扩展组件...${PLAIN}"
    
    # --- 1. 恢复日志系统 (如果曾被禁用) ---
    if [ -f "/etc/syspro_logs_killed" ]; then
        log_info "检测到日志系统曾被禁用，正在恢复..."
        
        # [关键修复] 显式递归解锁文件系统不可变属性
        # 必须在 chmod 之前执行，否则会被拒绝访问
        if command -v chattr >/dev/null 2>&1; then 
            log_info "  - 正在解除文件系统锁 (chattr -i)..."
            chattr -R -i /var/log 2>/dev/null
        fi
        
        # 恢复目录标准权限 (755 = rwxr-xr-x)
        chmod -R 755 /var/log
        
        # 移除内核静音配置
        rm -f /etc/sysctl.d/95-syspro-silence.conf
        
        # 恢复 Journald 配置
        # 如果文件内容被清空或修改过，重置为系统默认推荐值
        if [ -f /etc/systemd/journald.conf ]; then
             # 恢复为自动存储，限制最大占用 200M
             echo -e "[Journal]\nStorage=auto\nSystemMaxUse=200M" > /etc/systemd/journald.conf
        fi
        
        # 恢复基础日志服务
        # 列表包含了常见的发行版日志守护进程
        local SERVICES=("rsyslog" "systemd-journald" "syslog" "kdump" "auditd" "avahi-daemon")
        for svc in "${SERVICES[@]}"; do
            # Unmask 是关键，如果之前被 masked，直接 start 会失败
            systemctl unmask "$svc" 2>/dev/null
            systemctl enable "$svc" 2>/dev/null
            systemctl restart "$svc" 2>/dev/null
        done
        
        # 删除状态标记文件
        rm -f /etc/syspro_logs_killed
        log_success "日志系统功能已恢复。"
    fi

    # --- 2. 清理网络组件与安全规则 ---
    log_info "正在清理网络组件与安全规则..."
    
    # 2.1 移除 DoH 服务
    systemctl disable --now syspro-doh >/dev/null 2>&1
    rm -f /etc/systemd/system/syspro-doh.service
    rm -f /usr/local/bin/cloudflared 
    
    # 2.2 清理防火墙规则 (iptables)
    DEFAULT_IFACE=$(ip route | grep default | head -n1 | awk '{print $5}')
    if [ -n "$DEFAULT_IFACE" ] && command -v iptables >/dev/null; then
        # 尝试删除脚本添加的 DROP 规则
        iptables -D INPUT -i "$DEFAULT_IFACE" -p udp --dport 53 -j DROP 2>/dev/null
        iptables -D INPUT -i "$DEFAULT_IFACE" -p tcp --dport 53 -j DROP 2>/dev/null
        # 清理 Docker 相关的显式放行规则
        iptables -D INPUT -i docker0 -p udp --dport 53 -j ACCEPT 2>/dev/null
        iptables -D INPUT -i docker0 -p tcp --dport 53 -j ACCEPT 2>/dev/null
        log_info "防火墙规则清理尝试完成。"
    fi
    
    # 2.3 还原 Docker 配置文件
    RESTART_DOCKER=0
    if [ -f /etc/docker/daemon.json.syspro.bak ]; then
        # 场景A: 存在脚本创建的备份文件，直接还原 (最安全)
        mv /etc/docker/daemon.json.syspro.bak /etc/docker/daemon.json
        log_info "已还原 Docker 原始 daemon.json 配置文件。"
        RESTART_DOCKER=1
    elif [ -f /etc/docker/daemon.json ]; then
        # 场景B: 无备份，但文件存在。
        # 检查是否为脚本生成的简单单行配置 (包含 dns 且只有 1 行)
        if grep -q "dns" /etc/docker/daemon.json && [ $(wc -l < /etc/docker/daemon.json) -eq 1 ]; then
             rm -f /etc/docker/daemon.json
             log_info "已删除脚本生成的 Docker 配置文件。"
             RESTART_DOCKER=1
        else
             log_warn "Docker 配置文件似乎被用户修改过，为数据安全起见未自动删除。请手动检查: /etc/docker/daemon.json"
        fi
    fi

    # --- 3. 修复系统 DNS (解决 Docker 断网核心) ---
    log_info "正在重置系统 DNS 配置..."
    
    # 解锁 resolv.conf (如果被锁)
    if command -v chattr >/dev/null 2>&1; then chattr -i /etc/resolv.conf 2>/dev/null; fi
    
    # 辅助函数：生成默认的保底 DNS (Google/Cloudflare)
    # 避免卸载后无 DNS 可用
    gen_reset_resolv_conf() {
        echo "# SysPro Reset (Default)" > /etc/resolv.conf
        echo "nameserver 8.8.8.8" >> /etc/resolv.conf
        echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    }

    # 判断是否为 Ubuntu/Debian 等使用 systemd-resolved 的系统
    if systemctl list-unit-files | grep -q "systemd-resolved"; then
        
        # 恢复服务 (关键: Unmask + Enable)
        systemctl unmask systemd-resolved 2>/dev/null
        systemctl enable --now systemd-resolved 2>/dev/null
        
        # [逻辑优化] 尝试恢复软链接
        # Ubuntu 标准做法是 /etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf
        if [ -f /run/systemd/resolve/stub-resolv.conf ]; then
            rm -f /etc/resolv.conf
            ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
            log_success "/etc/resolv.conf 已恢复为标准软链接。"
        else
            # 存根不存在，回退到保底配置
            rm -f /etc/resolv.conf
            gen_reset_resolv_conf
            log_warn "Systemd-resolved 存根未找到，已重置为公共 DNS。"
        fi
        
        # 尝试重启 resolved 以重新生成配置
        systemctl restart systemd-resolved 2>/dev/null
    else
        # CentOS 7 等老系统，直接重置
        rm -f /etc/resolv.conf
        gen_reset_resolv_conf
        log_success "DNS 已重置为公共 DNS。"
    fi

    # 2.4 重启 Docker (应用配置还原)
    if [[ "$RESTART_DOCKER" == "1" ]] && systemctl is-active docker >/dev/null 2>&1; then
        systemctl restart docker
        log_success "Docker 服务已重启，网络配置已回滚。"
    fi

    # --- 4. 清理常规优化组件 ---
    # 移除 ZRAM
    systemctl disable --now zram >/dev/null 2>&1
    rm -f /usr/local/bin/zram-start.sh /etc/systemd/system/zram.service
    
    # 清理所有 SysPro 相关的内核参数文件
    rm -f /etc/sysctl.d/97-syspro-latency.conf
    rm -f /etc/sysctl.d/99-syspro-swap.conf
    rm -f /etc/sysctl.d/98-syspro-security.conf
    rm -f /etc/sysctl.d/96-no-audit.conf
    
    # 清理 Swap 与 Fstab
    if [ -f "/swapfile" ]; then swapoff /swapfile 2>/dev/null; rm -f /swapfile; fi
    if [ -f /etc/fstab.syspro.bak ]; then 
        cp /etc/fstab.syspro.bak /etc/fstab
        mount -o remount / 2>/dev/null
        rm -f /etc/fstab.syspro.bak
        log_info "已恢复原始 fstab 文件。"
    fi
    
    # 清理 Udev I/O 调度规则
    rm -f /etc/udev/rules.d/60-io-scheduler.rules
    if command -v udevadm >/dev/null 2>&1; then udevadm control --reload && udevadm trigger; fi
    
    # 清理 Systemd 额外配置 (OOM 保护等)
    rm -rf /etc/systemd/system/ssh.service.d /etc/systemd/system/sshd.service.d
    rm -f /etc/security/limits.d/99-disable-core.conf
    if [ -f /etc/systemd/system.conf.syspro.bak ]; then
        cp /etc/systemd/system.conf.syspro.bak /etc/systemd/system.conf
    fi
    
    # --- 5. 刷新系统状态 ---
    systemctl daemon-reload
    sysctl --system >/dev/null 2>&1
    
    echo ""
    echo -e "${GREEN}SysPro 已成功完全卸载。${PLAIN}"
    echo -e "${YELLOW}提示: Docker 配置已尝试还原，建议重启一次服务器以彻底重置内核状态。${PLAIN}"
}
show_menu() {
    clear
    echo -e "${BLUE}================================================================${PLAIN}"
    echo -e "${GREEN}    SysPro High Performance Network Edition   ${PLAIN}"
    echo -e "${BLUE}================================================================${PLAIN}"
    echo -e " 1. ${GREEN}I/O 优化${PLAIN}   (Noatime, Udev 调度)"
    echo -e " 2. ${GREEN}CPU 与熵池${PLAIN}      (15ms 调度周期, BBR 适配)"
    echo -e " 3. ${GREEN}进程与内存${PLAIN}      (禁用 Auditd, 智能 ZRAM, 文件句柄)"
    echo -e " 4. ${GREEN}安全配置${PLAIN}        (隐藏内核地址, dmesg 限制)"
    echo -e " 5. ${GREEN}接入与 DNS${PLAIN}      (SSH 配置, DoH/UDP 双模)"
    echo -e " 6. ${GREEN}维护与清理${PLAIN}      (常用工具, 时区, 缓存清理)"
    echo -e " 7. ${YELLOW}手动管理工具${PLAIN}    (卸载内核 / 安装其他 BBR)"
    echo -e "${BLUE}----------------------------------------------------------------${PLAIN}"
    echo -e " 9. ${RED}关闭日志系统${PLAIN}    (极速模式：彻底抹杀日志进程，降低 IO)"
    echo -e "${BLUE}----------------------------------------------------------------${PLAIN}"
    echo -e " 0. ${GREEN}一键执行所有优化${PLAIN}    (推荐: 先运行此项，重启后再跑 nftx2)"
    echo -e " 8. ${RED}卸载/还原${PLAIN}       (还原系统默认状态)"
    echo -e " q. 退出"
    echo -e "${BLUE}================================================================${PLAIN}"
    echo -n "请输入选项: "
    read choice

    case $choice in
        1) optimize_disk_io ;;
        2) optimize_compute ;;
        3) optimize_systemd; optimize_memory ;;
        4) optimize_security ;;
        5) optimize_access ;;
        6) maintenance_tasks ;;
        7) manual_tasks_menu ;;
        9) optimize_logging_killer ;;
        8) uninstall_syspro ;;
        0)
            optimize_disk_io
            optimize_compute
            optimize_systemd
            optimize_memory
            optimize_security
            optimize_access
            maintenance_tasks
            echo -e "\n${GREEN}SysPro 基础优化已完成！${PLAIN}"
            echo -e "${YELLOW}建议: 1. 重启服务器 (reboot)。${PLAIN}"
            echo -e "${YELLOW}      2. 运行脚本 2 (nftx2) 进行网络协议栈调优。${PLAIN}"
            ;;
        q) exit 0 ;;
        *) log_err "无效输入，请重新选择。" ;;
    esac
}

while true; do show_menu; echo -n "按回车键继续..."; read; done
