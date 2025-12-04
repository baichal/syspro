#!/bin/bash
#
# ==============================================================================
#   SysPro Linux Deep Infrastructure Optimizer (ARM 增强全量版)
#   (Foundation Layer | DoH Support | Safe Operations | ARM Ready)
# ==============================================================================
#
#   [版本特性 - v5.3 ARM Special]
#   1. 全架构支持: 完美适配 x86_64 (AMD/Intel), aarch64 (Oracle ARM/Apple Silicon), armv7l (Raspberry Pi).
#   2. 存储深度优化: 增加对 SD 卡/eMMC (mmcblk) 的 I/O 调度支持，防止树莓派卡顿。
#   3. 安全优先: SSH 重启前强制校验配置；ARM 环境下限制危险的换内核操作。
#   4. 现代兼容: 智能检测内核版本 (5.6+) 跳过过时的 Haveged。
#   5. 文件系统: Swap 创建自动适配 Btrfs (No-CoW) 并在 ext4 上使用 fallocate 加速。
#   6. 网络共存: 温和处理 systemd-resolved，防止 53 端口冲突。
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
#   全局辅助函数：智能包管理器更新
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
        # 调试用，实际运行时可注释掉
        # log_info "包管理器缓存已更新，跳过。" 
        :
    fi
}

# --- 使用说明 ---
# 在后续所有模块中 (如 optimize_compute, maintenance_tasks)，
# 将原本的 "apt-get update" 替换为 "smart_pkg_update" 即可。

# ==============================================================================
#   模块 1: 磁盘 I/O 深度调优 (Disk I/O) - [低延迟服务器定制版]
#   修改说明: 移除 CPU 密集型的 bfq 算法，全面转向 mq-deadline/none
# ==============================================================================
optimize_disk_io() {
    log_info "正在优化磁盘 I/O 策略 (低延迟/网络优先模式)..."
    
    # --- 1.1 挂载参数优化 (noatime) ---
    # 保持原逻辑：减少文件访问时间写入，大幅降低小文件 I/O 延迟
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
# 原因: 现代 NVMe 极快，且 VPS 的 I/O 由宿主机管理，虚拟机内部不应再做复杂调度
ACTION=="add|change", KERNEL=="nvme[0-9]*n[0-9]*|vd[a-z]*", ATTR{queue/scheduler}="none"

# 2. 物理 SATA SSD / 机械硬盘 (HDD) / SD卡 (树莓派)
# 策略: mq-deadline
# 原因: 相比 bfq，它更轻量，延迟更低，适合数据库和高吞吐网络服务器
ACTION=="add|change", KERNEL=="sd[a-z]*|mmcblk[0-9]*", ATTR{queue/scheduler}="mq-deadline"

# 3. 减少预读 (Read-ahead)
# 对于随机读写较多的服务器，过大的预读浪费内存；设为 256KB (512扇区) 比较均衡
ACTION=="add|change", KERNEL=="vd[a-z]*|sd[a-z]*", ATTR{bdi/read_ahead_kb}="256"
EOF
        # 重载规则并触发
        udevadm control --reload && udevadm trigger
        log_success "I/O 调度器规则已更新 (Latency-First 策略)。"
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
#   模块 2: 算力与调度 (Compute & Latency) - [v5.4 低延迟特化版]
# ==============================================================================
optimize_compute() {
    log_info "正在优化 CPU 调度器与电源管理 (极速响应模式)..."

    # --- 2.1 熵池补充 (Haveged) ---
    # 保持原逻辑：5.6 以下内核补充熵池，避免加密握手卡顿
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

    # --- 2.2 内核调度器微调 (CFS Micro-Tuning) ---
    # 原理: Linux 默认调度器倾向于让任务跑久一点以增加吞吐量(Throughput)。
    # 对于低延迟场景，我们需要让调度器更频繁地检查任务队列，以便网卡中断能瞬间抢占 CPU。
    
    cat > /etc/sysctl.d/97-syspro-latency.conf << EOF
# [关键] 调度延迟周期 (Scheduler Latency)
# 定义了一个任务队列轮询的周期。默认通常是 24ms。
# 改为 3ms: 强迫 CPU 更频繁地检查是否有新任务(如网络包)到来。
kernel.sched_latency_ns = 3000000

# [关键] 唤醒粒度 (Wakeup Granularity)
# 定义了任务抢占的最小时间片。默认通常是 4ms。
# 改为 0.5ms (500us): 只要有高优先级任务(如软中断)到来，当前任务会更快让路。
kernel.sched_wakeup_granularity_ns = 500000

# 迁移成本 (Migration Cost)
# 降低任务在不同 CPU 核心间迁移的“预估成本”，允许任务更积极地寻找空闲核心。
kernel.sched_migration_cost_ns = 250000

# 禁用 RT 节流 (Realtime Throttling)
# 防止处理网络包的实时进程(Realtime)占用 CPU 时间过长被内核强行掐断。
# 设置为 -1 表示禁用限制，允许关键进程跑满 CPU。
kernel.sched_rt_runtime_us = -1
EOF
    sysctl -p /etc/sysctl.d/97-syspro-latency.conf >/dev/null 2>&1
    log_success "内核 CFS 调度器已优化 (微秒级响应调优)。"

    # --- 2.3 CPU 模式锁定与 C-State 禁用 (Ping 优化核心) ---
    # 原理: 现代 CPU 极其省电，空闲时会进入 C-States (深度睡眠)。
    # 从 C6/C7 睡眠唤醒到 C0 工作状态需要几十微秒，导致 Ping 值抖动。
    # 我们的目标是: 让 CPU 永远不睡觉 (Always On)。
    
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
            # A. 锁定 Performance 频率 (P-State): 始终保持最高主频
            cpupower frequency-set -g performance >/dev/null 2>&1
            
            # B. 禁用 C-States (Idle State): 禁止睡眠
            # 获取当前 CPU 支持的 idle 状态数量
            IDLE_STATES=$(cpupower idle-info 2>/dev/null | grep "Number of idle states:" | awk '{print $NF}')
            
            if [ -n "$IDLE_STATES" ] && [ "$IDLE_STATES" -gt 1 ]; then
                # 禁用 State 1 及以上的所有深度睡眠状态 (仅保留 State 0 - POLL)
                # 这会增加功耗，但能消除唤醒延迟
                cpupower idle-set -D 1 >/dev/null 2>&1
                log_success "CPU 频率已锁定，且已禁用深度睡眠 (C-States Disabled)。"
            else
                log_success "CPU 频率已锁定 (未检测到多级睡眠状态)。"
            fi
        else
            # C. 回退方案: 直接修改 Sysfs (如果 cpupower 安装失败)
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
#   模块 3-1: Systemd 全局配置与进程保护 (更新：禁用审计开销)
# ==============================================================================
optimize_systemd() {
    log_info "优化 Systemd 与削减系统开销..."
    
    # --- 3.0 [新增] 禁用 Auditd (审计服务) ---
    # 原理: Auditd 会 Hook 每一个系统调用(Syscall)来记录日志。
    # 在高并发网络下，这会显著拖慢系统调用的返回速度。关闭它能减少内核路径开销。
    if systemctl is-active auditd >/dev/null 2>&1; then
        log_info "正在禁用 auditd 审计服务 (减少系统调用开销)..."
        systemctl stop auditd
        systemctl disable auditd
        
        # 即使关了服务，内核可能还在产生审计消息，通过 sysctl 彻底屏蔽
        # kernel.printk = 3 4 1 3 (抑制控制台日志)
        if [ ! -f /etc/sysctl.d/96-no-audit.conf ]; then
             echo "kernel.printk = 3 4 1 3" > /etc/sysctl.d/96-no-audit.conf
        fi
        log_success "Auditd 服务已禁用。"
    fi
    
    # --- 3.1 Systemd 超时优化 ---
    # 减少关机等待时间
    [ ! -f /etc/systemd/system.conf.syspro.bak ] && cp /etc/systemd/system.conf /etc/systemd/system.conf.syspro.bak
    sed -i -e 's/^#\?DefaultTimeoutStopSec=.*/DefaultTimeoutStopSec=10s/' /etc/systemd/system.conf
    systemctl daemon-reload
    
    # --- 3.2 禁用 Core Dump ---
    # 防止程序崩溃时写入大量磁盘数据，导致瞬间 I/O 卡顿
    if [ ! -d /etc/security/limits.d ]; then mkdir -p /etc/security/limits.d; fi
    echo "* hard core 0" > /etc/security/limits.d/99-disable-core.conf
    
    # --- 3.3 OOM 关键进程豁免 ---
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
    
    # 清理旧版脚本
    if [ -f /usr/local/bin/oom-protect.sh ]; then
        rm -f /usr/local/bin/oom-protect.sh
        crontab -l 2>/dev/null | grep -v "oom-protect" | crontab -
    fi

    systemctl daemon-reload
    log_success "进程保护与开销优化完成。"
}

# ==============================================================================
#   模块 3-2: 内存结构优化 (ZRAM & Swap) - [轻量化/NFTX2 兼容版]
#   修改说明: 
#     1. ZRAM 大小限制为 RAM 的 20% (原50%)，避免抢占 TCP 缓冲区。
#     2. Swappiness 降为 10，优先使用物理内存，减少 CPU 上下文切换。
# ==============================================================================
optimize_memory() {
    log_info "正在优化内存结构 (ZRAM & Swap)..."

    # --- 3.4 ZRAM 内存压缩 (轻量化配置) ---
    HAS_ZRAM=0
    
    if modinfo zram >/dev/null 2>&1; then
        # 尝试加载模块
        if modprobe zram num_devices=1; then
            
            # 等待设备节点就绪
            if command -v udevadm >/dev/null 2>&1; then
                udevadm settle --timeout=5
            else
                sleep 0.5
            fi

            # 检查是否已启用
            if ! grep -q "zram" /proc/swaps; then
                log_info "配置轻量级 ZRAM (作为 OOM 最后防线)..."
                
                # [关键修改 1] 动态计算 ZRAM 大小
                # 逻辑: 仅占用物理内存的 20%，且最大不超过 1024MB。
                # 目的: 将 80% 以上的物理内存留给 nftx2 进行 TCP BDP 缓冲。
                MEM_TOTAL_MB=$(free -m | awk '/Mem:/ {print $2}')
                
                # 计算 20%
                ZRAM_SIZE=$(($MEM_TOTAL_MB / 5))
                
                # 限制最大值 1GB
                if [ "$ZRAM_SIZE" -gt 1024 ]; then
                    ZRAM_SIZE=1024
                fi
                # 限制最小值 128MB (如果内存太小，给少了没意义)
                if [ "$ZRAM_SIZE" -lt 128 ]; then
                    ZRAM_SIZE=128
                fi
                
                # 算法选择: 优先 zstd (压缩比高), 其次 lzo (速度快)
                ALGO="lzo"
                if [ -f /sys/block/zram0/comp_algorithm ]; then
                    local avail_algos=$(cat /sys/block/zram0/comp_algorithm)
                    if [[ "$avail_algos" == *"zstd"* ]]; then
                        ALGO="zstd"
                    fi
                fi

                # 生成启动脚本
                cat > /usr/local/bin/zram-start.sh <<EOF
#!/bin/bash
modprobe zram num_devices=1
sleep 0.5
# 重置设备 (如果存在)
[ -f /sys/block/zram0/reset ] && echo 1 > /sys/block/zram0/reset 2>/dev/null
# 设置参数
echo "$ALGO" > /sys/block/zram0/comp_algorithm 2>/dev/null
echo "${ZRAM_SIZE}M" > /sys/block/zram0/disksize
# 格式化与启用
mkswap /dev/zram0 >/dev/null 2>&1
# 优先级 100 (高于磁盘 Swap)
swapon -p 100 /dev/zram0
EOF
                chmod +x /usr/local/bin/zram-start.sh
                
                # Systemd Service 封装
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
                
                # 验证状态
                sleep 1
                if grep -q "zram" /proc/swaps; then
                    log_success "ZRAM 已启用 (大小: ${ZRAM_SIZE}MB, 算法: ${ALGO}) - 已限制大小以避让网络缓冲。"
                    HAS_ZRAM=1
                else
                    log_err "ZRAM 启动失败，可能受限于 VPS 虚拟化架构。"
                fi
            else
                log_info "ZRAM 已经处于启用状态，跳过配置。"
                HAS_ZRAM=1
            fi
        else
            log_warn "加载 zram 模块失败，跳过。"
        fi
    else
        log_warn "当前内核缺少 zram 模块，跳过。"
    fi
    
    # --- 3.5 Swappiness 优化 (协同 nftx2) ---
    
    # [新增] 检测 nftx2 是否存在
    NFTX2_EXISTS=0
    if [ -f /etc/sysctl.d/99-nftx2.conf ] || [ -f /etc/systemd/system/nftx2.service ]; then
        NFTX2_EXISTS=1
        log_warn "检测到 nftx2 网络优化套件..."
    fi
    
    # [关键修改 2] 强制低 Swappiness
    # 无论是否有 ZRAM，作为跑流量的机器，应尽量避免内存换页造成的延迟。
    # 设置为 10: 只有当物理内存剩下 10% 时才开始动用 Swap。
    sysctl -w vm.swappiness=10 >/dev/null 2>&1
    
    if [ "$NFTX2_EXISTS" -eq 0 ]; then
        # 只有在没有 nftx2 的情况下，syspro 才持久化这个参数
        # 如果有 nftx2，把控制权交给 nftx2 (nftx2 会根据情况动态调整)
        echo "vm.swappiness = 10" > /etc/sysctl.d/99-syspro-swap.conf
        log_info "  - 已设置 Swappiness = 10 (物理内存优先，降低延迟)。"
    else
        log_info "  - Swappiness 运行时已设为 10，但持久化配置交由 nftx2 管理。"
    fi
    
    # --- 3.6 保底磁盘 Swap ---
    # 只有当系统完全没有 Swap 时，才创建小文件作为防崩溃保险
    CURRENT_SWAP_MB=$(free -m | awk '/Swap:/ {print $2}')
    
    if [ "$CURRENT_SWAP_MB" -ge 512 ]; then
        log_info "系统已有 Swap (${CURRENT_SWAP_MB}MB)，无需额外创建。"
        return
    fi
    
    log_warn "系统无 Swap 且 ZRAM 未生效，正在创建保底 Swap (/swapfile)..."
    
    # 固定为 1GB，不做动态计算，避免占用太多磁盘
    SIZE=1024
    
    # 检查磁盘空间 (至少留 2GB 给系统)
    DISK_AVAIL=$(df -m / | awk 'NR==2 {print $4}')
    if [ "$DISK_AVAIL" -lt 2048 ]; then
        log_err "磁盘空间不足，无法创建保底 Swap。"
        return
    fi

    rm -f /swapfile && touch /swapfile
    
    # Btrfs No-CoW 处理
    FS_TYPE=$(df -T /swapfile | tail -1 | awk '{print $2}')
    if [ "$FS_TYPE" == "btrfs" ] && command -v chattr >/dev/null; then 
        chattr +C /swapfile
    fi
    
    if ! fallocate -l ${SIZE}M /swapfile 2>/dev/null; then
        dd if=/dev/zero of=/swapfile bs=1M count=$SIZE status=none
    fi
    
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1
    swapon /swapfile
    
    if ! grep -q "/swapfile" /etc/fstab; then 
        echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
    fi
    
    log_success "保底磁盘 Swap (${SIZE}MB) 已创建。"
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
#   模块 5: 辅助函数 - Cloudflared 安装与启动 - [完整优化版]
# ==============================================================================
install_cloudflared() {
    log_info "开始部署 Cloudflared DoH 客户端..."
    
    # 1. 架构判断与下载链接
    case $ARCH in
        amd64)
            URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
            ;;
        arm64)
            URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"
            ;;
        armhf)
            URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm"
            ;;
        *)
            log_err "Cloudflared 不支持当前架构: $ARCH ($RAW_ARCH)"
            return 1
            ;;
    esac

    # 2. 下载二进制文件 (增强超时与重试)
    log_info "正在从 GitHub 下载二进制文件 ($ARCH)..."
    if [ ! -f /usr/local/bin/cloudflared ]; then
        # --connect-timeout 5: 连接超时5秒
        # --max-time 60: 整个下载最长60秒
        # --retry 2: 失败重试2次
        if curl -L --retry 2 --connect-timeout 5 --max-time 60 -o /usr/local/bin/cloudflared "$URL"; then
            chmod +x /usr/local/bin/cloudflared
        else
            log_err "下载失败。请检查网络或配置代理。"
            return 1
        fi
    else
        log_info "检测到本地已存在 Cloudflared，跳过下载。"
        chmod +x /usr/local/bin/cloudflared
    fi
    
    # 3. 创建专用用户 (安全性)
    id -u cloudflared &>/dev/null || useradd -M -s /usr/sbin/nologin cloudflared

    # 4. 构造启动参数
    UPSTREAM_ARGS=""
    while read -r url; do
        [[ -z "$url" || "$url" =~ ^# ]] && continue
        UPSTREAM_ARGS="$UPSTREAM_ARGS --upstream $url"
    done <<< "$DOH_URL_LIST"

    # 5. 生成 Systemd Unit 文件
    cat > /etc/systemd/system/syspro-doh.service << EOF
[Unit]
Description=SysPro DoH Client (Cloudflared)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cloudflared
# 允许非 Root 用户绑定 53 端口
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/cloudflared proxy-dns --port 53 --address 127.0.0.1 $UPSTREAM_ARGS
Restart=on-failure
RestartSec=10
StandardOutput=null

[Install]
WantedBy=multi-user.target
EOF

    # 6. [关键] 解决端口冲突
    # Cloudflared 需要监听 53 端口，必须停用 systemd-resolved
    if systemctl is-active systemd-resolved >/dev/null 2>&1; then
        log_warn "检测到 systemd-resolved 占用 53 端口，正在停用..."
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved
        # 删除软链接，防止后续写入 resolv.conf 失败
        rm -f /etc/resolv.conf
    fi

    # 7. 启动服务与状态检测 (事件驱动优化)
    systemctl daemon-reload
    systemctl enable syspro-doh >/dev/null 2>&1
    systemctl restart syspro-doh
    
    log_info "正在等待 DoH 服务启动..."
    
    # 轮询检查状态 (替代 sleep 3)
    # 尝试 20 次，每次间隔 0.2 秒，最长等待 4 秒
    local max_retries=20
    local started=0
    
    for ((i=1; i<=max_retries; i++)); do
        if systemctl is-active --quiet syspro-doh; then
            started=1
            break
        fi
        sleep 0.2
    done
    
    if [ $started -eq 1 ]; then
        log_success "DoH 服务启动成功。"
        return 0
    else
        log_err "DoH 服务启动超时或失败，正在输出最后 10 行日志..."
        journalctl -u syspro-doh --no-pager -n 10
        return 1
    fi
}

optimize_access() {
    log_info "正在优化接入层 (SSH & Environment)..."

    # --- 5.1 SSH 优化 (带回滚) ---
    SSHD_CONF="/etc/ssh/sshd_config"
    [ ! -f ${SSHD_CONF}.syspro.bak ] && cp $SSHD_CONF ${SSHD_CONF}.syspro.bak
    
    # 仅修改必要项
    sed -i \
    -e 's/^#\?UseDNS.*/UseDNS no/' \
    -e 's/^#\?GSSAPIAuthentication.*/GSSAPIAuthentication no/' \
    "$SSHD_CONF"
    
    # 校验并重启
    if sshd -t; then
        if [[ "${RELEASE}" == "centos" ]]; then systemctl restart sshd; else systemctl restart ssh; fi
        log_success "SSH 配置优化完成 (已禁用 DNS反查)。"
    else
        log_err "SSH 配置校验失败，已自动回滚。"
        cp ${SSHD_CONF}.syspro.bak $SSHD_CONF
    fi

    # --- 5.2 [新增] Shell 交互体验优化 ---
    log_info "配置 Shell 历史记录与提示符..."
    # 写入 profile.d 以便对所有用户生效
    cat > /etc/profile.d/syspro_shell.sh << 'EOF'
# SysPro Shell Optimization
# 1. 增加历史记录容量
export HISTSIZE=10000
export HISTFILESIZE=20000
# 2. 忽略重复命令
export HISTCONTROL=ignoreboth
# 3. 增加时间戳 (年-月-日 时:分:秒)
export HISTTIMEFORMAT="%F %T "
# 4. 防止多窗口覆盖历史记录
shopt -s histappend
export PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"
# 5. Root 用户提示符标红 (警示作用)
if [ "$EUID" -eq 0 ]; then
    PS1='\[\e[1;31m\]\u@\h\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
fi
EOF
    log_success "Shell 环境配置已生成 (/etc/profile.d/syspro_shell.sh)。"

    # --- 5.3 DNS 配置 ---
    echo -e "${YELLOW}请选择 DNS 模式:${PLAIN}"
    echo -e " 1. ${GREEN}标准 UDP DNS${PLAIN} (速度快, 1.1.1.1/8.8.8.8)"
    echo -e " 2. ${GREEN}DoH 加密 DNS${PLAIN} (防劫持, 支持 ARM)"
    read -p "请输入选项 [1-2] (默认1): " DNS_CHOICE
    
    # 1. 解锁并准备文件
    chattr -i /etc/resolv.conf >/dev/null 2>&1
    
    # 2. 如果存在旧的 DoH 服务，先停止，防止冲突
    if [ -f /etc/systemd/system/syspro-doh.service ]; then
        systemctl stop syspro-doh
        systemctl disable syspro-doh
    fi

    # 3. 处理 DoH 选项
    if [[ "$DNS_CHOICE" == "2" ]]; then
        if install_cloudflared; then
            rm -f /etc/resolv.conf
            echo "# SysPro DoH (Cloudflared)" > /etc/resolv.conf
            echo "nameserver 127.0.0.1" >> /etc/resolv.conf
            # 添加备用 DNS 防止 Cloudflared 挂掉断网
            echo "# Fallback DNS" >> /etc/resolv.conf
            echo "nameserver 1.1.1.1" >> /etc/resolv.conf
            echo "options timeout:1 attempts:1" >> /etc/resolv.conf
            
            chattr +i /etc/resolv.conf
            log_success "DoH 模式已生效 (Resolv.conf 已锁定)。"
        else
            log_warn "DoH 安装失败，自动回退到标准 UDP 模式。"
            DNS_CHOICE="1"
        fi
    fi

    # 4. 处理标准 DNS 选项 (或回退)
    if [[ "$DNS_CHOICE" != "2" ]]; then
        rm -f /etc/resolv.conf
        echo "# SysPro Standard DNS" > /etc/resolv.conf
        
        while read -r ip; do
            [[ -z "$ip" || "$ip" =~ ^# ]] && continue
            echo "nameserver $ip" >> /etc/resolv.conf
        done <<< "$DNS_IPV4_LIST"
        
        # IPv6
        if ip -6 addr show scope global | grep -q inet6; then
            while read -r ip; do
                [[ -z "$ip" || "$ip" =~ ^# ]] && continue
                echo "nameserver $ip" >> /etc/resolv.conf
            done <<< "$DNS_IPV6_LIST"
        fi
        
        echo "options timeout:1 attempts:2" >> /etc/resolv.conf
        chattr +i /etc/resolv.conf
        log_success "标准 DNS 模式已生效 (Resolv.conf 已锁定)。"
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
    
    # 优化 Chrony 配置 (激进同步)
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
    
    # --- 6.2 [修正] 时区设置 (交互式) ---
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
#   模块 7: 手动管理工具 (ARM 安全修正)
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

    # [ARM 兼容性] 引导更新逻辑
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

# 7.2 安装第三方 BBR (ARM 风险提示)
action_install_other_bbr() {
    clear
    echo -e "${YELLOW}======================================================${PLAIN}"
    echo -e " 准备运行第三方 BBR 安装脚本 (Source: git.io/kernel.sh)"
    echo -e " 注意: 这将从网络下载脚本并以 Root 权限执行。"
    
    # [ARM 严重警告]
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
#   模块 8: 彻底抹杀日志系统 (Log Killer) - [从脚本1移植的暴力模式]
#   功能: 停止服务 -> 清空文件 -> 锁定权限 -> 内核静音 -> 创建标记
# ==============================================================================
optimize_logging_killer() {
    echo -e "${RED}================================================================${PLAIN}"
    echo -e "${RED} [警告] 正在执行：彻底抹杀日志系统 (IO/CPU 极致释放)...       ${PLAIN}"
    echo -e "${RED} 此操作将导致系统失去所有错误记录能力，但能显著降低 IO 延迟。   ${PLAIN}"
    echo -e "${RED}================================================================${PLAIN}"
    
    # [关键步骤 0] 创建状态标记文件
    # 作用: 就像一个"墓碑"，告诉卸载程序这里曾经发生过"屠杀"，需要特殊复活逻辑。
    touch /etc/syspro_logs_killed
    log_info "已创建状态标记: /etc/syspro_logs_killed"

    # [步骤 1] 停止并禁用常见的日志与崩溃报告服务
    # 作用: 立即释放被这些守护进程占用的内存和 CPU 时间片
    log_info "正在终止所有日志守护进程..."
    # 定义服务列表：包括传统的 rsyslog, systemd日志, 以及崩溃转储工具 kdump/apport
    local SERVICES=("rsyslog" "systemd-journald" "syslog" "rsyslogd" "kdump" "apport" "abrtd" "avahi-daemon")
    
    for svc in "${SERVICES[@]}"; do
        # 检查服务是否存在或正在运行
        if systemctl is-active --quiet "$svc" || systemctl is-enabled --quiet "$svc"; then
            systemctl stop "$svc" 2>/dev/null
            systemctl disable "$svc" 2>/dev/null
            # [重要] Mask (屏蔽) 服务：防止被其他依赖服务自动唤醒
            systemctl mask "$svc" 2>/dev/null
            log_info "  - 服务已停止并屏蔽: $svc"
        fi
    done

    # [步骤 2] 暴力配置 Journald (使其变成黑洞)
    # 作用: 即使 systemd-journald 被核心进程强制唤醒，配置它不记录任何数据到磁盘或内存
    log_info "配置 systemd-journald 为黑洞模式..."
    cat > /etc/systemd/journald.conf << EOF
[Journal]
Storage=none
ForwardToSyslog=no
ForwardToKMsg=no
ForwardToConsole=no
ForwardToWall=no
EOF

    # [步骤 3] 清理磁盘日志并锁定权限 (核心提速点)
    # 作用: 删除现有的大日志文件，并物理阻断未来的写入操作 (Permission Denied)
    log_info "正在清理并锁定 /var/log 目录..."
    
    # 3.1 递归删除 /var/log 下的所有文件
    find /var/log -type f -delete 2>/dev/null || true
    
    # 3.2 重建关键的空文件 (伪装)
    # 原因: 某些服务(如 sshd)登录时如果找不到 wtmp/btmp 会报错或拒绝登录
    touch /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/auth.log /var/log/syslog /var/log/messages
    
    # 3.3 暴力清空内容 (双重保险)
    cat /dev/null > /var/log/wtmp
    cat /dev/null > /var/log/btmp
    
    # 3.4 修改文件系统权限
    # 0555 = r-xr-xr-x (所有人只读/执行，不可写入)
    chmod -R 0555 /var/log
    
    # 3.5 [绝杀] 使用 chattr 设置不可变属性
    # 作用: 即使是 Root 用户也无法使用 rm 或 echo 修改文件，除非先 chattr -i
    if command -v chattr >/dev/null 2>&1; then
        chattr +i /var/log/wtmp /var/log/btmp /var/log/syslog /var/log/messages 2>/dev/null || true
        # 尝试递归锁定整个目录 (可能会失败，忽略错误)
        chattr -R +i /var/log 2>/dev/null || true
        log_success "  - 文件系统锁 (chattr +i) 已施加。"
    fi

    # [步骤 4] 内核层静音 (Printk)
    # 作用: 禁止内核向控制台(Console)打印消息，减少高负载下的 CPU 中断
    log_info "应用内核静音参数..."
    # 备份现有配置 (如果不存在)
    if [ ! -f /etc/sysctl.d/95-syspro-silence.conf ]; then
        # printk: console_loglevel=0 (紧急消息也不打)
        echo "kernel.printk = 0 0 0 0" > /etc/sysctl.d/95-syspro-silence.conf
        # core_pattern: 程序崩溃时不写 core dump 文件，直接丢进黑洞
        echo "kernel.core_pattern = /dev/null" >> /etc/sysctl.d/95-syspro-silence.conf
        sysctl -p /etc/sysctl.d/95-syspro-silence.conf >/dev/null 2>&1
    fi

    # [步骤 5] 尝试重启 Journald 使"黑洞配置"生效
    # 因为前面 Mask 了，这里可能启动失败，这正是我们要的效果
    systemctl restart systemd-journald 2>/dev/null

    log_success "日志系统已彻底处决。磁盘 IO 与 CPU 中断已释放。"
}

# ==============================================================================
#   模块 9: 卸载 SysPro
# ==============================================================================
uninstall_syspro() {
    echo -e "${RED}警告: 正在卸载 SysPro 及所有扩展组件...${PLAIN}"
    
    # --- [关键逻辑] 检查是否存在日志被杀的标记 ---
    if [ -f "/etc/syspro_logs_killed" ]; then
        log_info "检测到日志系统曾被禁用 (/etc/syspro_logs_killed)，正在执行复活手术..."
        
        # [恢复步骤 1] 必须先解锁文件属性 (chattr -i)
        # 如果不先做这一步，后续的 chmod 和 rm 都会提示 "Operation not permitted"
        log_info "  - 解锁文件系统不可变属性..."
        if command -v chattr >/dev/null 2>&1; then
            chattr -R -i /var/log 2>/dev/null
        fi
        
        # [恢复步骤 2] 恢复目录写权限
        # 恢复为标准的 755 (rwxr-xr-x)
        chmod -R 755 /var/log
        
        # [恢复步骤 3] 移除内核静音配置
        rm -f /etc/sysctl.d/95-syspro-silence.conf
        
        # [恢复步骤 4] 恢复 Journald 配置文件
        # 删除我们写入的"黑洞配置"
        rm -f /etc/systemd/journald.conf
        
        # 如果配置文件被删没了，尝试写入一个标准的默认值，防止服务报错
        if [ ! -f /etc/systemd/journald.conf ]; then
             echo "[Journal]" > /etc/systemd/journald.conf
             echo "Storage=auto" >> /etc/systemd/journald.conf
             # 限制日志大小，防止恢复后日志瞬间撑爆硬盘
             echo "SystemMaxUse=200M" >> /etc/systemd/journald.conf
        fi
        
        # [恢复步骤 5] 解除服务屏蔽 (Unmask) 并重启
        local SERVICES=("rsyslog" "systemd-journald" "syslog" "kdump")
        for svc in "${SERVICES[@]}"; do
            # Unmask: 移除指向 /dev/null 的软链接
            systemctl unmask "$svc" 2>/dev/null
            # Enable: 设置开机自启
            systemctl enable "$svc" 2>/dev/null
            # Restart: 立即启动
            systemctl restart "$svc" 2>/dev/null
        done
        
        # [恢复步骤 6] 销毁墓碑 (删除标记文件)
        rm -f /etc/syspro_logs_killed
        log_success "日志系统功能已恢复，服务已重启。"
    else
        log_info "日志系统未被深度修改，无需执行恢复流程。"
    fi

    # --- 以下是常规组件的卸载逻辑 ---
    
    log_info "正在清理 DNS 与网络组件..."
    # 1. 解锁并重置 resolv.conf (必须先 chattr -i)
    chattr -i /etc/resolv.conf >/dev/null 2>&1
    rm -f /etc/resolv.conf
    # 恢复为 Google/Cloudflare 公共 DNS
    echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf
    
    # 2. 停止并清理 DoH 和 ZRAM 服务
    systemctl disable --now syspro-doh zram >/dev/null 2>&1
    rm -f /etc/systemd/system/syspro-doh.service
    rm -f /etc/systemd/system/zram.service
    
    # 3. 删除二进制文件与脚本
    rm -f /usr/local/bin/cloudflared 
    rm -f /usr/local/bin/zram-start.sh
    
    # 4. 清理内核参数 (Sysctl)
    log_info "正在清理内核优化参数..."
    rm -f /etc/sysctl.d/97-syspro-latency.conf
    rm -f /etc/sysctl.d/99-syspro-swap.conf
    rm -f /etc/sysctl.d/98-syspro-security.conf
    rm -f /etc/sysctl.d/96-no-audit.conf
    
    # 5. 清理 Swap 文件与 Fstab 挂载
    if [ -f "/swapfile" ]; then 
        swapoff /swapfile 2>/dev/null
        rm -f /swapfile
        log_info "  - 已删除 /swapfile"
    fi
    # 还原 fstab (去除 noatime 等)
    if [ -f /etc/fstab.syspro.bak ]; then 
        cp /etc/fstab.syspro.bak /etc/fstab
        # 重新挂载根目录使参数生效
        mount -o remount / 2>/dev/null
    fi
    
    # 6. 清理 Udev 规则 (IO调度)
    rm -f /etc/udev/rules.d/60-io-scheduler.rules
    if command -v udevadm >/dev/null 2>&1; then 
        udevadm control --reload && udevadm trigger
    fi
    
    # 7. 清理 Systemd 全局配置与 OOM 保护
    rm -rf /etc/systemd/system/ssh.service.d
    rm -f /etc/security/limits.d/99-disable-core.conf
    if [ -f /etc/systemd/system.conf.syspro.bak ]; then
        cp /etc/systemd/system.conf.syspro.bak /etc/systemd/system.conf
    fi
    
    # 8. 刷新系统状态
    systemctl daemon-reload
    sysctl --system >/dev/null 2>&1
    
    echo ""
    echo -e "${GREEN}SysPro 已成功完全卸载。${PLAIN}"
    echo -e "${YELLOW}提示: 建议重启服务器 (reboot) 以彻底重置内核状态。${PLAIN}"
}

# ==============================================================================
#   主菜单
# ==============================================================================
show_menu() {
    clear
    echo -e "${BLUE}================================================================${PLAIN}"
    echo -e "${GREEN}    SysPro v5.4 - Infrastructure Optimizer (Log Killer Mod)   ${PLAIN}"
    echo -e "${BLUE}================================================================${PLAIN}"
    echo -e " 1. ${GREEN}深度 I/O 优化${PLAIN}   (Noatime, Udev 智能调度)"
    echo -e " 2. ${GREEN}算力与熵池${PLAIN}      (CPU Performance, 智能 Haveged)"
    echo -e " 3. ${GREEN}进程与内存${PLAIN}      (Systemd 优化, ZRAM, Btrfs Swap)"
    echo -e " 4. ${GREEN}安全加固${PLAIN}        (隐藏内核地址, dmesg 限制)"
    echo -e " 5. ${GREEN}接入与 DNS${PLAIN}      (SSH 安全重启, DoH/UDP 双模)"
    echo -e " 6. ${GREEN}维护与清理${PLAIN}      (常用工具, 时区, 缓存清理)"
    echo -e " 7. ${YELLOW}手动管理工具${PLAIN}    (卸载内核 / 安装其他 BBR)"
    echo -e "${BLUE}----------------------------------------------------------------${PLAIN}"
    echo -e " 9. ${RED}彻底抹杀日志${PLAIN}    (暴力模式: 极速 IO)"
    echo -e "${BLUE}----------------------------------------------------------------${PLAIN}"
    echo -e " 0. ${GREEN}一键全套执行${PLAIN}    (执行 1-6，默认保留安全日志)"
    echo -e " 8. ${RED}卸载/还原${PLAIN}       (智能识别，支持一键恢复日志)"
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
            echo -e "\n${GREEN}SysPro 标准优化已完成！${PLAIN}"
            echo -e "${YELLOW}提示: 如需极致网速/IO体验，请手动执行选项 [9] 彻底抹杀日志。${PLAIN}"
            ;;
        q) exit 0 ;;
        *) log_err "无效输入，请重新选择。" ;;
    esac
}

while true; do show_menu; echo -n "按回车键继续..."; read; done
