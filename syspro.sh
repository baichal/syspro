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
#   模块 1: 磁盘 I/O 深度调优 (Disk I/O)
# ==============================================================================
optimize_disk_io() {
    log_info "正在优化磁盘 I/O 策略与存储健康..."
    
    # --- 1.1 挂载参数优化 (noatime) ---
    # 减少文件访问时间写入，降低 I/O 延迟
    [ ! -f /etc/fstab.syspro.bak ] && cp /etc/fstab /etc/fstab.syspro.bak
    
    if grep -q " / " /etc/fstab && grep -E " / .*noatime" /etc/fstab >/dev/null 2>&1; then
        log_info "根分区已配置 noatime，跳过修改。"
    else
        log_info "尝试修改 /etc/fstab 添加 noatime..."
        # 精确匹配根分区并添加参数
        awk '$2 == "/" && ($3 == "ext4" || $3 == "xfs" || $3 == "btrfs") { $4 = $4",noatime,nodiratime" } 1' /etc/fstab > /etc/fstab.tmp
        
        if cmp -s /etc/fstab /etc/fstab.tmp; then
            rm -f /etc/fstab.tmp
            log_warn "未检测到标准根分区格式，跳过 fstab 修改。"
        else
            mv /etc/fstab.tmp /etc/fstab
            # 立即测试挂载，失败则回滚
            if mount -o remount / 2>/dev/null; then
                log_success "根分区挂载参数已更新 (noatime)。"
            else
                log_err "挂载测试失败！自动回滚 fstab..."
                cp /etc/fstab.syspro.bak /etc/fstab
            fi
        fi
    fi

    # --- 1.2 I/O 调度器优化 (Udev 规则) ---
    # 针对 NVMe, SSD, HDD, SD卡(MMC) 设置不同的调度算法
    if command -v udevadm >/dev/null 2>&1; then
        cat > /etc/udev/rules.d/60-io-scheduler.rules << EOF
ACTION=="add|change", KERNEL=="nvme[0-9]*n[0-9]*", ATTR{queue/scheduler}="none"
ACTION=="add|change", KERNEL=="sd[a-z]*|vd[a-z]*", ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="mq-deadline"
ACTION=="add|change", KERNEL=="sd[a-z]*", ATTR{queue/rotational}=="1", ATTR{queue/scheduler}="bfq"
ACTION=="add|change", KERNEL=="mmcblk[0-9]*", ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="mq-deadline"
EOF
        udevadm control --reload && udevadm trigger
        log_success "I/O 调度器规则已更新 (含 MMC/SD 卡优化)。"
    else
        log_warn "未找到 udevadm，跳过调度器优化。"
    fi

    # --- 1.3 [新增] 存储健康维护 (Fstrim) ---
    # 只有存在 fstrim 命令且由 systemd 管理时才启用
    if command -v fstrim >/dev/null 2>&1; then
        log_info "正在配置 Flash 存储 TRIM 自动清理..."
        # 优先使用 Systemd Timer
        if [ -d /usr/lib/systemd/system ] || [ -d /etc/systemd/system ]; then
            # 某些精简系统可能没有 fstrim.timer 文件，我们需要先确认
            if systemctl list-unit-files --all | grep -q "fstrim.timer"; then
                systemctl enable fstrim.timer --now >/dev/null 2>&1
                log_success "fstrim.timer 已启用 (Systemd 托管)。"
            else
                # 如果没有 timer 文件，创建 cron 任务作为保底
                if [ ! -f /etc/cron.weekly/fstrim ]; then
                    echo -e "#!/bin/sh\nfstrim -av" > /etc/cron.weekly/fstrim
                    chmod +x /etc/cron.weekly/fstrim
                    log_success "已创建 fstrim 周常任务 (/etc/cron.weekly)。"
                fi
            fi
        fi
    fi
}

# ==============================================================================
#   模块 2: 算力与熵池 (Compute & Entropy) - [完整修复版]
# ==============================================================================
optimize_compute() {
    log_info "正在优化 CPU 调度与随机数熵池..."

    # --- 2.1 智能熵池补充 (Haveged) ---
    # 获取内核主版本和次版本
    KERNEL_MAJOR=$(uname -r | cut -d. -f1)
    KERNEL_MINOR=$(uname -r | cut -d. -f2)
    
    # 逻辑说明: 
    # Linux 5.6+ 内核重构了 /dev/random，原生支持高性能熵生成 (LRNG)，不再需要 haveged 守护进程。
    # 只有在旧内核上才需要安装 haveged 防止熵耗尽导致的加密操作卡顿。
    if [ "$KERNEL_MAJOR" -gt 5 ] || { [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 6 ]; }; then
        log_success "当前内核 ($KERNEL_MAJOR.$KERNEL_MINOR) 支持 LRNG 高效随机数，跳过 Haveged 安装。"
    else
        log_info "检测到旧版内核，正在安装 Haveged 补充熵池..."
        # 确保包管理器已更新
        smart_pkg_update
        
        if [[ "${RELEASE}" == "centos" ]]; then
            yum install -y epel-release haveged
            systemctl enable haveged --now
        else
            apt-get install -y haveged
            systemctl enable haveged --now
        fi
    fi

    # --- 2.2 CPU 模式锁定 (Performance) ---
    # 目标: 禁止 CPU 降频，减少唤醒延迟，提升系统响应速度 (这对 IO 密集型应用很有用)
    
    # A. 虚拟化环境检测 (VM/Container)
    # 某些容器环境 (LXC/Docker) 无法修改宿主机 CPU 频率，强行修改会报错。
    # KVM 虚拟机通常允许修改，或者至少不会报错，所以 KVM 视为可优化环境。
    IS_VIRTUAL="false"
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        VIRT_TECH=$(systemd-detect-virt)
        # 排除 none (物理机), kvm, oracle (Oracle Cloud 机器)
        if [[ "$VIRT_TECH" != "none" && "$VIRT_TECH" != "kvm" && "$VIRT_TECH" != "oracle" ]]; then
            IS_VIRTUAL="true"
            log_info "检测到受限虚拟化环境 ($VIRT_TECH)，跳过 CPU 频率锁定。"
        fi
    fi

    # B. 执行锁定逻辑 (仅非受限环境)
    if [[ "$IS_VIRTUAL" == "false" ]]; then
        log_info "物理机/KVM 环境检测，准备锁定 CPU 为 Performance 模式..."
        
        # 1. 尝试安装必要的调频工具
        # 优先使用 cpupower (C语言编写，效率高)，而不是用 Shell 循环遍历 sysfs
        if ! command -v cpupower >/dev/null 2>&1; then
            # [关键修复]
            # 如果上面的 Haveged 安装被跳过，smart_pkg_update 可能从未运行过。
            # 这里强制调用一次，确保安装 cpupower 时不会因为缓存过期而 404 报错。
            smart_pkg_update 
            
            if [[ "${RELEASE}" == "centos" ]]; then
                yum install -y kernel-tools >/dev/null 2>&1
            else
                # Debian/Ubuntu ARM 往往需要 cpufrequtils 或 linux-cpupower
                apt-get install -y linux-cpupower cpufrequtils >/dev/null 2>&1
            fi
        fi
        
        # 2. 尝试方法 A: 使用 cpupower 标准工具 (推荐)
        if command -v cpupower >/dev/null 2>&1; then
            if cpupower frequency-set -g performance >/dev/null 2>&1; then
                log_success "CPU 频率调节器已通过 cpupower 锁定为最高性能。"
                return
            fi
        fi

        # 3. 尝试方法 B: 直接修改 Sysfs (回退方案)
        # 当工具安装失败或不可用时，使用 Shell 遍历核心
        log_info "cpupower 调用未成功，尝试直接修改内核 Sysfs 接口..."
        
        local success_count=0
        # 检查路径是否存在
        if [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
            # 遍历所有核心的 governor 文件
            for cpu_gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
                # 检查是否可写
                if [ -w "$cpu_gov" ]; then
                    echo "performance" > "$cpu_gov" 2>/dev/null && ((success_count++))
                fi
            done
        fi
        
        if [ "$success_count" -gt 0 ]; then
            log_success "已通过 Sysfs 成功锁定 $success_count 个核心。"
        else
            log_warn "未检测到可写的 CPU 频率接口 (可能是树莓派固件锁定或被 BIOS 接管)，跳过。"
        fi
    fi
}

# ==============================================================================
#   模块 3: 系统进程与内存 (Systemd & Swap) - [完整优化版]
# ==============================================================================
optimize_systemd() {
    log_info "优化 Systemd 全局配置与进程保护..."
    
    # --- 3.1 Systemd 超时优化 ---
    # 减少关机/重启时的等待时间
    [ ! -f /etc/systemd/system.conf.syspro.bak ] && cp /etc/systemd/system.conf /etc/systemd/system.conf.syspro.bak
    # 合并 sed 操作，减少 I/O
    sed -i -e 's/^#\?DefaultTimeoutStopSec=.*/DefaultTimeoutStopSec=10s/' /etc/systemd/system.conf
    systemctl daemon-reload
    
    # --- 3.2 禁用 Core Dump (防止程序崩溃产生大量垃圾文件) ---
    echo "* hard core 0" > /etc/security/limits.d/99-disable-core.conf
    
    # --- 3.3 OOM 关键进程豁免 (Systemd Native Drop-in 模式) ---
    # 相比旧版 Crontab 脚本，此方法更稳定，服务重启后配置自动生效
    log_info "正在部署 OOM Killer 豁免策略 (Systemd Drop-in)..."
    
    # 定义应用保护的内部函数
    apply_oom_protect() {
        local service_name=$1
        local protect_val=$2  # -1000 (禁止被杀) 到 0 (默认)
        local override_dir="/etc/systemd/system/${service_name}.service.d"
        
        # 检查服务是否存在 (兼容不同发行版)
        if systemctl list-unit-files "${service_name}.service" >/dev/null 2>&1; then
            mkdir -p "$override_dir"
            # 写入覆盖配置
            cat > "${override_dir}/99-syspro-oom.conf" <<EOF
[Service]
OOMScoreAdjust=${protect_val}
EOF
            log_info "  - 已添加保护策略: ${service_name}.service (Score: ${protect_val})"
        fi
    }

    # 1. 保护 SSH 服务 (Debian系通常叫 ssh, RHEL系通常叫 sshd，两个都做)
    apply_oom_protect "ssh" "-1000"
    apply_oom_protect "sshd" "-1000"
    
    # 2. 保护日志服务 (防止日志进程被杀导致无法排查故障)
    apply_oom_protect "systemd-journald" "-500"
    
    # 3. 清理旧版本脚本 (如果有)
    if [ -f /usr/local/bin/oom-protect.sh ]; then
        rm -f /usr/local/bin/oom-protect.sh
        # 从 crontab 中移除
        crontab -l 2>/dev/null | grep -v "oom-protect" | crontab -
        log_info "  - 已清理旧版 Crontab 保护脚本。"
    fi

    # 重载配置使保护立即生效
    systemctl daemon-reload
    log_success "关键进程保护配置已刷新。"
}

optimize_memory() {
    log_info "正在优化内存结构 (ZRAM & Swap)..."

    # --- 3.4 ZRAM 内存压缩 (事件驱动优化版) ---
    HAS_ZRAM=0
    
    # 检查模块是否存在
    if modinfo zram >/dev/null 2>&1; then
        # 尝试加载模块
        if modprobe zram num_devices=1; then
            
            # [优化] 使用 udevadm settle 等待设备节点 /dev/zram0 创建
            # 这比 sleep 1 更快且更可靠
            if command -v udevadm >/dev/null 2>&1; then
                udevadm settle --timeout=5
            else
                sleep 0.5 # 回退方案
            fi

            # 检查是否已经启用，避免重复配置
            if ! grep -q "zram" /proc/swaps; then
                log_info "内核支持 ZRAM，正在配置内存压缩..."
                
                # 动态计算 ZRAM 大小
                MEM_TOTAL_MB=$(free -m | awk '/Mem:/ {print $2}')
                if [ "$MEM_TOTAL_MB" -le 2048 ]; then 
                    ZRAM_SIZE=$(($MEM_TOTAL_MB / 2)) # 小内存给 50%
                else 
                    ZRAM_SIZE=2048 # 大内存上限 2GB
                fi
                
                # 智能选择压缩算法 (优先 zstd > lzo)
                ALGO="lzo"
                if [ -f /sys/block/zram0/comp_algorithm ]; then
                    local avail_algos=$(cat /sys/block/zram0/comp_algorithm)
                    if [[ "$avail_algos" == *"zstd"* ]]; then
                        ALGO="zstd"
                    fi
                fi

                # [关键修复] 生成启动脚本，修正设备路径
                cat > /usr/local/bin/zram-start.sh <<EOF
#!/bin/bash
modprobe zram num_devices=1
# 等待设备创建
sleep 0.5
# 防止设备忙，先尝试重置
[ -f /sys/block/zram0/reset ] && echo 1 > /sys/block/zram0/reset 2>/dev/null
# 设置算法和大小
echo "$ALGO" > /sys/block/zram0/comp_algorithm 2>/dev/null
echo "${ZRAM_SIZE}M" > /sys/block/zram0/disksize
# [修复] 使用 /dev/zram0 而不是 /sys/block/zram0
mkswap /dev/zram0 >/dev/null 2>&1
# 优先级设为 100 (高于磁盘 Swap)
swapon -p 100 /dev/zram0
EOF
                chmod +x /usr/local/bin/zram-start.sh
                
                # Systemd Service 封装
                cat > /etc/systemd/system/zram.service <<EOF
[Unit]
Description=SysPro ZRAM Swap
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
                
                # [优化] 状态检查轮询 (Polling) 代替 sleep
                # 最多等待 2秒 (10 * 0.2s)
                for i in {1..10}; do
                    if grep -q "zram" /proc/swaps; then
                        log_success "ZRAM 已启用 (大小: ${ZRAM_SIZE}MB, 算法: ${ALGO})。"
                        HAS_ZRAM=1
                        break
                    fi
                    sleep 0.2
                done
                
                if [ $HAS_ZRAM -eq 0 ]; then
                    log_err "ZRAM 启动超时，可能受限于 VPS 虚拟化架构。"
                fi
            else
                log_info "ZRAM 已经处于启用状态。"
                HAS_ZRAM=1
            fi
        else
            log_warn "加载 zram 模块失败，跳过。"
        fi
    else
        log_warn "当前内核缺少 zram 模块，跳过。"
    fi
    
    # --- 3.5 磁盘 Swap 与 Swappiness 优化 ---
    
    # [新增] 检测 nftx2 是否已配置内存参数（避免冲突）
    NFTX2_ACTIVE=0
    if [ -f /etc/sysctl.d/99-nftx2.conf ] && grep -q "tcp_mem" /etc/sysctl.d/99-nftx2.conf 2>/dev/null; then
        NFTX2_ACTIVE=1
        log_warn "检测到 nftx2 网络优化已部署，将协同配置内存参数。"
    fi
    
    # [核心优化] 根据是否使用了 ZRAM 调整 Swappiness
    # vm.swappiness 定义了使用 Swap 的积极程度 (0-100)
    if [ "$HAS_ZRAM" -eq 1 ]; then
        # 如果有 ZRAM (内存压缩)，我们希望积极使用它来节省物理内存
        sysctl -w vm.swappiness=80 >/dev/null 2>&1
        echo "vm.swappiness = 80" > /etc/sysctl.d/99-syspro-swap.conf
        log_info "  - 已优化 Swappiness 为 80 (适配 ZRAM 内存压缩)。"
    else
        # 如果只有磁盘 Swap，尽量少用，防止 I/O 卡顿
        sysctl -w vm.swappiness=10 >/dev/null 2>&1
        echo "vm.swappiness = 10" > /etc/sysctl.d/99-syspro-swap.conf
        log_info "  - 已优化 Swappiness 为 10 (适配磁盘 Swap)。"
    fi
    
    # [新增] 如果 nftx2 活跃，添加兼容性注释
    if [ "$NFTX2_ACTIVE" -eq 1 ]; then
        cat >> /etc/sysctl.d/99-syspro-swap.conf <<EOF

# === nftx2 兼容性说明 ===
# 本配置与 nftx2 网络优化共存
# nftx2 管理: TCP缓冲区、网络栈参数
# syspro 管理: Swap策略、ZRAM、I/O调度
EOF
    fi
    
    # --- 3.6 磁盘 Swap 文件创建（如果需要）---
    # 检查当前 Swap 总量
    CURRENT_SWAP_MB=$(free -m | awk '/Swap:/ {print $2}')
    
    # 如果已有足够的 Swap（ZRAM或磁盘），跳过创建
    if [ "$CURRENT_SWAP_MB" -ge 1024 ]; then
        log_info "系统已有 ${CURRENT_SWAP_MB}MB Swap 空间，跳过磁盘 Swap 创建。"
        return
    fi
    
    # 创建 /swapfile
    log_warn "系统 Swap 空间不足，正在创建磁盘 Swap (/swapfile)..."
    
    # 动态计算 Swap 文件大小
    if [ "$HAS_ZRAM" -eq 1 ]; then 
        SIZE=1024  # 有 ZRAM 时只需小磁盘 Swap 作为保底
    else
        MEM_TOTAL=$(free -m | awk '/Mem:/ {print $2}')
        if [ "$MEM_TOTAL" -le 2048 ]; then 
            SIZE=2048  # 小内存机器给 2GB
        else 
            SIZE=1024  # 大内存机器给 1GB 即可
        fi
    fi
    
    # 检查磁盘空间是否充足
    DISK_AVAIL=$(df -m / | awk 'NR==2 {print $4}')
    if [ "$DISK_AVAIL" -lt "$((SIZE + 500))" ]; then
        log_err "磁盘空间不足（剩余 ${DISK_AVAIL}MB），无法创建 ${SIZE}MB Swap 文件。"
        return
    fi

    # 删除旧文件并创建新文件
    rm -f /swapfile && touch /swapfile
    
    # [新增] Btrfs 文件系统特殊处理（防止 CoW 导致性能问题）
    FS_TYPE=$(df -T /swapfile | tail -1 | awk '{print $2}')
    if [ "$FS_TYPE" == "btrfs" ]; then
        if command -v chattr >/dev/null; then 
            chattr +C /swapfile  # 禁用 Copy-on-Write
            log_info "检测到 Btrfs 文件系统，已禁用 Swap 文件的 CoW。"
        fi
    fi
    
    # 快速分配空间（fallocate 比 dd 快100倍）
    if ! fallocate -l ${SIZE}M /swapfile 2>/dev/null; then
        # 回退到 dd（某些文件系统不支持 fallocate）
        dd if=/dev/zero of=/swapfile bs=1M count=$SIZE status=none
    fi
    
    # 设置安全权限并格式化
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1
    swapon /swapfile
    
    # 写入 /etc/fstab 实现开机自动挂载
    if ! grep -q "/swapfile" /etc/fstab; then 
        echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
    fi
    
    log_success "磁盘 Swap (${SIZE}MB) 已创建并启用。"
    
    # 显示最终的 Swap 配置
    log_info "当前 Swap 配置汇总:"
    swapon --show 2>/dev/null | while read line; do
        log_info "  $line"
    done
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
#   模块 8: 卸载 SysPro (完整清理版 v2 - 增强ZRAM处理)
# ==============================================================================
uninstall_syspro() {
    echo -e "${RED}警告: 正在卸载 SysPro 及所有扩展组件...${PLAIN}"
    
    # --- 1. 解锁并还原 DNS 配置 ---
    # 必须先移除不可变属性 (chattr -i)，否则无法修改或删除
    chattr -i /etc/resolv.conf >/dev/null 2>&1
    rm -f /etc/resolv.conf
    # 恢复为通用的公共 DNS
    echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf
    log_info "DNS 已重置为默认值。"

    # --- 2. 清理 DoH 服务 (Cloudflared) ---
    if systemctl is-active syspro-doh >/dev/null 2>&1; then
        systemctl stop syspro-doh
        systemctl disable syspro-doh
    fi
    rm -f /etc/systemd/system/syspro-doh.service
    rm -f /usr/local/bin/cloudflared
    log_info "DoH 服务已清理。"
    
    # --- 3. 清理 ZRAM 组件 (增强版) ---
    log_info "正在清理 ZRAM 内存压缩组件..."
    
    # 3.1 停止并禁用服务
    if systemctl is-active zram >/dev/null 2>&1; then
        systemctl stop zram
        systemctl disable zram
    fi
    
    # 3.2 卸载 ZRAM 设备（关键步骤）
    if grep -q "zram" /proc/swaps; then
        log_info "正在卸载 ZRAM swap 设备..."
        swapoff /dev/zram0 >/dev/null 2>&1
        # 等待卸载完成
        sleep 1
    fi
    
    # 3.3 重置 ZRAM 设备
    if [ -f /sys/block/zram0/reset ]; then
        echo 1 > /sys/block/zram0/reset 2>/dev/null
    fi
    
    # 3.4 卸载内核模块
    if lsmod | grep -q zram; then
        modprobe -r zram >/dev/null 2>&1
        log_info "ZRAM 内核模块已卸载。"
    fi
    
    # 3.5 删除配置文件
    rm -f /etc/systemd/system/zram.service
    rm -f /usr/local/bin/zram-start.sh
    
    # 3.6 清理模块自启配置
    if [ -f /etc/modules-load.d/syspro.conf ]; then
        sed -i '/zram/d' /etc/modules-load.d/syspro.conf
    fi
    
    log_success "ZRAM 组件已完全清理。"

    # --- 4. 清理 OOM 进程保护 (重点修正) ---
    log_info "正在清理进程保护策略..."
    
    # 4.1 清理旧版 Crontab/Shell 模式 (兼容旧版脚本)
    rm -f /usr/local/bin/oom-protect.sh
    crontab -l 2>/dev/null | grep -v "oom-protect" | crontab - 2>/dev/null
    
    # 4.2 清理新版 Systemd Drop-in 模式
    # 删除特定的配置文件
    rm -f /etc/systemd/system/ssh.service.d/99-syspro-oom.conf
    rm -f /etc/systemd/system/sshd.service.d/99-syspro-oom.conf
    rm -f /etc/systemd/system/systemd-journald.service.d/99-syspro-oom.conf
    
    # 尝试删除目录 (只有当目录为空时才会删除，rmdir 很安全)
    rmdir /etc/systemd/system/ssh.service.d 2>/dev/null
    rmdir /etc/systemd/system/sshd.service.d 2>/dev/null
    rmdir /etc/systemd/system/systemd-journald.service.d 2>/dev/null
    
    log_success "OOM 保护策略已清理。"
    
    # --- 5. 清理 Swap 与 Fstab ---
    log_info "正在清理 Swap 配置..."
    
    # 5.1 移除 Swap 倾向性设置
    rm -f /etc/sysctl.d/99-syspro-swap.conf

    # 5.2 处理 /swapfile
    if [ -f "/swapfile" ]; then
        # 先卸载，不管是否成功都继续
        swapoff /swapfile >/dev/null 2>&1
        sleep 0.5  # 等待卸载完成
        rm -f /swapfile
        log_success "已删除 /swapfile 文件。"
    fi

    # 5.3 修复 /etc/fstab
    # 方案 A: 如果有脚本创建的备份，优先还原
    if [ -f /etc/fstab.syspro.bak ]; then
        cp /etc/fstab.syspro.bak /etc/fstab
        log_info "已还原 fstab 备份文件。"
    fi
    
    # 方案 B: 二次清洗 (防止备份文件里本身就含有 swapfile 的情况)
    # 删除所有包含 /swapfile 的行
    sed -i '/^\/swapfile/d' /etc/fstab
    
    # 5.4 刷新挂载点 (重新挂载根目录以去除 noatime 等参数)
    mount -o remount / 2>/dev/null
    log_success "Swap 配置已清理。"

    # --- 6. 清理其他系统配置 ---
    log_info "正在清理系统配置文件..."
    
    # Shell 增强
    rm -f /etc/profile.d/syspro_shell.sh
    
    # Fstrim 任务
    systemctl disable fstrim.timer >/dev/null 2>&1
    rm -f /etc/cron.weekly/fstrim
    
    # Udev 规则
    rm -f /etc/udev/rules.d/60-io-scheduler.rules
    if command -v udevadm >/dev/null 2>&1; then
        udevadm control --reload
        udevadm trigger
    fi
    
    # Sysctl 安全参数
    rm -f /etc/sysctl.d/98-syspro-security.conf
    
    # Limits 配置
    rm -f /etc/security/limits.d/99-disable-core.conf
    
    log_success "系统配置文件已清理。"
    
    # --- 7. 还原 SSH 配置 ---
    log_info "正在还原 SSH 配置..."
    if [ -f /etc/ssh/sshd_config.syspro.bak ]; then
        cp /etc/ssh/sshd_config.syspro.bak /etc/ssh/sshd_config
        # 测试配置有效性，有效则重启服务
        if sshd -t 2>/dev/null; then 
            if [[ "${RELEASE}" == "centos" ]]; then 
                systemctl restart sshd
            else 
                systemctl restart ssh
            fi
            log_success "SSH 配置已还原。"
        else
            log_err "SSH 配置验证失败，保持当前配置。"
        fi
    fi
    
    # --- 8. 还原 Systemd 全局配置 ---
    log_info "正在还原 Systemd 全局配置..."
    if [ -f /etc/systemd/system.conf.syspro.bak ]; then
        cp /etc/systemd/system.conf.syspro.bak /etc/systemd/system.conf
        log_success "Systemd 全局配置已还原。"
    fi

    # --- 9. 还原 CPU 频率调节器（如果可用）---
    log_info "正在尝试还原 CPU 频率策略..."
    # 尝试恢复为节能模式（大多数系统的默认值）
    if command -v cpupower >/dev/null 2>&1; then
        cpupower frequency-set -g powersave >/dev/null 2>&1 || \
        cpupower frequency-set -g ondemand >/dev/null 2>&1 || \
        log_warn "无法还原 CPU 频率策略（可能不支持或为虚拟机）。"
    else
        # 回退方案：直接写 sysfs
        for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            if [ -w "$gov" ]; then
                echo "ondemand" > "$gov" 2>/dev/null || \
                echo "powersave" > "$gov" 2>/dev/null || true
            fi
        done
    fi

    # --- 10. 应用所有变更 ---
    log_info "正在应用系统变更..."
    
    # 刷新 Systemd
    systemctl daemon-reload
    
    # 刷新 Sysctl (重新加载系统默认配置)
    sysctl --system >/dev/null 2>&1
    
    # 刷新 Udev 规则
    if command -v udevadm >/dev/null 2>&1; then
        udevadm control --reload 
        udevadm trigger
    fi

    # --- 11. 最终验证与报告 ---
    echo ""
    echo -e "${GREEN}================================================================${PLAIN}"
    echo -e "${GREEN}                  卸载完成汇总报告                              ${PLAIN}"
    echo -e "${GREEN}================================================================${PLAIN}"
    
    # 验证 ZRAM 是否完全清理
    if lsmod | grep -q zram; then
        echo -e "${YELLOW}⚠ ZRAM 模块仍在内存中（需重启完全卸载）${PLAIN}"
    else
        echo -e "${GREEN}✓ ZRAM 模块已完全卸载${PLAIN}"
    fi
    
    # 验证 Swap 状态
    echo -e "\n当前 Swap 状态:"
    if swapon --show 2>/dev/null | grep -qE "zram|swapfile"; then
        echo -e "${YELLOW}⚠ 仍有 SysPro 创建的 Swap 活跃（将在重启后消失）${PLAIN}"
        swapon --show
    else
        echo -e "${GREEN}✓ 所有 SysPro Swap 已卸载${PLAIN}"
    fi
    
    # 检查残留配置
    echo -e "\n残留配置检查:"
    LEFTOVER=0
    
    if [ -f /etc/sysctl.d/99-syspro-swap.conf ]; then
        echo -e "${YELLOW}⚠ /etc/sysctl.d/99-syspro-swap.conf 仍存在${PLAIN}"
        LEFTOVER=1
    fi
    
    if [ -f /etc/systemd/system/zram.service ]; then
        echo -e "${YELLOW}⚠ /etc/systemd/system/zram.service 仍存在${PLAIN}"
        LEFTOVER=1
    fi
    
    if [ $LEFTOVER -eq 0 ]; then
        echo -e "${GREEN}✓ 无残留配置文件${PLAIN}"
    fi
    
    echo -e "${GREEN}================================================================${PLAIN}"
    echo -e "${YELLOW}重要提示:${PLAIN}"
    echo -e " 1. 建议立即重启服务器以确保所有内核参数和模块彻底重置"
    echo -e " 2. 重启命令: ${GREEN}reboot${PLAIN}"
    echo -e " 3. 如需保留 nftx2 网络优化，重启后它将继续生效"
    echo -e "${GREEN}================================================================${PLAIN}"
}

# ==============================================================================
#   主菜单
# ==============================================================================
show_menu() {
    clear
    echo -e "${BLUE}================================================================${PLAIN}"
    echo -e "${GREEN}    SysPro v5.3 - Infrastructure Optimizer (ARM 完整增强版)   ${PLAIN}"
    echo -e "${BLUE}================================================================${PLAIN}"
    echo -e " 1. ${GREEN}深度 I/O 优化${PLAIN}   (Noatime, Udev 智能调度 / MMC支持)"
    echo -e " 2. ${GREEN}算力与熵池${PLAIN}      (CPU Performance, 智能 Haveged)"
    echo -e " 3. ${GREEN}进程与内存${PLAIN}      (Systemd 优化, Btrfs 兼容 Swap)"
    echo -e " 4. ${GREEN}安全加固${PLAIN}        (隐藏内核地址, dmesg 限制)"
    echo -e " 5. ${GREEN}接入与 DNS${PLAIN}      (SSH 安全重启, DoH 支持 ARM)"
    echo -e " 6. ${GREEN}维护与清理${PLAIN}      (常用工具, 交互式时区, 日志限制)"
    echo -e " 7. ${YELLOW}手动管理工具${PLAIN}    (卸载内核 / 安装其他 BBR)"
    echo -e "${BLUE}----------------------------------------------------------------${PLAIN}"
    echo -e " 0. ${GREEN}一键全套执行${PLAIN}    (推荐: 依次执行 1-6)"
    echo -e " 8. ${RED}卸载/还原${PLAIN}       (恢复默认配置)"
    echo -e " 9. ${YELLOW}解锁 DNS 文件${PLAIN}   (移除 chattr +i 锁以便手动修改)"
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
        8) uninstall_syspro ;;
        9) chattr -i /etc/resolv.conf; log_success "DNS 文件已解锁。" ;;
        0)
            optimize_disk_io
            optimize_compute
            optimize_systemd
            optimize_memory
            optimize_security
            optimize_access
            maintenance_tasks
            echo -e "\n${GREEN}SysPro 全套优化已完成！${PLAIN}"
            ;;
        q) exit 0 ;;
        *) log_err "无效输入，请重新选择。" ;;
    esac
}

while true; do show_menu; echo -n "按回车键继续..."; read; done
