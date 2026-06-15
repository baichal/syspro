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
#   全局常量定义 (Global Constants)
#   说明: 使用常量替换魔法数字，提高代码可读性和可维护性
# ==============================================================================

# 内存相关常量 (MB)
MIN_MEM_FOR_ZRAM=512          # 启用 ZRAM 的最小内存阈值
MAX_MEM_FOR_SWAP=4096         # 不需要创建 Swap 的内存阈值
SWAP_FILE_SIZE=1024           # Swap 文件大小
MIN_SWAP_REQUIRED=128         # 最小 Swap 要求
SWAPPINESS_VALUE=10           # swappiness 值

# 时间相关常量 (秒)
DEFAULT_TIMEOUT_STOP=5        # Systemd 停止超时时间
DNS_TIMEOUT=5                 # DNS 查询超时时间
DNS_ATTEMPTS=3                # DNS 查询重试次数

# 权限相关常量
FILE_PERMISSION=644           # 配置文件权限
DIR_PERMISSION=755            # 目录权限

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
LOG_FILE="/var/log/syspro-exec.log"
log_to_file() {
    mkdir -p /var/log
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$$] $1" >> "$LOG_FILE"
}

log_info()    { local msg="${BLUE}[INFO]${PLAIN} $1"; echo -e "$msg"; log_to_file "[INFO] $1"; }
log_success() { local msg="${GREEN}[OK]${PLAIN} $1"; echo -e "$msg"; log_to_file "[OK] $1"; }
log_warn()    { local msg="${YELLOW}[WARN]${PLAIN} $1"; echo -e "$msg"; log_to_file "[WARN] $1"; }
log_err()     { local msg="${RED}[ERR]${PLAIN} $1"; echo -e "$msg"; log_to_file "[ERR] $1"; }

# 记录脚本启动信息
log_to_file "=========================================="
log_to_file "SysPro v5.3 started"
log_to_file "Hostname: $(hostname)"
log_to_file "User: $USER"
log_to_file "=========================================="

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

# 精确检测系统发行版
detect_release() {
    if [ -f /etc/almalinux-release ]; then
        echo "almalinux"
    elif [ -f /etc/rocky-release ]; then
        echo "rocky"
    elif [ -f /etc/fedora-release ]; then
        echo "fedora"
    elif [ -f /etc/centos-release ]; then
        echo "centos"
    elif [ -f /etc/redhat-release ]; then
        echo "centos"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    elif grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
        echo "ubuntu"
    elif grep -qi "debian" /etc/os-release 2>/dev/null; then
        echo "debian"
    elif cat /etc/issue | grep -Eqi "debian"; then
        echo "debian"
    elif cat /etc/issue | grep -Eqi "ubuntu"; then
        echo "ubuntu"
    else
        echo "unknown"
    fi
}

RELEASE=$(detect_release)

log_info "系统环境: ${GREEN}${RELEASE}${PLAIN} | 架构: ${GREEN}${ARCH}${PLAIN} (${RAW_ARCH})"

# 执行配置验证和系统兼容性检查
validate_dns_config
validate_system_compatibility

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
#   配置验证函数
# ==============================================================================

validate_ipv4() {
    local ip=$1
    if echo "$ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
        local IFS='.'
        read -ra octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

validate_ipv6() {
    local ip=$1
    if echo "$ip" | grep -qE '^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$' || \
       echo "$ip" | grep -qE '^([0-9a-fA-F]{1,4}:){1,7}:$' || \
       echo "$ip" | grep -qE '^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$'; then
        return 0
    fi
    return 1
}

validate_dns_config() {
    log_info "正在验证 DNS 配置..."
    local valid=1
    
    while read -r ip; do
        [[ -z "$ip" || "$ip" =~ ^# ]] && continue
        if ! validate_ipv4 "$ip"; then
            log_err "无效的 IPv4 地址: $ip"
            valid=0
        fi
    done <<< "$DNS_IPV4_LIST"
    
    while read -r ip; do
        [[ -z "$ip" || "$ip" =~ ^# ]] && continue
        if ! validate_ipv6 "$ip"; then
            log_warn "无效的 IPv6 地址: $ip"
        fi
    done <<< "$DNS_IPV6_LIST"
    
    while read -r url; do
        [[ -z "$url" || "$url" =~ ^# ]] && continue
        if ! echo "$url" | grep -qE '^https://'; then
            log_warn "DoH URL 格式建议使用 https: $url"
        fi
    done <<< "$DOH_URL_LIST"
    
    if [ "$valid" -eq 1 ]; then
        log_success "DNS 配置验证通过。"
        return 0
    else
        return 1
    fi
}

validate_system_compatibility() {
    log_info "正在检查系统兼容性..."
    local compatible=1
    
    if [ "$RELEASE" = "unknown" ]; then
        log_err "无法识别当前系统发行版"
        compatible=0
    fi
    
    if [ "$ARCH" = "unknown" ]; then
        log_warn "无法识别当前架构: $RAW_ARCH"
    fi
    
    local os_version=""
    if [[ "$RELEASE" == "debian" ]]; then
        os_version=$(cat /etc/debian_version 2>/dev/null | cut -d'.' -f1)
        if [[ ! "$os_version" =~ ^(10|11|12)$ ]]; then
            log_warn "检测到 Debian $os_version，推荐版本: 10/11/12"
        fi
    elif [[ "$RELEASE" == "ubuntu" ]]; then
        os_version=$(lsb_release -rs 2>/dev/null)
        if [[ ! "$os_version" =~ ^(20\.04|22\.04|24\.04)$ ]]; then
            log_warn "检测到 Ubuntu $os_version，推荐版本: 20.04/22.04/24.04"
        fi
    elif [[ "$RELEASE" == "centos" || "$RELEASE" == "almalinux" || "$RELEASE" == "rocky" ]]; then
        os_version=$(rpm -E %rhel 2>/dev/null)
        if [[ ! "$os_version" =~ ^(7|8|9)$ ]]; then
            log_warn "检测到 RHEL/CentOS $os_version，推荐版本: 7/8/9"
        fi
    fi
    
    if [ "$compatible" -eq 1 ]; then
        log_success "系统兼容性检查通过。"
        return 0
    else
        return 1
    fi
}

# ==============================================================================
#   模块 1: 磁盘 I/O 调优 (Disk I/O)
#   修改说明: 移除 CPU 密集型的 bfq 算法，使用 mq-deadline/none
# ==============================================================================
optimize_disk_io() {
    log_info "正在优化磁盘 I/O 策略 (低延迟/网络优先模式)..."
    local errors=0
    local backups=()
    
    # --- 1.1 挂载参数优化 (noatime) ---
    if [ ! -f /etc/fstab.syspro.bak ]; then
        if cp /etc/fstab /etc/fstab.syspro.bak; then
            backups+=("/etc/fstab.syspro.bak")
        else
            log_err "无法备份 fstab 文件"
            errors=$((errors + 1))
        fi
    fi
    
    if grep -q " / " /etc/fstab && grep -E " / .*noatime" /etc/fstab >/dev/null 2>&1; then
        log_info "根分区已配置 noatime，跳过修改。"
    else
        log_info "尝试修改 /etc/fstab 添加 noatime..."
        if ! awk '$2 == "/" && ($3 == "ext4" || $3 == "xfs" || $3 == "btrfs") { $4 = $4",noatime,nodiratime" } 1' /etc/fstab > /etc/fstab.tmp; then
            log_err "fstab 修改失败"
            errors=$((errors + 1))
        elif cmp -s /etc/fstab /etc/fstab.tmp; then
            rm -f /etc/fstab.tmp
            log_warn "未检测到标准根分区格式，跳过 fstab 修改。"
        else
            if mv /etc/fstab.tmp /etc/fstab; then
                if mount -o remount / 2>/dev/null; then
                    log_success "根分区挂载参数已更新 (noatime)。"
                else
                    log_err "挂载测试失败！自动回滚 fstab..."
                    cp /etc/fstab.syspro.bak /etc/fstab
                    errors=$((errors + 1))
                fi
            else
                log_err "无法替换 fstab 文件"
                rm -f /etc/fstab.tmp
                errors=$((errors + 1))
            fi
        fi
    fi

    # --- 1.2 I/O 调度器优化 (Udev 规则 - 核心修改) ---
    if command -v udevadm >/dev/null 2>&1; then
        if cat > /etc/udev/rules.d/60-io-scheduler.rules << EOF
# 1. NVMe SSD & 虚拟磁盘 (VPS/KVM)
ACTION=="add|change", KERNEL=="nvme[0-9]*n[0-9]*|vd[a-z]*", ATTR{queue/scheduler}="none"

# 2. 物理 SATA SSD / 机械硬盘 (HDD) / SD卡 (树莓派)
ACTION=="add|change", KERNEL=="sd[a-z]*|mmcblk[0-9]*", ATTR{queue/scheduler}="mq-deadline"

# 3. 减少预读 (Read-ahead)
ACTION=="add|change", KERNEL=="vd[a-z]*|sd[a-z]*", ATTR{bdi/read_ahead_kb}="256"
EOF
        then
            chmod 644 /etc/udev/rules.d/60-io-scheduler.rules
            if udevadm control --reload && udevadm trigger; then
                log_success "I/O 调度器规则已更新。"
            else
                log_err "Udev 规则重载失败"
                errors=$((errors + 1))
            fi
        else
            log_err "无法创建 udev 规则文件"
            errors=$((errors + 1))
        fi
    else
        log_warn "未找到 udevadm，跳过调度器优化。"
    fi

    # --- 1.3 存储健康维护 (Fstrim) ---
    if command -v fstrim >/dev/null 2>&1; then
        log_info "检查 Flash 存储 TRIM 自动清理..."
        if [ -d /usr/lib/systemd/system ] || [ -d /etc/systemd/system ]; then
            if systemctl list-unit-files --all | grep -q "fstrim.timer"; then
                if systemctl enable fstrim.timer --now >/dev/null 2>&1; then
                    log_success "fstrim.timer 已启用。"
                else
                    log_warn "无法启用 fstrim.timer"
                fi
            else
                if [ ! -f /etc/cron.weekly/fstrim ]; then
                    if echo -e "#!/bin/sh\nfstrim -av" > /etc/cron.weekly/fstrim && chmod +x /etc/cron.weekly/fstrim; then
                        log_success "已创建 fstrim 周常任务。"
                    else
                        log_err "无法创建 fstrim 任务"
                        errors=$((errors + 1))
                    fi
                fi
            fi
        fi
    fi
    
    if [ "$errors" -gt 0 ]; then
        log_warn "I/O 优化完成，但有 $errors 个错误。"
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
    # [核心修改] 添加 kernel.sched_autogroup_enabled = 0
    # 这确保了无论 SSH 是否连接，进程都获得同等的 CPU 调度权重。
    
    cat > /etc/sysctl.d/97-syspro-latency.conf << EOF
# 禁用调度器自动分组 (解决 SSH 断开后进程降速的核心参数)
kernel.sched_autogroup_enabled = 0

# 调度延迟周期
kernel.sched_latency_ns = 4000000
# 唤醒粒度
kernel.sched_wakeup_granularity_ns = 500000
kernel.sched_min_granularity_ns = 100000
# 迁移成本
kernel.sched_migration_cost_ns = 250000
# 禁用 RT 节流
kernel.sched_rt_runtime_us = 950000
EOF
    sysctl -p /etc/sysctl.d/97-syspro-latency.conf >/dev/null 2>&1
    log_success "内核 CFS 调度器已优化 (Autogroup Disabled / 15ms)。"

    # --- 2.3 CPU 模式锁定与 C-State 禁用 ---
    # [修改] 移除虚拟化检测限制，强制对所有环境尝试锁定频率。
    # 因为很多 KVM VPS 实际上允许客户机调整 governor。
    log_info "正在锁定 CPU 频率为 Performance 模式..."
    
    # 方法 A: 使用 cpupower (如果可用)
    if command -v cpupower >/dev/null 2>&1; then
        cpupower frequency-set -g performance >/dev/null 2>&1
        cpupower idle-set -D 2 >/dev/null 2>&1
    fi
    
    # 方法 B: 直接修改 Sysfs (更可靠，适配所有 Linux 发行版)
    # 强制遍历所有核心，写入 performance
    local success_count=0
    for cpu_gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        if [ -w "$cpu_gov" ]; then
            echo "performance" > "$cpu_gov" 2>/dev/null && ((success_count++))
        fi
    done
    
    if [ "$success_count" -gt 0 ]; then
        log_success "已强制锁定 $success_count 个核心为 Performance 模式。"
    else
        log_warn "无法修改 CPU 频率 (可能受母机限制)，已尝试但无权操作。"
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

    # --- 3.4 防止断开 SSH 后杀后台进程 (logind) ---
    # 作用: 默认情况下，用户退出 SSH 后，systemd 可能会清理属于该用户的进程。
    # 修改此项可确保后台高吞吐任务不会被限速或误杀。
    log_info "优化 Systemd 用户会话保留策略 (KillUserProcesses=no)..."
    
    if [ -f /etc/systemd/logind.conf ]; then
        # 1. 备份原文件
        [ ! -f /etc/systemd/logind.conf.syspro.bak ] && cp /etc/systemd/logind.conf /etc/systemd/logind.conf.syspro.bak
        
        # 2. 修改配置 (取消注释并强制设为 no)
        sed -i 's/^#\?KillUserProcesses.*/KillUserProcesses=no/' /etc/systemd/logind.conf
        
        # 3. 重启 logind 服务使配置生效
        # 注意: 这通常不会断开当前的 SSH 连接，但会应用新策略
        systemctl restart systemd-logind
        log_success "Logind 策略已更新: 后台任务将常驻。"
    else
        log_warn "未找到 /etc/systemd/logind.conf，跳过会话策略优化。"
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
    local errors=0
    
    # --- 1. 获取物理内存大小 (MB) ---
    MEM_TOTAL_MB=$(free -m | awk '/Mem:/ {print $2}')
    if [ -z "$MEM_TOTAL_MB" ] || [ "$MEM_TOTAL_MB" -eq 0 ]; then
        log_err "无法获取物理内存大小"
        return 1
    fi
    HAS_ZRAM=0
    
    # --- 2. ZRAM 策略调整 (关键修复) ---
    if [ "$MEM_TOTAL_MB" -gt "$MIN_MEM_FOR_ZRAM" ]; then
        log_info "物理内存充足 (>${MIN_MEM_FOR_ZRAM}MB)，禁用 ZRAM..."
        if systemctl is-active zram >/dev/null 2>&1; then
            if ! systemctl disable --now zram >/dev/null 2>&1; then
                log_warn "无法禁用 ZRAM 服务"
            fi
        fi
        rm -f /usr/local/bin/zram-start.sh /etc/systemd/system/zram.service
        HAS_ZRAM=0
    else
        log_info "检测到微型内存环境 (<${MIN_MEM_FOR_ZRAM}MB)，启用轻量化 ZRAM..."
        if modprobe zram num_devices=1; then
            if command -v udevadm >/dev/null 2>&1; then udevadm settle --timeout=5; else sleep 0.5; fi
            
            if ! grep -q "zram" /proc/swaps; then
                ZRAM_SIZE=$(($MEM_TOTAL_MB / 5))
                [ "$ZRAM_SIZE" -lt 64 ] && ZRAM_SIZE=64
                ALGO="lz4"
                
                if cat > /usr/local/bin/zram-start.sh <<EOF
#!/bin/bash
modprobe zram num_devices=1
sleep 0.5
[ -f /sys/block/zram0/reset ] && echo 1 > /sys/block/zram0/reset 2>/dev/null
echo "$ALGO" > /sys/block/zram0/comp_algorithm 2>/dev/null
echo "${ZRAM_SIZE}M" > /sys/block/zram0/disksize
mkswap /dev/zram0 >/dev/null 2>&1
swapon -p 100 /dev/zram0
EOF
                then
                    chmod +x /usr/local/bin/zram-start.sh
                    
                    if cat > /etc/systemd/system/zram.service <<EOF
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
                    then
                        systemctl daemon-reload
                        if systemctl enable zram --now >/dev/null 2>&1; then
                            HAS_ZRAM=1
                            log_success "ZRAM 已启用 (大小: ${ZRAM_SIZE}MB, 算法: lz4)。"
                        else
                            log_err "无法启用 ZRAM 服务"
                            errors=$((errors + 1))
                        fi
                    else
                        log_err "无法创建 ZRAM 服务文件"
                        errors=$((errors + 1))
                    fi
                else
                    log_err "无法创建 ZRAM 启动脚本"
                    errors=$((errors + 1))
                fi
            fi
        else
            log_warn "内核不支持 ZRAM 模块，跳过。"
        fi
    fi
    
    # --- 3. Swappiness 优化 ---
    if sysctl -w vm.swappiness="$SWAPPINESS_VALUE" >/dev/null 2>&1; then
        if echo "vm.swappiness = $SWAPPINESS_VALUE" > /etc/sysctl.d/99-syspro-swap.conf; then
            chmod $FILE_PERMISSION /etc/sysctl.d/99-syspro-swap.conf
            log_info "  - Swappiness 已锁定为 $SWAPPINESS_VALUE。"
        else
            log_err "无法保存 swappiness 配置"
            errors=$((errors + 1))
        fi
    else
        log_err "无法设置 swappiness"
        errors=$((errors + 1))
    fi
    
    # --- 4. 保底磁盘 Swap ---
    CURRENT_SWAP_MB=$(free -m | awk '/Swap:/ {print $2}')
    if [ "$CURRENT_SWAP_MB" -ge "$MIN_SWAP_REQUIRED" ] || [ "$MEM_TOTAL_MB" -gt "$MAX_MEM_FOR_SWAP" ]; then
        log_info "Swap 已存在或内存充足，跳过 Swap 创建。"
        return 0
    fi
    
    log_warn "系统无 Swap 且内存较小，正在创建保底 Swap..."
    SIZE=$SWAP_FILE_SIZE
    
    DISK_AVAIL=$(df -m / | awk 'NR==2 {print $4}')
    if [ "$DISK_AVAIL" -lt 2048 ]; then
        log_err "磁盘空间不足，跳过 Swap 创建。"
        return 0
    fi

    rm -f /swapfile && touch /swapfile
    
    FS_TYPE=$(df -T /swapfile | tail -1 | awk '{print $2}')
    if [ "$FS_TYPE" == "btrfs" ] && command -v chattr >/dev/null; then 
        chattr +C /swapfile
    fi
    
    if ! fallocate -l ${SIZE}M /swapfile 2>/dev/null; then
        log_info "fallocate 不可用，使用 dd 创建 Swap..."
        if ! dd if=/dev/zero of=/swapfile bs=1M count=$SIZE status=none; then
            log_err "无法创建 Swap 文件"
            errors=$((errors + 1))
            return 0
        fi
    fi
    
    chmod 600 /swapfile
    if mkswap /swapfile >/dev/null 2>&1; then
        if swapon /swapfile; then
            if ! grep -q "/swapfile" /etc/fstab; then 
                echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
            fi
            log_success "保底磁盘 Swap (1GB) 已创建。"
        else
            log_err "无法启用 Swap"
            rm -f /swapfile
            errors=$((errors + 1))
        fi
    else
        log_err "无法格式化 Swap"
        rm -f /swapfile
        errors=$((errors + 1))
    fi
    
    if [ "$errors" -gt 0 ]; then
        log_warn "内存优化完成，但有 $errors 个错误。"
    fi
}

# ==============================================================================
#   模块 4: 安全加固 (Security)
# ==============================================================================
optimize_security() {
    log_info "应用内核级安全加固..."
    
    if cat > /etc/sysctl.d/98-syspro-security.conf << EOF
# 限制暴露内核指针地址 (防止内核漏洞利用)
kernel.kptr_restrict = 2
# 限制普通用户读取 dmesg 日志
kernel.dmesg_restrict = 1
# 禁用 SysRq 魔术键 (仅保留 Sync)
kernel.sysrq = 16
# 禁止响应 ICMP ping
net.ipv4.icmp_echo_ignore_all = 1
EOF
    then
        chmod 644 /etc/sysctl.d/98-syspro-security.conf
        if sysctl -p /etc/sysctl.d/98-syspro-security.conf >/dev/null 2>&1; then
            log_success "内核安全参数已加载。"
        else
            log_err "无法加载内核安全参数"
        fi
    else
        log_err "无法创建安全配置文件"
    fi
}

# ==============================================================================
#   模块 5: 辅助函数 - Cloudflared 安装与启动
# ==============================================================================

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

    # --- 4. 生成 Systemd 服务 ---
    if cat > /etc/systemd/system/syspro-doh.service << EOF
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
    then
        chmod 644 /etc/systemd/system/syspro-doh.service
    else
        log_err "无法创建 DoH 服务文件"
        return 1
    fi

    # --- 5. 处理端口冲突 ---
    if systemctl is-active systemd-resolved >/dev/null 2>&1 || systemctl is-enabled systemd-resolved >/dev/null 2>&1; then
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved
        systemctl mask systemd-resolved
        rm -f /etc/resolv.conf
    fi

    # --- 6. 启动服务 ---
    systemctl daemon-reload
    systemctl enable syspro-doh >/dev/null 2>&1
    systemctl restart syspro-doh
    
    local started=0
    for ((i=1; i<=10; i++)); do
        if ss -ln | grep -q ":53 "; then started=1; break; fi
        sleep 0.5
    done
    
    if [ $started -eq 1 ]; then
        log_success "DoH 服务启动成功。Docker 容器将自动使用宿主机 DNS。"
        return 0
    else
        log_err "DoH 启动超时。"
        return 1
    fi
}

optimize_ssh() {
    log_info "正在优化 SSH 配置..."
    
    SSHD_CONF="/etc/ssh/sshd_config"
    [ ! -f ${SSHD_CONF}.syspro.bak ] && cp $SSHD_CONF ${SSHD_CONF}.syspro.bak
    
    sed -i \
    -e 's/^#\?UseDNS.*/UseDNS no/' \
    -e 's/^#\?GSSAPIAuthentication.*/GSSAPIAuthentication no/' \
    "$SSHD_CONF"
    
    if sshd -t; then
        if [[ "${RELEASE}" == "centos" ]]; then 
            systemctl restart sshd
        else 
            systemctl restart ssh
        fi
        log_success "SSH 配置优化完成 (已禁用 DNS反查)。"
    else
        log_err "SSH 配置校验失败，已自动回滚。"
        cp ${SSHD_CONF}.syspro.bak $SSHD_CONF
    fi
}

optimize_shell_env() {
    log_info "正在优化 Shell 环境..."
    
    cat > /etc/profile.d/syspro.sh << 'EOF'
# SysPro Shell Enhancements
export HISTTIMEFORMAT="%F %T "
export HISTSIZE=100000
export HISTFILESIZE=100000
export HISTCONTROL=ignoredups:ignorespace

# Color prompt for root
if [ "$USER" = "root" ]; then
    PS1='\[\033[01;31m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
fi
EOF
    chmod $FILE_PERMISSION /etc/profile.d/syspro.sh
    log_success "Shell 环境优化完成。"
}

configure_dns() {
    log_info "正在配置 DNS..."
    
    echo -e "${YELLOW}请选择 DNS 模式:${PLAIN}"
    echo -e " 1. ${GREEN}标准 UDP DNS${PLAIN} (使用脚本开头配置的 IP, 兼容性最佳)"
    echo -e " 2. ${GREEN}DoH 加密 DNS${PLAIN} (防劫持, Docker 自动配置备用 IP)"
    
    while true; do
        read -p "请输入选项 [1-2] (默认1): " DNS_CHOICE
        if [[ "$DNS_CHOICE" =~ ^[1-2]$ || -z "$DNS_CHOICE" ]]; then
            break
        fi
        log_err "无效输入，请输入 1 或 2"
    done
    
    chattr -i /etc/resolv.conf >/dev/null 2>&1
    
    if [ -f /etc/systemd/system/syspro-doh.service ]; then
        systemctl stop syspro-doh
        systemctl disable syspro-doh
    fi

    if [[ "$DNS_CHOICE" == "2" ]]; then
        if install_cloudflared; then
            rm -f /etc/resolv.conf
            echo "# SysPro DoH (Cloudflared)" > /etc/resolv.conf
            echo "nameserver 127.0.0.1" >> /etc/resolv.conf
            echo "options timeout:$DNS_TIMEOUT attempts:$DNS_ATTEMPTS" >> /etc/resolv.conf
            chattr +i /etc/resolv.conf
            log_success "DoH 模式已生效。Docker 容器将自动使用宿主机 DNS。"
        else
            log_warn "DoH 安装失败，自动回退到标准 UDP 模式。"
            DNS_CHOICE="1"
        fi
    fi

    if [[ "$DNS_CHOICE" != "2" ]]; then
        rm -f /etc/resolv.conf
        echo "# SysPro Standard DNS" > /etc/resolv.conf
        
        while read -r ip; do
            [[ -z "$ip" || "$ip" =~ ^# ]] && continue
            echo "nameserver $ip" >> /etc/resolv.conf
        done <<< "$DNS_IPV4_LIST"
        
        if ip -6 addr show scope global | grep -q inet6; then
            while read -r ip; do
                [[ -z "$ip" || "$ip" =~ ^# ]] && continue
                echo "nameserver $ip" >> /etc/resolv.conf
            done <<< "$DNS_IPV6_LIST"
        fi
        
        echo "options timeout:$DNS_TIMEOUT attempts:$DNS_ATTEMPTS rotate" >> /etc/resolv.conf
        chattr +i /etc/resolv.conf
        
        log_success "标准 DNS 模式已生效。"
    fi
}

optimize_access() {
    log_info "正在优化接入层 (SSH & Environment)..."
    
    optimize_ssh
    optimize_shell_env
    configure_dns
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
    
    # 输入验证
    while true; do
        read -p "请输入选项 [0-6] (默认1): " TZ_CHOICE
        if [[ "$TZ_CHOICE" =~ ^[0-6]$ || -z "$TZ_CHOICE" ]]; then
            break
        fi
        log_err "无效输入，请输入 0-6 之间的数字"
    done
    
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
    echo -e "${RED} [警告] 禁用系统日志生成                   ${PLAIN}"
    echo -e "${RED}----------------------------------------------------------------${PLAIN}"
    echo -e "${RED} 此操作将：                          ${PLAIN}"
    echo -e "${RED}   - 停止并禁用系统日志服务            ${PLAIN}"
    echo -e "${RED}   - 清理系统日志文件                  ${PLAIN}"
    echo -e "${RED}   - 降低内核日志级别                  ${PLAIN}"
    echo -e "${YELLOW} 注意: 应用日志（如 nginx, docker）仍可正常书写。${PLAIN}"
    echo -e "${RED}----------------------------------------------------------------${PLAIN}"
    echo -e "${RED} 风险警告: 禁用系统日志可能影响问题排查！${PLAIN}"
    echo -e "${RED}================================================================${PLAIN}"
    
    read -p "确认继续执行吗? [y/N]: " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[yY]$ ]]; then
        log_info "操作已取消。"
        return 0
    fi
    
    # 1. 创建状态标记文件
    touch /etc/syspro_logs_killed
    log_info "已创建状态标记: /etc/syspro_logs_killed"

    # 2. 内核层静音系统日志 (不影响应用日志)
    log_info "正在配置内核层系统日志静音..."
    if [ ! -f /etc/sysctl.d/95-syspro-silence.conf ]; then
        cat > /etc/sysctl.d/95-syspro-silence.conf << EOF
# 降低内核控制台日志级别 (仅输出紧急消息)
kernel.printk = 3 4 1 3

# 禁止普通用户读取 dmesg
kernel.dmesg_restrict = 1

# 禁用系统调用审计 (消除 auditd 的 syscall hook)
audit=0

# 程序崩溃时不生成 core dump 文件
kernel.core_pattern = /dev/null
EOF
        sysctl -p /etc/sysctl.d/95-syspro-silence.conf >/dev/null 2>&1
        log_success "内核层系统日志已静音。"
    fi

    # 3. 禁用系统级日志服务 (阻止系统日志收集，但保留应用日志路径)
    log_info "正在禁用系统日志服务..."
    local SERVICES=("rsyslog" "systemd-journald" "syslog" "rsyslogd" "kdump" "apport" "abrtd" "avahi-daemon" "auditd")
    
    for svc in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$svc" || systemctl is-enabled --quiet "$svc"; then
            systemctl stop "$svc" 2>/dev/null
            systemctl disable "$svc" 2>/dev/null
            systemctl mask "$svc" 2>/dev/null
            log_info "  - 服务已停止并屏蔽: $svc"
        fi
    done

    # 4. 配置 Journald 不存储日志 (仅作为转发通道)
    log_info "配置 systemd-journald 不存储日志..."
    mkdir -p /etc/systemd
    cat > /etc/systemd/journald.conf << EOF
[Journal]
# 不存储日志到磁盘
Storage=none
# 不转发到 syslog
ForwardToSyslog=no
# 不转发到内核环形缓冲区
ForwardToKMsg=no
# 不输出到控制台
ForwardToConsole=no
# 不发送墙报消息
ForwardToWall=no
EOF

    # 5. 清理系统日志文件但保留应用日志目录
    log_info "正在清理系统日志文件..."
    if command -v chattr >/dev/null 2>&1; then
        chattr -R -i /var/log >/dev/null 2>&1
    fi
    
    # 只删除系统日志文件，保留应用日志目录和文件
    # 删除的系统日志文件列表
    local SYS_LOG_FILES=("wtmp" "btmp" "lastlog" "syslog" "messages" "auth.log" "daemon.log" "kern.log" "user.log" "debug" "mail.log" "cron.log")
    for logfile in "${SYS_LOG_FILES[@]}"; do
        rm -f "/var/log/$logfile" "/var/log/${logfile}.1" "/var/log/${logfile}.gz" 2>/dev/null || true
    done
    
    # 创建空的系统日志占位文件 (防止某些服务报错)
    touch /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/auth.log /var/log/syslog /var/log/messages
    chmod 644 /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/auth.log /var/log/syslog /var/log/messages
    
    # 确保 /var/log 目录权限允许应用写入
    chmod 755 /var/log
    
    log_success "系统日志文件已清理，应用日志目录保持可写。"

    # 6. 设置系统服务的日志级别为最低
    log_info "配置系统服务日志级别..."
    cat > /etc/profile.d/syspro-silent.sh << EOF
# 仅设置系统级日志级别，不影响应用日志
export SYSTEMD_LOG_LEVEL=err
EOF
    chmod +x /etc/profile.d/syspro-silent.sh

    # 7. 刷新系统配置
    systemctl daemon-reload
    sysctl --system >/dev/null 2>&1

    log_success "系统日志已禁用。应用日志（如 nginx, docker 容器日志等）仍可正常书写。"
}

# ==============================================================================
#   模块 9: 卸载 SysPro (完整回滚版 - 适配用户配置) [修复完整版]
#   功能: 恢复日志、还原 Docker 网络、清理旧版防火墙规则、重置 DNS
# ==============================================================================
# ==============================================================================
#   卸载辅助函数 - 卸载逻辑组件
# ==============================================================================

# 通用配置恢复函数
# 参数: $1 = 备份文件路径, $2 = 目标文件路径, $3 = 描述
restore_from_backup() {
    local backup_file="$1"
    local target_file="$2"
    local desc="$3"
    
    if [ -f "$backup_file" ]; then
        if cp "$backup_file" "$target_file" 2>/dev/null; then
            rm -f "$backup_file"
            log_info "已恢复${desc}"
            return 0
        else
            log_err "恢复${desc}失败"
            return 1
        fi
    fi
    return 1
}

# 恢复日志系统
restore_logging() {
    if [ ! -f "/etc/syspro_logs_killed" ]; then
        return 0
    fi
    
    log_info "检测到日志系统曾被禁用，正在恢复..."
    
    if command -v chattr >/dev/null 2>&1; then
        chattr -R -i /var/log 2>/dev/null
    fi
    
    chmod -R 755 /var/log
    
    rm -f /etc/sysctl.d/95-syspro-silence.conf
    rm -f /etc/profile.d/syspro-silent.sh
    
    if [ -f /etc/systemd/journald.conf ]; then
        echo -e "[Journal]\nStorage=auto\nSystemMaxUse=200M" > /etc/systemd/journald.conf
    fi
    
    local SERVICES=("rsyslog" "systemd-journald" "syslog" "kdump" "auditd" "avahi-daemon")
    for svc in "${SERVICES[@]}"; do
        systemctl unmask "$svc" 2>/dev/null
        systemctl enable "$svc" 2>/dev/null
        systemctl restart "$svc" 2>/dev/null
    done
    
    rm -f /etc/syspro_logs_killed
    log_success "系统日志功能已恢复"
    return 0
}

# 清理网络组件
cleanup_network() {
    log_info "正在清理网络组件..."
    local errors=0
    
    # 移除 DoH 服务
    if [ -f /etc/systemd/system/syspro-doh.service ]; then
        systemctl disable --now syspro-doh >/dev/null 2>&1
        rm -f /etc/systemd/system/syspro-doh.service
        rm -f /usr/local/bin/cloudflared
        log_info "  - DoH 服务已移除"
    fi
    
    # 清理防火墙规则
    local DEFAULT_IFACE=$(ip route | grep default | head -n1 | awk '{print $5}')
    if [ -n "$DEFAULT_IFACE" ] && command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -i "$DEFAULT_IFACE" -p udp --dport 53 -j DROP 2>/dev/null
        iptables -D INPUT -i "$DEFAULT_IFACE" -p tcp --dport 53 -j DROP 2>/dev/null
        iptables -D INPUT -i docker0 -p udp --dport 53 -j ACCEPT 2>/dev/null
        iptables -D INPUT -i docker0 -p tcp --dport 53 -j ACCEPT 2>/dev/null
        log_info "  - 防火墙规则已清理"
    fi
    
    # 恢复 SSH 配置
    if [ -f /etc/ssh/sshd_config.syspro.bak ]; then
        cp /etc/ssh/sshd_config.syspro.bak /etc/ssh/sshd_config
        rm -f /etc/ssh/sshd_config.syspro.bak
        if systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
            log_info "  - SSH 配置已恢复"
        fi
    fi
    
    # 恢复 Shell 环境
    rm -f /etc/profile.d/syspro.sh
    
    return $errors
}

# 恢复系统 DNS
restore_dns() {
    log_info "正在重置系统 DNS 配置..."
    
    if command -v chattr >/dev/null 2>&1; then
        chattr -i /etc/resolv.conf 2>/dev/null
    fi
    
    gen_default_resolv_conf() {
        echo "# SysPro Reset - 恢复为默认 DNS" > /etc/resolv.conf
        echo "nameserver 8.8.8.8" >> /etc/resolv.conf
        echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    }

    if systemctl list-unit-files | grep -q "systemd-resolved"; then
        systemctl unmask systemd-resolved 2>/dev/null
        systemctl enable --now systemd-resolved 2>/dev/null
        
        if [ -f /run/systemd/resolve/stub-resolv.conf ]; then
            rm -f /etc/resolv.conf
            ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
            log_info "  - /etc/resolv.conf 已恢复为 systemd-resolved 软链接"
        else
            rm -f /etc/resolv.conf
            gen_default_resolv_conf
            log_warn "  - systemd-resolved 存根未找到，已重置为公共 DNS"
        fi
        
        systemctl restart systemd-resolved 2>/dev/null
    else
        rm -f /etc/resolv.conf
        gen_default_resolv_conf
        log_info "  - 已重置为公共 DNS"
    fi
    
    return 0
}

# 清理常规优化配置
cleanup_optimizations() {
    log_info "正在清理优化配置..."
    
    # ZRAM
    if [ -f /etc/systemd/system/zram.service ]; then
        systemctl disable --now zram >/dev/null 2>&1
        rm -f /usr/local/bin/zram-start.sh /etc/systemd/system/zram.service
        log_info "  - ZRAM 已移除"
    fi
    
    # 内核参数文件
    local sysctl_files=(
        "/etc/sysctl.d/97-syspro-latency.conf"
        "/etc/sysctl.d/99-syspro-swap.conf"
        "/etc/sysctl.d/98-syspro-security.conf"
        "/etc/sysctl.d/96-no-audit.conf"
    )
    local sysctl_removed=0
    for f in "${sysctl_files[@]}"; do
        if [ -f "$f" ]; then
            rm -f "$f"
            sysctl_removed=$((sysctl_removed + 1))
        fi
    done
    if [ "$sysctl_removed" -gt 0 ]; then
        log_info "  - 已移除 $sysctl_removed 个内核参数文件"
    fi
    
    # Swap
    if [ -f "/swapfile" ]; then
        swapoff /swapfile 2>/dev/null
        rm -f /swapfile
        log_info "  - Swap 文件已移除"
    fi
    
    # fstab
    restore_from_backup "/etc/fstab.syspro.bak" "/etc/fstab" "fstab 配置" && mount -o remount / 2>/dev/null
    
    # Udev 规则
    if [ -f /etc/udev/rules.d/60-io-scheduler.rules ]; then
        rm -f /etc/udev/rules.d/60-io-scheduler.rules
        if command -v udevadm >/dev/null 2>&1; then
            udevadm control --reload && udevadm trigger 2>/dev/null
        fi
        log_info "  - Udev I/O 调度规则已恢复"
    fi
    
    # Systemd 额外配置
    rm -rf /etc/systemd/system/ssh.service.d /etc/systemd/system/sshd.service.d
    rm -f /etc/security/limits.d/99-disable-core.conf
    restore_from_backup "/etc/systemd/system.conf.syspro.bak" "/etc/systemd/system.conf" "Systemd 主配置"
    
    # Logind
    if [ -f /etc/systemd/logind.conf.syspro.bak ]; then
        mv /etc/systemd/logind.conf.syspro.bak /etc/systemd/logind.conf
        systemctl restart systemd-logind 2>/dev/null
        log_info "  - Logind 配置已恢复"
    fi
    
    return 0
}

# 显示卸载摘要
show_uninstall_summary() {
    echo ""
    echo -e "${GREEN}----------------------------------------------------------------${PLAIN}"
    echo -e "${GREEN} SysPro 卸载完成${PLAIN}"
    echo -e "${GREEN}----------------------------------------------------------------${PLAIN}"
    echo ""
    echo "  已执行的操作："
    echo "    1. 系统日志 - 已恢复 (如曾被禁用)"
    echo "    2. 网络组件 - DoH 服务与防火墙规则已清理"
    echo "    3. DNS 配置 - 已重置为系统默认"
    echo "    4. SSH 配置 - 已从备份恢复 (如存在)"
    echo "    5. I/O 优化 - Udev 规则已恢复"
    echo "    6. 系统优化 - 内核参数、fstab、ZRAM 已清理"
    echo "    7. Systemd 配置 - 主配置与 logind 已恢复"
    echo ""
    echo -e "${YELLOW}建议: 重启服务器以确保所有内核状态完全重置。${PLAIN}"
    echo -e "${GREEN}----------------------------------------------------------------${PLAIN}"
    echo ""
}

uninstall_syspro() {
    echo -e "${RED}================================================================${PLAIN}"
    echo -e "${RED} [警告] 卸载 SysPro 及所有扩展组件         ${PLAIN}"
    echo -e "${RED}----------------------------------------------------------------${PLAIN}"
    echo -e "${RED} 此操作将：                          ${PLAIN}"
    echo -e "${RED}   - 恢复系统日志服务                  ${PLAIN}"
    echo -e "${RED}   - 移除 DoH 客户端                  ${PLAIN}"
    echo -e "${RED}   - 删除 Swap 文件                   ${PLAIN}"
    echo -e "${RED}   - 还原系统配置文件                  ${PLAIN}"
    echo -e "${RED}----------------------------------------------------------------${PLAIN}"
    echo -e "${YELLOW} 注意: 此操作不可逆，请确保已备份重要数据！${PLAIN}"
    echo -e "${RED}================================================================${PLAIN}"
    
    read -p "确认继续卸载吗? [y/N]: " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[yY]$ ]]; then
        log_info "操作已取消。"
        return 0
    fi
    
    echo ""
    
    # --- 1. 恢复日志系统 ---
    restore_logging
    
    # --- 2. 清理网络组件 ---
    cleanup_network
    
    # --- 3. 修复系统 DNS ---
    restore_dns
    
    # --- 4. 清理常规优化配置 ---
    cleanup_optimizations
    
    # --- 5. 刷新系统状态 ---
    systemctl daemon-reload 2>/dev/null
    sysctl --system >/dev/null 2>&1
    
    # --- 6. 显示卸载摘要 ---
    show_uninstall_summary
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
