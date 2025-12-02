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
#   模块 2: 算力与熵池 (Compute & Entropy)
# ==============================================================================
optimize_compute() {
    log_info "正在优化 CPU 调度与随机数熵池..."

    # --- 2.1 智能熵池补充 (Haveged) ---
    # 改进点: Linux Kernel 5.6+ 重构了 /dev/random，不再需要 haveged
    KERNEL_MAJOR=$(uname -r | cut -d. -f1)
    KERNEL_MINOR=$(uname -r | cut -d. -f2)
    
    # 逻辑: 如果 主版本 > 5 或者 (主版本=5 且 次版本 >= 6)
    if [ "$KERNEL_MAJOR" -gt 5 ] || { [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 6 ]; }; then
        log_success "当前内核 ($KERNEL_MAJOR.$KERNEL_MINOR) 支持 LRNG 高效随机数，跳过 Haveged 安装。"
    else
        log_info "检测到旧版内核，正在安装 Haveged 补充熵池..."
        if [[ "${RELEASE}" == "centos" ]]; then
            yum install -y epel-release haveged
            systemctl enable haveged --now
        else
            apt-get update
            apt-get install -y haveged
            systemctl enable haveged --now
        fi
    fi

    # --- 2.2 CPU 模式锁定 (Performance) [修复版] ---
    # 原理: 禁止 CPU 降频，减少唤醒延迟
    
    # 检测是否为虚拟化环境 (VM/Container)
    IS_VIRTUAL="false"
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        VIRT_TECH=$(systemd-detect-virt)
        if [[ "$VIRT_TECH" != "none" ]]; then
            IS_VIRTUAL="true"
            log_info "检测到虚拟化环境 ($VIRT_TECH)，跳过 CPU 频率锁定。"
        fi
    fi

    # 只有非虚拟化环境才尝试锁定频率
    if [[ "$IS_VIRTUAL" == "false" ]]; then
        log_info "物理机环境检测，尝试锁定 CPU 为 Performance 模式..."
        if [[ "${RELEASE}" == "centos" ]]; then
            yum install -y kernel-tools
        else
            # Debian/Ubuntu ARM 往往需要 cpufrequtils
            apt-get install -y linux-cpupower cpufrequtils 2>/dev/null
        fi
        
        # 遍历所有核心 (增加判断，防止树莓派无权限报错)
        if [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
            for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
                if [ -w "$cpu" ]; then
                    echo "performance" > "$cpu" 2>/dev/null
                fi
            done
            log_success "CPU 频率调节器已锁定为最高性能。"
        else
            log_info "未检测到可写的 CPU 频率接口 (可能是树莓派固件锁定)，跳过。"
        fi
    else
        : 
    fi
}

# ==============================================================================
#   模块 3: 系统进程与内存 (Systemd & Swap)
# ==============================================================================
optimize_systemd() {
    log_info "优化 Systemd 全局配置与进程保护..."
    
    # --- 3.1 Systemd 超时优化 ---
    [ ! -f /etc/systemd/system.conf.syspro.bak ] && cp /etc/systemd/system.conf /etc/systemd/system.conf.syspro.bak
    sed -i 's/^#DefaultTimeoutStopSec=.*/DefaultTimeoutStopSec=10s/' /etc/systemd/system.conf
    sed -i 's/^DefaultTimeoutStopSec=.*/DefaultTimeoutStopSec=10s/' /etc/systemd/system.conf
    systemctl daemon-reload
    
    # --- 3.2 禁用 Core Dump ---
    echo "* hard core 0" > /etc/security/limits.d/99-disable-core.conf
    
    # --- 3.3 [新增] OOM 关键进程豁免 (防失联) ---
    log_info "正在部署 OOM Killer 豁免策略 (SSH/Systemd)..."
    
    # 创建保护脚本
    cat > /usr/local/bin/oom-protect.sh << 'EOF'
#!/bin/bash
# 核心原理: 设置 oom_score_adj 为 -1000 (禁止被杀)
# 1. 保护 Systemd (PID 1)
echo -1000 > /proc/1/oom_score_adj 2>/dev/null
# 2. 保护 Journald (日志)
pgrep -f "systemd-journald" | while read pid; do echo -500 > /proc/$pid/oom_score_adj 2>/dev/null; done
# 3. 保护 SSHD (主进程及当前连接)
if [ -f /var/run/sshd.pid ]; then 
    echo -1000 > /proc/$(cat /var/run/sshd.pid)/oom_score_adj 2>/dev/null
fi
pgrep -f "/usr/sbin/sshd" | while read pid; do 
    echo -1000 > /proc/$pid/oom_score_adj 2>/dev/null
done
EOF
    chmod +x /usr/local/bin/oom-protect.sh
    
    # 注册到 Crontab (@reboot) 以确保持久化
    if ! crontab -l 2>/dev/null | grep -q "oom-protect"; then
        (crontab -l 2>/dev/null; echo "@reboot /usr/local/bin/oom-protect.sh") | crontab -
    fi
    
    # 立即执行一次
    /usr/local/bin/oom-protect.sh
    log_success "关键进程保护已生效 (SSH OOM Score = -1000)。"
}

optimize_memory() {
    log_info "正在优化内存结构 (ZRAM & Swap)..."

    # --- 3.4 [增强版] ZRAM 内存压缩 ---
    HAS_ZRAM=0
    # 增加检测：不仅要模块存在，还要能加载
    if modinfo zram >/dev/null 2>&1 && modprobe zram num_devices=1 >/dev/null 2>&1; then
        if ! grep -q "zram" /proc/swaps; then
            log_info "内核支持 ZRAM，正在配置内存压缩..."
            
            MEM_TOTAL_MB=$(free -m | awk '/Mem:/ {print $2}')
            if [ "$MEM_TOTAL_MB" -le 2048 ]; then 
                ZRAM_SIZE=$(($MEM_TOTAL_MB / 2))
            else 
                ZRAM_SIZE=2048
            fi
            
            # 算法选择
            ALGO="lzo"
            if [ -f /sys/block/zram0/comp_algorithm ]; then
                if grep -q zstd /sys/block/zram0/comp_algorithm; then ALGO="zstd"; fi
            fi

            # [关键修改] 生成更稳健的启动脚本
            cat > /usr/local/bin/zram-start.sh <<EOF
#!/bin/bash
# 1. 加载模块
modprobe zram num_devices=1
sleep 1

# 2. 如果设备已被初始化过，先重置 (防止报错 Device or resource busy)
if [ -f /sys/block/zram0/reset ]; then
    echo 1 > /sys/block/zram0/reset 2>/dev/null
fi

# 3. 设置参数
echo "$ALGO" > /sys/block/zram0/comp_algorithm 2>/dev/null
echo "${ZRAM_SIZE}M" > /sys/block/zram0/disksize

# 4. 启用 Swap
mkswap /sys/block/zram0
swapon -p 100 /sys/block/zram0
EOF
            chmod +x /usr/local/bin/zram-start.sh
            
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
            
            # 验证
            sleep 2 # 给一点时间让 Service 启动
            if grep -q "zram" /proc/swaps; then
                log_success "ZRAM 已启用 (大小: ${ZRAM_SIZE}MB, 算法: ${ALGO})。"
                HAS_ZRAM=1
            else
                log_err "ZRAM 启动失败 (可能是 KVM 限制)，将回退到普通 Swap。"
            fi
        else
            log_info "ZRAM 已经处于启用状态。"
            HAS_ZRAM=1
        fi
    else
        log_warn "当前内核不支持 ZRAM，跳过。"
    fi
    
    # --- 3.5 磁盘 Swap (awk 精确识别版) ---
    SWAP_TOTAL=$(free -m | awk '/Swap:/ {print $2}')
    
    # 使用 awk 读取 /proc/swaps 的第二列 (Type)
    # 忽略表头，查找是否有 partition 或 file
    HAS_PARTITION_SWAP=$(awk 'NR>1 {if ($2 == "partition") print "yes"}' /proc/swaps | head -n1)
    HAS_FILE_SWAP=$(awk 'NR>1 {if ($2 == "file") print "yes"}' /proc/swaps | head -n1)

    # 逻辑判断
    if [ "$SWAP_TOTAL" -ge 100 ]; then
        if [ "$HAS_FILE_SWAP" == "yes" ]; then
            log_info "检测到已存在文件型 Swap (Type: file)，跳过创建。"
        elif [ "$HAS_PARTITION_SWAP" == "yes" ]; then
            log_info "检测到 VPS 预分配的物理 Swap 分区 (Type: partition)，无需创建文件 Swap。"
        else
            # 可能是 ZRAM 撑起来的空间
            log_info "Swap 空间充足 ($SWAP_TOTAL MB)，无需额外操作。"
        fi
        return
    fi
    
    # 创建 /swapfile
    log_warn "系统 Swap 空间不足，正在创建磁盘 Swap (/swapfile)..."
    
    if [ "$HAS_ZRAM" -eq 1 ]; then SIZE=1024; else
        MEM_TOTAL=$(free -m | awk '/Mem:/ {print $2}')
        if [ "$MEM_TOTAL" -le 2048 ]; then SIZE=2048; else SIZE=1024; fi
    fi
    
    DISK_AVAIL=$(df -m / | awk 'NR==2 {print $4}')
    if [ "$DISK_AVAIL" -lt "$((SIZE + 500))" ]; then
        log_err "磁盘空间不足，无法创建文件 Swap。"
        return
    fi

    rm -f /swapfile && touch /swapfile
    FS_TYPE=$(df -T /swapfile | tail -1 | awk '{print $2}')
    if [ "$FS_TYPE" == "btrfs" ]; then
        if command -v chattr >/dev/null; then chattr +C /swapfile; fi
    fi
    
    if ! fallocate -l ${SIZE}M /swapfile 2>/dev/null; then
        dd if=/dev/zero of=/swapfile bs=1M count=$SIZE status=none
    fi
    
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    
    if ! grep -q "/swapfile" /etc/fstab; then 
        echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
    fi
    log_success "磁盘 Swap (${SIZE}MB) 已创建并启用。"
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
#   模块 5: 接入层优化 (SSH & DNS) - ARM 适配修正
# ==============================================================================

# 辅助函数: 安全安装 DoH 客户端
install_cloudflared() {
    log_info "开始部署 Cloudflared DoH 客户端..."
    
    # [ARM 修复] 架构判断与下载链接
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

    # 下载 (增加超时参数)
    log_info "正在从 GitHub 下载二进制文件 ($ARCH)..."
    if [ ! -f /usr/local/bin/cloudflared ]; then
        if curl -L --retry 2 --connect-timeout 10 -m 60 -o /usr/local/bin/cloudflared "$URL"; then
            chmod +x /usr/local/bin/cloudflared
        else
            log_err "下载失败。请检查网络或配置代理。"
            return 1
        fi
    else
        log_info "检测到本地已存在 Cloudflared，跳过下载。"
        chmod +x /usr/local/bin/cloudflared
    fi
    
    # 创建用户
    id -u cloudflared &>/dev/null || useradd -M -s /usr/sbin/nologin cloudflared

    # 构造参数
    UPSTREAM_ARGS=""
    while read -r url; do
        [[ -z "$url" || "$url" =~ ^# ]] && continue
        UPSTREAM_ARGS="$UPSTREAM_ARGS --upstream $url"
    done <<< "$DOH_URL_LIST"

    # 服务文件
    cat > /etc/systemd/system/syspro-doh.service << EOF
[Unit]
Description=SysPro DoH Client (Cloudflared)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cloudflared
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/cloudflared proxy-dns --port 53 --address 127.0.0.1 $UPSTREAM_ARGS
Restart=on-failure
RestartSec=10
StandardOutput=null

[Install]
WantedBy=multi-user.target
EOF

    # [关键修复]：彻底解决与 systemd-resolved 的冲突
    # 不再尝试共存，而是直接停用 resolved，防止 53 端口冲突或解析环路
    if systemctl is-active systemd-resolved >/dev/null 2>&1; then
        log_warn "检测到 systemd-resolved，正在停用以防止端口冲突..."
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved
        # 删除 resolved 产生的软链接，为后续创建静态文件做准备
        rm -f /etc/resolv.conf
    fi

    systemctl daemon-reload
    systemctl enable syspro-doh
    systemctl stop syspro-doh
    systemctl restart syspro-doh
    
    sleep 3
    if systemctl is-active syspro-doh >/dev/null 2>&1; then
        log_success "DoH 服务启动成功。"
        return 0
    else
        log_err "DoH 服务启动失败，正在查看详细报错..."
        journalctl -u syspro-doh --no-pager -n 5
        return 1
    fi
}

optimize_access() {
    log_info "正在优化接入层 (SSH & Environment)..."

    # --- 5.1 SSH 优化 (带回滚) ---
    SSHD_CONF="/etc/ssh/sshd_config"
    [ ! -f ${SSHD_CONF}.syspro.bak ] && cp $SSHD_CONF ${SSHD_CONF}.syspro.bak
    
    # 仅修改必要项
    sed -i 's/^#UseDNS.*/UseDNS no/' $SSHD_CONF
    sed -i 's/^UseDNS.*/UseDNS no/' $SSHD_CONF
    sed -i 's/^#GSSAPIAuthentication.*/GSSAPIAuthentication no/' $SSHD_CONF
    sed -i 's/^GSSAPIAuthentication.*/GSSAPIAuthentication no/' $SSHD_CONF
    
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
        
        echo "options timeout:1 attempts:2 rotate" >> /etc/resolv.conf
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
        apt-get update
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
#   模块 8: 卸载 SysPro 
# ==============================================================================
uninstall_syspro() {
    echo -e "${RED}警告: 正在卸载 SysPro 及所有扩展组件...${PLAIN}"
    
    # 1. 解锁 DNS
    chattr -i /etc/resolv.conf >/dev/null 2>&1
    
    # 2. 清理 ZRAM
    if systemctl is-active zram >/dev/null 2>&1; then
        systemctl stop zram
        systemctl disable zram
    fi
    rm -f /etc/systemd/system/zram.service
    rm -f /usr/local/bin/zram-start.sh
    
    # 3. 清理 OOM / Shell / Cron
    rm -f /usr/local/bin/oom-protect.sh
    crontab -l 2>/dev/null | grep -v "oom-protect" | crontab -

    # 4. 清理 Shell 配置 (新)
    rm -f /etc/profile.d/syspro_shell.sh

    # 5. 清理 Fstrim 任务 (新)
    rm -f /etc/cron.weekly/fstrim
    
    # 4. 清理 DoH
    if systemctl is-active syspro-doh >/dev/null 2>&1; then
        systemctl stop syspro-doh
        systemctl disable syspro-doh
    fi
    rm -f /etc/systemd/system/syspro-doh.service
    rm -f /usr/local/bin/cloudflared
    
    # 5. 还原 DNS
    rm -f /etc/resolv.conf
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf
    
    # 6. [核心修正] 安全清理 Swap
    log_info "正在清理 Swap 配置..."
    
    # A. 无论是否挂载，只要文件存在，即视为脚本创建的目标
    if [ -f "/swapfile" ]; then
        # 尝试卸载 (忽略错误，以防未挂载)
        swapoff /swapfile >/dev/null 2>&1
        # 删除文件
        rm -f /swapfile
        log_success "已移除脚本创建的 /swapfile 文件。"
    else
        log_info "未检测到 /swapfile 文件，跳过删除。"
    fi

    # B. 清理当前 fstab
    if grep -q "/swapfile" /etc/fstab; then
        sed -i '/^\/swapfile/d' /etc/fstab
    fi
    
    # C. 还原 fstab 备份 (如果存在)
    if [ -f /etc/fstab.syspro.bak ]; then
        mv /etc/fstab.syspro.bak /etc/fstab
        # [关键步骤] 即使还原了备份，也要再次确保备份里没有 swapfile
        # 防止用户多次运行脚本，导致备份文件里已经包含了 swapfile
        sed -i '/^\/swapfile/d' /etc/fstab
        systemctl daemon-reload && mount -o remount /
        log_info "已还原 /etc/fstab 备份。"
    fi

    # D. 最终状态检查 (只提示物理分区)
    # 使用 awk 精确检查是否还有 Type 为 partition 的设备
    HAS_PARTITION=$(awk 'NR>1 {if ($2 == "partition") print "yes"}' /proc/swaps | head -n1)
    if [ "$HAS_PARTITION" == "yes" ]; then
        log_info "检测到系统预分配的物理 Swap 分区 (Partition)，已安全保留。"
    fi

    # 7. 还原其他组件
    rm -f /etc/udev/rules.d/60-io-scheduler.rules
    [ -n "$(command -v udevadm)" ] && udevadm control --reload && udevadm trigger
    
    # 还原 SSH
    if [ -f /etc/ssh/sshd_config.syspro.bak ]; then
        mv /etc/ssh/sshd_config.syspro.bak /etc/ssh/sshd_config
        if sshd -t; then 
            if [[ "${RELEASE}" == "centos" ]]; then systemctl restart sshd; else systemctl restart ssh; fi
        fi
    fi
    
    # 还原 Systemd
    [ -f /etc/systemd/system.conf.syspro.bak ] && mv /etc/systemd/system.conf.syspro.bak /etc/systemd/system.conf
    systemctl daemon-reload
    
    # 还原 Sysctl
    rm -f /etc/sysctl.d/98-syspro-security.conf
    rm -f /etc/security/limits.d/99-disable-core.conf
    sysctl --system >/dev/null 2>&1

    echo -e "${GREEN}卸载完成！系统已恢复默认状态。${PLAIN}"
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
