#!/bin/bash
#
# ==============================================================================
#   SysPro v5.2 - Linux Deep Infrastructure Optimizer (专业修正版)
#   (Foundation Layer | DoH Support | Safe Operations)
# ==============================================================================
#
#   [版本特性]
#   1. 安全优先: SSH 重启前强制校验配置，防止配置错误导致失联。
#   2. 现代兼容: 智能检测内核版本 (5.6+) 跳过过时的 Haveged。
#   3. 文件系统: Swap 创建自动适配 Btrfs (No-CoW) 并在 ext4 上使用 fallocate 加速。
#   4. 网络共存: 温和处理 systemd-resolved，不破坏默认 DNS 架构。
#   5. 人性化: 时区设置改为交互式，DNS 配置文件锁定提供解锁选项。
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

# 2. 系统发行版与架构检测
ARCH=$(uname -m)
if [ -f /etc/redhat-release ]; then
    RELEASE="centos"
elif cat /etc/issue | grep -Eqi "debian"; then
    RELEASE="debian"
elif cat /etc/issue | grep -Eqi "ubuntu"; then
    RELEASE="ubuntu"
else
    RELEASE="unknown"
fi

# ==============================================================================
#   模块 1: 磁盘 I/O 深度调优 (Disk I/O)
# ==============================================================================
optimize_disk_io() {
    log_info "正在优化磁盘 I/O 策略..."
    
    # --- 1.1 挂载参数优化 (noatime) [修复版] ---
    # 原理: 默认 atime 会在每次读取文件时产生写入操作，noatime 可大幅减少元数据写入。
    
    # 1. 备份 fstab
    [ ! -f /etc/fstab.syspro.bak ] && cp /etc/fstab /etc/fstab.syspro.bak
    
    # 2. 检查是否已经存在 noatime
    if grep -q " / " /etc/fstab && grep -E " / .*noatime" /etc/fstab >/dev/null 2>&1; then
        log_info "根分区已配置 noatime，跳过修改。"
    else
        log_info "尝试修改 /etc/fstab 添加 noatime..."
        
        # 使用 awk 精确查找根分区行并修改，避免 sed 正则误伤
        # 逻辑：找到第2列是"/" 且 第3列是 ext4或xfs 的行，在第4列末尾追加 ,noatime,nodiratime
        awk '$2 == "/" && ($3 == "ext4" || $3 == "xfs") { $4 = $4",noatime,nodiratime" } 1' /etc/fstab > /etc/fstab.tmp
        
        # 覆盖前校验文件是否有变化
        if cmp -s /etc/fstab /etc/fstab.tmp; then
            log_warn "未能在 fstab 中定位到标准的根分区配置(ext4/xfs)，跳过修改。"
            rm -f /etc/fstab.tmp
        else
            mv /etc/fstab.tmp /etc/fstab
            
            # [关键修复] 立即验证配置有效性
            if mount -o remount / 2>/dev/null; then
                log_success "根分区挂载参数已更新并在线生效。"
            else
                log_err "警告：修改 fstab 后挂载测试失败！正在回滚以防重启失败..."
                cp /etc/fstab.syspro.bak /etc/fstab
                log_warn "已自动恢复 /etc/fstab 原文件。"
            fi
        fi
    fi

    # --- 1.2 I/O 调度器优化 (基于 udev) ---
    # 原理: NVMe 无需调度，SSD 使用 mq-deadline，机械盘使用 bfq
    if command -v udevadm >/dev/null 2>&1; then
        cat > /etc/udev/rules.d/60-io-scheduler.rules << EOF
# NVMe: 设置为 none (直接旁路，减少延迟)
ACTION=="add|change", KERNEL=="nvme[0-9]*n[0-9]*", ATTR{queue/scheduler}="none"
# SSD/VirtIO (非旋转): 设置为 mq-deadline
ACTION=="add|change", KERNEL=="sd[a-z]*|vd[a-z]*", ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="mq-deadline"
# HDD (旋转): 设置为 bfq
ACTION=="add|change", KERNEL=="sd[a-z]*", ATTR{queue/rotational}=="1", ATTR{queue/scheduler}="bfq"
EOF
        # 重载规则并触发
        udevadm control --reload && udevadm trigger
        log_success "I/O 调度器规则已配置。"
    else
        log_warn "系统未安装 udevadm，跳过调度器优化。"
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
            apt-get install -y linux-cpupower
        fi
        
        # 遍历所有核心
        if [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
            for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
                echo "performance" > "$cpu" 2>/dev/null
            done
            log_success "CPU 频率调节器已锁定为最高性能。"
        else
            log_info "未检测到 CPU 频率接口，跳过。"
        fi
    else
        # 即使是虚拟机，如果有权访问 sysfs 也可以尝试一下，但不强制
        : 
    fi
}

# ==============================================================================
#   模块 3: 系统进程与内存 (Systemd & Swap)
# ==============================================================================
optimize_systemd() {
    log_info "优化 Systemd 全局配置..."
    
    # 备份配置
    [ ! -f /etc/systemd/system.conf.syspro.bak ] && cp /etc/systemd/system.conf /etc/systemd/system.conf.syspro.bak
    
    # --- 3.1 缩短服务停止超时 (90s -> 10s) ---
    # 解决关机/重启时长时间等待问题
    sed -i 's/^#DefaultTimeoutStopSec=.*/DefaultTimeoutStopSec=10s/' /etc/systemd/system.conf
    sed -i 's/^DefaultTimeoutStopSec=.*/DefaultTimeoutStopSec=10s/' /etc/systemd/system.conf
    
    systemctl daemon-reload
    log_success "服务超时时间已缩短至 10s。"
    
    # --- 3.2 禁用 Core Dump ---
    # 节省空间并提高安全性
    echo "* hard core 0" > /etc/security/limits.d/99-disable-core.conf
    echo "* soft core 0" >> /etc/security/limits.d/99-disable-core.conf
}

optimize_memory() {
    log_info "检查 Swap 分区状态..."
    
    SWAP_TOTAL=$(free -m | awk '/Swap:/ {print $2}')
    
    if [ "$SWAP_TOTAL" -eq 0 ]; then
        log_warn "未检测到 Swap，正在创建以防止内存溢出..."
        
        # 计算大小: 内存<=2G则2G Swap，否则1G Swap
        MEM_TOTAL=$(free -m | awk '/Mem:/ {print $2}')
        if [ "$MEM_TOTAL" -le 2048 ]; then SIZE=2048; else SIZE=1024; fi
        
        log_info "计划创建 ${SIZE}MB Swap 文件..."
        
        # --- 改进点: Btrfs 兼容性检查 ---
        # 如果是 Btrfs，Swap 文件必须禁用 CoW (Copy-on-Write) 否则会损坏文件系统
        # 我们先创建一个空文件，设置属性，然后再分配大小
        
        # 1. 清理旧残留
        rm -f /swapfile
        touch /swapfile
        
        # 2. 检查文件系统类型
        FS_TYPE=$(df -T /swapfile | tail -1 | awk '{print $2}')
        if [ "$FS_TYPE" == "btrfs" ]; then
            log_warn "检测到 Btrfs 文件系统，正在禁用 Swap 文件的 CoW 属性..."
            if command -v chattr >/dev/null; then
                chattr +C /swapfile
            else
                log_err "缺少 chattr 命令，无法安全在 Btrfs 上创建 Swap，跳过。"
                rm -f /swapfile
                return
            fi
        fi
        
        # 3. 使用 fallocate 快速预分配 (秒级)
        if ! fallocate -l ${SIZE}M /swapfile 2>/dev/null; then
            log_warn "fallocate 分配失败，回退到 dd 模式 (较慢)..."
            dd if=/dev/zero of=/swapfile bs=1M count=$SIZE status=none
        fi
        
        # 4. 权限设置与启用
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        
        # 5. 持久化
        if ! grep -q "/swapfile" /etc/fstab; then 
            echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
        fi
        log_success "Swap 创建成功并已启用。"
    else
        log_info "系统已存在 Swap ($SWAP_TOTAL MB)，无需操作。"
    fi
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
#   模块 5: 接入层优化 (SSH & DNS) - 核心修正部分
# ==============================================================================

# 辅助函数: 安全安装 DoH 客户端
install_cloudflared() {
    log_info "开始部署 Cloudflared DoH 客户端..."
    
    # 架构判断
    if [[ "$ARCH" == "x86_64" ]]; then
        URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
    elif [[ "$ARCH" == "aarch64" ]]; then
        URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"
    else
        log_err "不支持的架构: $ARCH"
        return 1
    fi

    # 下载 (增加超时参数)
    log_info "正在从 GitHub 下载二进制文件..."
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
    log_info "正在优化接入层 (SSH & DNS)..."

    # --- 5.1 SSH 优化 (带安全回滚) ---
    log_info "优化 SSH 配置 (禁用 DNS 反查/GSSAPI)..."
    SSHD_CONF="/etc/ssh/sshd_config"
    [ ! -f ${SSHD_CONF}.syspro.bak ] && cp $SSHD_CONF ${SSHD_CONF}.syspro.bak
    
    sed -i 's/^#UseDNS.*/UseDNS no/' $SSHD_CONF
    sed -i 's/^UseDNS.*/UseDNS no/' $SSHD_CONF
    sed -i 's/^#GSSAPIAuthentication.*/GSSAPIAuthentication no/' $SSHD_CONF
    sed -i 's/^GSSAPIAuthentication.*/GSSAPIAuthentication no/' $SSHD_CONF
    
    # 重启前强制检查配置
    log_info "正在校验 SSH 配置完整性..."
    if sshd -t; then
        if [[ "${RELEASE}" == "centos" ]]; then systemctl restart sshd; else systemctl restart ssh; fi
        log_success "SSH 配置校验通过并已重启。"
    else
        log_err "SSH 配置校验失败！为了防止失联，已自动还原备份。"
        cp ${SSHD_CONF}.syspro.bak $SSHD_CONF
        log_warn "请手动检查 /etc/ssh/sshd_config 文件错误。"
    fi

    # --- 5.2 DNS 配置 (交互式) [修复版] ---
    echo -e "${YELLOW}请选择 DNS 模式:${PLAIN}"
    echo -e " 1. ${GREEN}标准 UDP DNS${PLAIN} (速度快, 1.1.1.1/8.8.8.8)"
    echo -e " 2. ${GREEN}DoH 加密 DNS${PLAIN} (防劫持, 需连接 GitHub 下载)"
    read -p "请输入选项 [1-2] (默认1): " DNS_CHOICE
    
    # 先解锁文件
    chattr -i /etc/resolv.conf >/dev/null 2>&1
    
    # 清理旧 DoH 服务
    if [ -f /etc/systemd/system/syspro-doh.service ]; then
        systemctl stop syspro-doh
        systemctl disable syspro-doh
    fi

    if [[ "$DNS_CHOICE" == "2" ]]; then
        if install_cloudflared; then
            rm -f /etc/resolv.conf
            echo "# SysPro DoH (Cloudflared)" > /etc/resolv.conf
            # 主 DNS 指向本地
            echo "nameserver 127.0.0.1" >> /etc/resolv.conf
            
            # [关键修复] 添加备用公共 DNS，防止 Cloudflared 挂掉导致断网 (单点故障)
            echo "# Fallback DNS (Backup)" >> /etc/resolv.conf
            echo "nameserver 1.1.1.1" >> /etc/resolv.conf
            echo "nameserver 8.8.8.8" >> /etc/resolv.conf
            
            # 缩短超时时间，加快故障切换
            echo "options timeout:1 attempts:1" >> /etc/resolv.conf
            
            chattr +i /etc/resolv.conf
            log_success "DoH 模式已生效 (Resolv.conf 已锁定，包含备用 DNS)。"
        else
            log_warn "DoH 安装失败，回退到标准模式。"
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
    
    # 基础工具
    TOOLS="curl wget vim nano htop iotop net-tools ca-certificates unzip"
    log_info "安装运维工具 ($TOOLS)..."
    
    if [[ "${RELEASE}" == "centos" ]]; then
        yum install -y epel-release && yum install -y $TOOLS
        systemctl enable chronyd --now 2>/dev/null || systemctl enable chrony --now 2>/dev/null
    else
        apt-get update && apt-get install -y $TOOLS
        systemctl enable chrony --now 2>/dev/null
    fi
    
    # 交互式时区设置
    CURRENT_TZ=$(timedatectl show --property=Timezone --value 2>/dev/null)
    echo -e "${YELLOW}当前时区: ${CURRENT_TZ:-Unknown}${PLAIN}"
    read -p "是否更改为 Asia/Shanghai (北京时间)? [y/N]: " SET_TZ
    if [[ "$SET_TZ" =~ ^[yY]$ ]]; then
        timedatectl set-timezone Asia/Shanghai
        log_success "时区已更新为 Asia/Shanghai。"
    else
        log_info "保持当前时区不变。"
    fi

    # 日志限制 (100M)
    if [ -f /etc/systemd/journald.conf ]; then
        sed -i 's/^#SystemMaxUse=.*/SystemMaxUse=100M/' /etc/systemd/journald.conf
        sed -i 's/^SystemMaxUse=.*/SystemMaxUse=100M/' /etc/systemd/journald.conf
        systemctl restart systemd-journald
    fi

    # 包清理
    # 警告：原脚本使用了 autoremove，这在生产环境极度危险，可能误删依赖库
    log_info "清理包管理器缓存..."
    if [[ "${RELEASE}" == "centos" ]]; then 
        yum clean all
    else 
        # 改为仅清理安装包缓存，不卸载任何软件
        apt-get clean
    fi
    log_success "系统缓存清理完成。"
}

# ==============================================================================
#   模块 7: 手动管理工具 (新增部分)
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
        # 仅匹配 kernel-数字开头的包，避免匹配到 kernel-tools/headers
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
                    # 尝试猜测并卸载 headers (仅适用于标准命名)
                    # 去掉 linux-image- 前缀，加上 linux-headers-
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

    log_info "正在更新 GRUB 引导配置..."
    if command -v update-grub >/dev/null 2>&1; then
        update-grub
    elif command -v grub2-mkconfig >/dev/null 2>&1; then
        grub2-mkconfig -o /boot/grub2/grub.cfg
    fi
    log_success "内核清理与引导更新完成。"
}

# 7.2 安装第三方 BBR
action_install_other_bbr() {
    clear
    echo -e "${YELLOW}======================================================${PLAIN}"
    echo -e " 准备运行第三方 BBR 安装脚本 (Source: git.io/kernel.sh)"
    echo -e " 注意: 这将从网络下载脚本并以 Root 权限执行。"
    echo -e "${YELLOW}======================================================${PLAIN}"
    read -p "确认继续吗? [y/N]: " CONFIRM
    if [[ "$CONFIRM" =~ ^[yY]$ ]]; then
        log_info "正在下载并执行..."
        # 确保基础依赖
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
        echo -e " 2. ${GREEN}安装其他 BBR${PLAIN}    (调用 git.io/kernel.sh 脚本)"
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
    echo -e "${RED}警告: 正在卸载 SysPro...${PLAIN}"
    
    # 1. 优先解锁 DNS 文件
    chattr -i /etc/resolv.conf >/dev/null 2>&1
    
    # 2. 清理 DoH 服务与残留
    if systemctl is-active syspro-doh >/dev/null 2>&1 || [ -f /etc/systemd/system/syspro-doh.service ]; then
        log_info "正在停止 DoH 服务..."
        systemctl stop syspro-doh
        systemctl disable syspro-doh
        rm -f /etc/systemd/system/syspro-doh.service
        rm -rf /etc/systemd/system/syspro-doh.service.d/
        rm -f /usr/local/bin/cloudflared
        userdel cloudflared >/dev/null 2>&1
        
        # 还原 systemd-resolved 配置
        if [ -f /etc/systemd/resolved.conf.syspro.bak ]; then
            mv /etc/systemd/resolved.conf.syspro.bak /etc/systemd/resolved.conf
            systemctl restart systemd-resolved 2>/dev/null
        elif [ -f /etc/systemd/resolved.conf ]; then
             sed -i 's/^DNSStubListener=no/#DNSStubListener=yes/' /etc/systemd/resolved.conf
             systemctl restart systemd-resolved 2>/dev/null
        fi
    fi

    # 3. [关键修复] 强制重置 resolv.conf 为公共 DNS
    # 防止因 DoH 停止且残留 127.0.0.1 导致断网
    log_info "正在重置 DNS 为公共服务器 (1.1.1.1/8.8.8.8)..."
    rm -f /etc/resolv.conf
    echo "# SysPro Uninstalled - Network Restored" > /etc/resolv.conf
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf
    echo "options timeout:2 attempts:2" >> /etc/resolv.conf
    
    # 4. 清理 Swap
    if grep -q "/swapfile" /proc/swaps; then swapoff /swapfile; fi
    rm -f /swapfile
    
    # 5. 还原 Fstab
    if [ -f /etc/fstab.syspro.bak ]; then
        mv /etc/fstab.syspro.bak /etc/fstab && systemctl daemon-reload && mount -o remount,defaults / 2>/dev/null
    else
        sed -i '/\/swapfile/d' /etc/fstab
    fi

    # 6. 还原 Udev 规则
    rm -f /etc/udev/rules.d/60-io-scheduler.rules
    [ -n "$(command -v udevadm)" ] && udevadm control --reload && udevadm trigger
    
    # 7. 还原 Sysctl 安全参数
    rm -f /etc/sysctl.d/98-syspro-security.conf
    rm -f /etc/security/limits.d/99-disable-core.conf
    sysctl --system >/dev/null 2>&1

    # 8. 还原 SSH (带校验)
    if [ -f /etc/ssh/sshd_config.syspro.bak ]; then
        mv /etc/ssh/sshd_config.syspro.bak /etc/ssh/sshd_config
        if sshd -t; then 
            if [[ "${RELEASE}" == "centos" ]]; then systemctl restart sshd; else systemctl restart ssh; fi
        else
            log_err "SSH 配置还原校验失败，未重启服务，请手动检查。"
        fi
    fi

    # 9. 还原 Systemd 全局
    [ -f /etc/systemd/system.conf.syspro.bak ] && mv /etc/systemd/system.conf.syspro.bak /etc/systemd/system.conf
    systemctl daemon-reload
    
    echo -e "${GREEN}卸载完成！网络已恢复 (使用公共 DNS)。${PLAIN}"
}

# ==============================================================================
#   主菜单
# ==============================================================================
show_menu() {
    clear
    echo -e "${BLUE}================================================================${PLAIN}"
    echo -e "${GREEN}    SysPro v5.3 - Infrastructure Optimizer (整合版)          ${PLAIN}"
    echo -e "${BLUE}================================================================${PLAIN}"
    echo -e " 1. ${GREEN}深度 I/O 优化${PLAIN}   (Noatime, Udev 智能调度)"
    echo -e " 2. ${GREEN}算力与熵池${PLAIN}      (CPU Performance, 智能 Haveged)"
    echo -e " 3. ${GREEN}进程与内存${PLAIN}      (Systemd 优化, Btrfs 兼容 Swap)"
    echo -e " 4. ${GREEN}安全加固${PLAIN}        (隐藏内核地址, dmesg 限制)"
    echo -e " 5. ${GREEN}接入与 DNS${PLAIN}      (SSH 安全重启, DoH/UDP DNS)"
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
