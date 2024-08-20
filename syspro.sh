#!/bin/bash

# syspro - Linux服务器优化和日志禁用脚本

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# 输出函数
info() {
    echo -e "${GREEN}[INFO] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# 检查是否已经优化
check_optimized() {
    if [ -f "/etc/syspro_optimized" ]; then
        return 0
    else
        return 1
    fi
}

# 标记为已优化
mark_optimized() {
    touch /etc/syspro_optimized
}

# 检查包是否已安装
is_package_installed() {
    if command -v dpkg &> /dev/null; then
        dpkg -s "$1" &> /dev/null
    elif command -v rpm &> /dev/null; then
        rpm -q "$1" &> /dev/null
    else
        warn "无法确定包管理系统，跳过包安装检查"
        return 1
    fi
}

# 安装包如果未安装
install_package() {
    if ! is_package_installed "$1"; then
        info "安装 $1..."
        if command -v apt &> /dev/null; then
            apt install -y "$1"
        elif command -v yum &> /dev/null; then
            yum install -y "$1"
        else
            error "未找到支持的包管理器"
            return 1
        fi
    else
        info "$1 已经安装，跳过"
    fi
}

# 自动优化部分
auto_optimize() {
    info "开始自动优化..."

    if check_optimized; then
        info "系统已经优化过，跳过自动优化"
        return
    fi

    update_system
    clean_packages
    disable_unnecessary_services
    set_time_sync
    disable_system_logs
    security_hardening
    configure_dns

    mark_optimized
    info "自动优化完成!"
}

update_system() {
    info "更新系统..."
    if command -v apt &> /dev/null; then
        apt update && apt upgrade -y
    elif command -v yum &> /dev/null; then
        yum update -y
    else
        error "未找到支持的包管理器"
        return 1
    fi
}

clean_packages() {
    info "清理不需要的软件包..."
    if command -v apt &> /dev/null; then
        apt autoremove -y && apt autoclean
    elif command -v yum &> /dev/null; then
        yum autoremove -y && yum clean all
    fi
}

disable_unnecessary_services() {
    info "禁用不必要的服务..."
    unnecessary_services=("bluetooth.service" "cups.service" "avahi-daemon.service" "gdm.service")
    for service in "${unnecessary_services[@]}"; do
        if systemctl is-active --quiet $service; then
            systemctl stop $service
            systemctl disable $service
            info "已禁用 $service"
        else
            info "$service 已经被禁用或不存在"
        fi
    done
}

set_time_sync() {
    info "设置时间同步..."
    if systemctl is-active --quiet systemd-timesyncd; then
        info "时间同步服务已经在运行"
    else
        if command -v timedatectl &> /dev/null; then
            timedatectl set-ntp true
        else
            if [ -f /etc/systemd/timesyncd.conf ]; then
                sed -i 's/^#NTP=/NTP=pool.ntp.org/' /etc/systemd/timesyncd.conf
                systemctl restart systemd-timesyncd
            else
                warn "无法设置时间同步，请手动配置NTP"
            fi
        fi
    fi
}

# 安装其他变种 BBR
install_other_bbr_variants() {
	echo -e "${NFTX_YELLOW}正在安装其他变种 BBR...${NFTX_PLAIN}"
	echo -e "${NFTX_YELLOW}这将运行来自 https://git.io/kernel.sh 的脚本${NFTX_PLAIN}"
	echo -e "${NFTX_RED}警告：运行来自网络的脚本可能存在安全风险。请确保您信任该脚本。${NFTX_PLAIN}"
	echo -n -e "${NFTX_YELLOW}是否继续？(y/n): ${NFTX_PLAIN}"
	read confirm

	if [[ $confirm == [Yy] ]]; then
		bash <(curl -Lso- https://git.io/kernel.sh)
	else
		echo -e "${NFTX_YELLOW}已取消安装${NFTX_PLAIN}"
	fi
}

disable_system_logs() {
    info "禁用系统日志..."
    if ! systemctl is-active --quiet rsyslog && ! systemctl is-active --quiet systemd-journald; then
        info "系统日志已经被禁用"
    else
        systemctl stop rsyslog
        systemctl disable rsyslog
        systemctl stop systemd-journald
        systemctl disable systemd-journald

        cat > /etc/systemd/journald.conf << EOF
[Journal]
Storage=none
ForwardToSyslog=no
ForwardToKMsg=no
ForwardToConsole=no
ForwardToWall=no
EOF

        # 安全地删除日志文件
        find /var/log -type f -delete 2>/dev/null || true
        chmod 0555 /var/log  # 更改为只读权限

        echo "* hard core 0" >> /etc/security/limits.conf
        echo "kernel.core_pattern = /dev/null" >> /etc/sysctl.conf

        if systemctl is-active --quiet kdump; then
            systemctl stop kdump
            systemctl disable kdump
        fi

        if [ -f /etc/default/apport ]; then
            sed -i 's/enabled=1/enabled=0/' /etc/default/apport
        fi

        if command -v abrt-cli &> /dev/null; then
            systemctl stop abrtd
            systemctl disable abrtd
        fi

        echo "kernel.printk = 0 0 0 0" >> /etc/sysctl.conf

        # 安全地处理 wtmp 和 btmp 文件
        if [ -f /var/log/wtmp ]; then
            cat /dev/null > /var/log/wtmp
        fi
        if [ -f /var/log/btmp ]; then
            cat /dev/null > /var/log/btmp
        fi

        # 尝试设置不可变属性，但不强制
        chattr +i /var/log/wtmp /var/log/btmp 2>/dev/null || true

        sysctl -p
    fi
    info "系统日志禁用完成"
}

security_hardening() {
    info "执行安全加固..."
    if [ -f "/etc/security_hardened" ]; then
        info "安全加固已经执行过"
    else
        # 禁用不必要的SUID和SGID文件
        find / -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null | while IFS= read -r -d '' file; do
            case "$file" in
                /bin/su|/usr/bin/sudo|/usr/bin/passwd)
                    # 保留这些重要的SUID文件
                    ;;
                *)
                    chmod u-s,g-s "$file"
                    info "已移除SUID/SGID位: $file"
                    ;;
            esac
        done

        # 设置更安全的密码策略
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

        # 设置强密码策略
        if [ -f /etc/pam.d/common-password ]; then
            sed -i '/pam_pwquality.so/c\password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' /etc/pam.d/common-password
        fi

        touch /etc/security_hardened
        info "安全加固完成"
    fi
}

configure_dns() {
    info "配置DNS..."
    if grep -q "nameserver 76.76.2.0" /etc/resolv.conf; then
        info "DNS已经配置过"
    else
        # 安装resolvconf
        install_package resolvconf

        if ! command -v resolvconf &> /dev/null; then
            warn "无法安装resolvconf，跳过DNS配置"
            return
        fi

        # 配置DNS服务器
        cat > /etc/resolvconf/resolv.conf.d/head << EOF
nameserver 76.76.2.0
nameserver 1.1.1.1
EOF

        # 检查是否启用了IPv6
        if ip -6 addr | grep -q "inet6"; then
            cat >> /etc/resolvconf/resolv.conf.d/head << EOF
nameserver 2606:1a40::
nameserver 2606:4700:4700::1111
EOF
        fi

        # 更新resolv.conf
        resolvconf -u

        info "DNS配置完成"
    fi
}

# 手动优化部分
manual_optimize() {
    while true; do
        echo -e "\n${YELLOW}手动优化选项:${NC}"
        echo "1. 配置硬件加速"
        echo "2. 返回主菜单"

        read -p "请选择要执行的操作 (1-2): " choice

        case $choice in
            1) configure_hardware_acceleration ;;
            2) return ;;
            *) error "无效选项，请重新选择" ;;
        esac
    done
}

# 手动优化部分
manual_optimize() {
    while true; do
        echo -e "\n${YELLOW}手动优化选项:${NC}"
        echo "1. 卸载旧内核"
		echo "2. 安装其他变种 BBR"
        echo "3. 返回主菜单"

        read -p "请选择要执行的操作 (1-2): " choice

        case $choice in
            1) uninstall_kernels ;;
			3) install_other_bbr_variants ;;
            2) return ;;
            *) error "无效选项，请重新选择" ;;
        esac
    done
}

uninstall_kernels() {
    info "列出当前安装的内核："

    current_kernel=$(uname -r)

    if command -v dpkg &> /dev/null; then
        # Debian/Ubuntu 系统
        kernels=($(dpkg --list | grep linux-image | awk '{print $2}' | sort -V))
    elif command -v rpm &> /dev/null; then
        # CentOS/RHEL 系统
        kernels=($(rpm -qa | grep kernel | sort -V))
    else
        error "未知的系统类型，无法列出内核"
        return 1
    fi

    echo "当前正在使用的内核: $current_kernel"
    echo "已安装的内核列表："

    for i in "${!kernels[@]}"; do
        if [[ "${kernels[$i]}" == *"$current_kernel"* ]]; then
            echo "$((i+1)). ${kernels[$i]} (当前使用)"
        else
            echo "$((i+1)). ${kernels[$i]}"
        fi
    done

    echo "输入要卸载的内核编号（用空格分隔多个编号），或者输入 'q' 退出："
    read -r selection

    if [[ "$selection" == "q" ]]; then
        return
    fi

    for num in $selection; do
        if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "${#kernels[@]}" ]; then
            kernel_to_remove="${kernels[$((num-1))]}"
            if [[ "$kernel_to_remove" == *"$current_kernel"* ]]; then
                warn "无法卸载当前正在使用的内核: $kernel_to_remove"
            else
                info "正在卸载内核: $kernel_to_remove"
                if command -v apt &> /dev/null; then
                    apt remove -y "$kernel_to_remove"
                elif command -v yum &> /dev/null; then
                    yum remove -y "$kernel_to_remove"
                fi
            fi
        else
            warn "无效的选择: $num"
        fi
    done

    info "内核卸载完成"
}

# 主菜单
main_menu() {
    while true; do
        echo -e "\n${GREEN}syspro - Linux服务器优化脚本${NC}"
        echo "1. 自动优化（包含禁用日志）"
        echo "2. 手动优化"
        echo "3. 退出"

        read -p "请选择操作 (1-3): " option

        case $option in
            1) auto_optimize ;;
            2) manual_optimize ;;
            3) 
                info "退出脚本"
                exit 0 
                ;;
            *) error "无效选项，请重新选择" ;;
        esac
    done
}

# 检查root权限
if [ "$(id -u)" != "0" ]; then
   error "此脚本需要root权限运行"
   exit 1
fi

# 运行主菜单
main_menu
