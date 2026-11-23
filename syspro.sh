#!/bin/bash
#
# ==============================================================================
#   SysPro Linux Infrastructure Optimizer (ARM 版)
#   (基础层 | DoH 支持 | 安全操作 | ARM 支持)
# ==============================================================================
#
#   [版本] v5.9  —— 以"可回滚"为目标的重写: 所有内核参数在改动前先记快照，
#                   卸载时按原值逐条回放，不再套用硬编码的发行版默认值。
#   [版本] v6.0  —— 新增 bbrplus 内核安装/验证/回退 (amd64 + Debian/Ubuntu 限定)，
#                   以及非交互 CLI 子命令；修复内核卸载后引导假成功等缺陷。
#   [版本] v6.1  —— DNS 选优从 nftx 迁入：探测驱动、协议族无关，只剔除实测不可达的
#                   nameserver；configure_dns 自动应用，并提供 dns check/apply CLI。
#   [适用系统]
#   Debian 10/11/12/13, Ubuntu 20.04/22.04/24.04, CentOS 7/8/9, AlmaLinux/Rocky/Fedora
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
# FIX-P2-6: 原第一项 2606:1a40:: 是 Control D 的 /64 网段前缀而非具体解析器地址，
# 作为 nameserver 通常不可达，白白浪费一次探测。换成两个明确的公共 IPv6 解析器。
DNS_IPV6_LIST="2606:4700:4700::1111
2001:4860:4860::8888"

# 3. DoH (DNS over HTTPS) 上游地址 (cloudflared 后端专用)
#    FIX-RUNTIME-2: 新版 cloudflared 已移除 proxy-dns，会自动切换到 dnscrypt-proxy
#    后端；dnscrypt-proxy 后端使用 cloudflare 上游（在线 resolver 列表），不使用此变量。
DOH_URL_LIST="https://freedns.controld.com/p0
https://8.8.8.8/dns-query"

# 4. DoH 监听地址
#    安全默认值: 127.0.0.1 —— 仅本机可用。
#    注意: 改成 0.0.0.0 会把本机变成"公网开放递归解析器"，会被用于 DNS 放大攻击，
#          云厂商通常会因此封禁 IP。确需给 Docker 容器使用时，请配合防火墙只放行
#          docker0 / br-* 网段，而不要直接暴露到公网。
DOH_LISTEN_ADDR="127.0.0.1"

# 5. 是否禁止 ICMP 回显 (ping)
#    1 = 不响应 ping（部分"安全加固"清单会要求，但会让云厂商探活、监控告警误判宕机）
#    0 = 正常响应 ping（默认，推荐）
SECURITY_BLOCK_ICMP=0

# 5.5 地址族选择偏好 (IPv4/IPv6)
#    现象: 机器没有全局 IPv6，但网卡自动带了一个链路本地地址 fe80::，
#          glibc 的 getaddrinfo(AI_ADDRCONFIG) 据此认为"IPv6 可用"，于是 AAAA 记录
#          被返回并按 RFC 3484 排到最前（IPv6 优先级 40 > IPv4 映射 35）。
#          不支持 Happy Eyeballs 的程序（部分代理）会先连排第一的 v6 → 立即
#          ENETUNREACH → 重试，表现为"每次点开要等几秒"。
#    1 = 自动（推荐）: 仅在检测到"无全局 IPv6 地址"时，往 /etc/gai.conf 写入
#        precedence ::ffff:0:0/96 100，让 getaddrinfo 优先 IPv4。
#        只调排序、不禁用 IPv6，有全局 v6 的机器自动跳过。
#    0 = 关闭: 不改动 gai.conf
GAI_PREFER_IPV4=1

# 6. 第三方 BBR 一键脚本地址
#    原脚本使用的 git.io 短链服务已停止运营（必然 404），此处改为直链。
#    脚本会先下载到临时文件、显示 SHA256 并二次确认后才执行。
BBR_SCRIPT_URL="https://raw.githubusercontent.com/teddysun/across/master/bbr.sh"

# 7. 是否给 /etc/resolv.conf 加 "不可变" 属性 (chattr +i)
#    0 = 不加锁（默认，推荐）
#    1 = 加锁。**风险极高**: DoH 模式下 cloudflared 一旦开机没起来，机器会同时
#        处于"DNS 全挂"和"resolv.conf 改不动"两个状态，只能靠控制台
#        chattr -i 抢救；cloud-init / NetworkManager / dhclient 也无法回写。
#    v5.8 及更早版本会无条件加锁，本版本改为默认不加，并在配置/卸载时自动
#    解除历史遗留的不可变属性。
DNS_LOCK_IMMUTABLE=0

# 8. CPU 频率策略
#    1 = 锁定 performance（默认，符合本脚本"网络吞吐优先"的定位）
#    0 = 不改动，保持系统默认（笔记本 / 在意功耗与温度的机器建议 0）
CPU_GOVERNOR_MODE=1

# 9. 是否禁用 CPU 深度 C-State（C1 以上）
#    1 = 禁用。能降低唤醒延迟，但空闲功耗与温度明显上升，部分小主机会过热。
#    0 = 保持内核默认（默认，推荐）
CPU_DISABLE_DEEP_CSTATES=0

# 10. bbrplus 内核 (v6.0 新增)
#     来源: UJX6N/bbrplus-6.6 的 GitHub release，Debian/Ubuntu amd64 .deb。
#     与"安装其他 BBR"(执行第三方在线 shell 脚本) 的区别:
#       - 只下载 deb，逐个校验包内确实带 CONFIG_TCP_CONG_BBRPLUS=y，不执行任何远程脚本
#       - 保留原内核与原 GRUB_DEFAULT 快照，仅用 grub-reboot 做一次性启动；
#         新内核起不来，下一次重启自动回到原内核
#       - 只有重启后确认 bbrplus 真的可用，才由 bbrplus-confirm 改持久默认
#     注意: 这是更换内核，6.6.21 比 Debian 13 自带的 6.12 更老，属能力换版本。
BBRPLUS_REPO="UJX6N/bbrplus-6.6"
BBRPLUS_TAG="6.6.21-bbrplus"
BBRPLUS_KVER="6.6.21-bbrplus"
BBRPLUS_BACKUP_DIR="/root/syspro-bbrplus-backup"
BBRPLUS_KEEP_DEB=1          # 安装成功后把 deb 留在备份目录，便于离线重装

# ==============================================================================
#   全局常量定义 (Global Constants)
#   说明: 使用常量替换魔法数字，提高代码可读性和可维护性
# ==============================================================================

# 内存相关常量 (MB)
MIN_MEM_FOR_ZRAM=512          # ZRAM 启用上限: 物理内存 <= 此值时才启用 ZRAM
MAX_MEM_FOR_SWAP=4096         # 不需要创建 Swap 的内存阈值
SWAP_FILE_SIZE=1024           # Swap 文件大小
MIN_SWAP_REQUIRED=128         # 最小 Swap 要求
SWAPPINESS_VALUE=10           # swappiness 值

# 状态标记文件 (卸载时据此判断"哪些东西是本脚本创建的"，避免误删用户数据)
MARK_AUDIT="/etc/syspro_audit_disabled"
MARK_SWAP="/etc/syspro_swap_created"
MARK_ZRAM="/etc/syspro_zram_created"
MARK_DOH="/etc/syspro_doh_installed"
MARK_LOGS="/etc/syspro_logs_killed"

# FIX-P3-7: 状态键名集中定义。写入(state_put)与读取(state_get/has)分散在不同函数，
# 字符串字面量拼写不一致会导致回滚时读不到快照。统一用常量避免拼写漂移。
FLAG_UDEV_RULES="FLAG:udev_rules"
FLAG_CSTATES="FLAG:cstates_disabled"
FLAG_CLOUDFLARED="FLAG:cloudflared_installed"
FLAG_SSHD_DROPIN="FLAG:sshd_dropin"
FLAG_JOURNALD_ABSENT="FLAG:journald_conf_absent"
# FIX-RUNTIME-2: DoH 提供者标记，卸载时据此判断是否需要移除 dnscrypt-proxy 配置/包
FLAG_DNSCRYPT="FLAG:dnscrypt_installed"
SVC_KEY_PREFIX="SVC:"        # svc_snapshot/svc_restore 内部构造键用
KEY_GOVERNOR="GOVERNOR"

# FIX-RUNTIME-2: DoH 后端。新版 cloudflared 已彻底移除 proxy-dns（子命令是空存根），
# 自动改用 apt 源里的 dnscrypt-proxy（活跃维护、原生 DoH）。两个后端都生成
# /etc/systemd/system/syspro-doh.service 并监听 DOH_LISTEN_ADDR:53，对上层透明。
DOH_DNSCRYPT_CONF="/etc/syspro-dnscrypt.toml"

# ==============================================================================
#   nftx 协同配置 (Network Fast-Path)
#   nftx_auto 的设计前提: 所有参数由"实测带宽 × RTT"动态推导，且刻意不落
#   /etc/sysctl.d（避免开机极早期把机器配到失联）。因此 syspro 只负责:
#     1) 预载它依赖的 qdisc / 拥塞控制模块
#     2) 持久化"容量型地板值"（只增不减）
#     3) 对齐 systemd 限制，别让 1024/4096 这类默认值把它卡住
#   绝对不能写 net.core.default_qdisc —— nftx 明确说明: 该值在网卡注册前生效，
#   一旦 sch_cake/sch_fq 那时没加载，新建网卡会拿到 noqueue，整机直接失联。
# ==============================================================================
NFTX_AWARE=1                                    # 1 = 执行 nftx 协同准备
NET_FLOOR_CONF="/etc/sysctl.d/96-syspro-netfloor.conf"
NET_MODULES_CONF="/etc/modules-load.d/99-syspro-net.conf"
NFTX_DROPIN="/etc/systemd/system/nftx_auto.service.d/10-syspro-net.conf"
NET_NOFILE_CEIL=1048576                         # nftx 的 NOFILE/NR_OPEN 上限
NET_NPROC_CEIL=65536                            # nftx 的 NPROC 上限

# 时间相关常量 (秒)
DEFAULT_TIMEOUT_STOP=5        # Systemd 停止超时时间
DNS_TIMEOUT=5                 # DNS 查询超时时间
DNS_ATTEMPTS=3                # DNS 查询重试次数

# 5.5 DNS 选优（探测驱动，协议族无关）
#     不预设"v6 该删"：对每个 nameserver 真实查询 N 次，v4/v6 一视同仁，
#     只有连续 N 次全失败才判不可达；全部不可达则保守不动，绝不写空 resolv.conf。
DNS_SELECT_ENABLED=1          # 1 = configure_dns 写盘前自动执行选优（菜单 5 / 一键优化均生效）
DNS_PROBE_TRIES=3             # 每个 nameserver 的探测次数（成功 1 次即保留）
DNS_PROBE_TIMEOUT=2           # 单次 dig 查询超时（秒）
DNS_PROBE_DOMAINS="example.com www.qq.com www.baidu.com"  # 轮换查询的真实域名
# FIX-P3-14: verify_resolv 的超时统一到这里，避免散落的硬编码 6 秒
DNS_VERIFY_TIMEOUT=6          # 写盘后解析验证的超时（秒）

# 权限相关常量
FILE_PERMISSION=644           # 配置文件权限
DIR_PERMISSION=755            # 目录权限

# ==============================================================================
#   全局变量与基础检查
# ==============================================================================

# FIX-P3-1: 启用 pipefail，让 `cmd | grep` 这类管道的失败不再被 grep 的成功掩盖。
# 注意: 脚本刻意不使用 set -e（大量命令失败是预期分支，靠显式判断处理），
# 因此 pipefail 只修正"管道退出码"这一处语义，不会让任何命令失败导致意外退出。
# 所有 `cmd | grep -q` 都在 if/&&/|| 中使用，本就依赖退出码，此处判断会更准确。
set -o pipefail 2>/dev/null || true

# 颜色定义 (用于输出美化)
# 非交互环境（管道、重定向、CI）下关闭颜色，避免日志里塞满转义字符
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    PLAIN='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; PLAIN=''
fi

# 通用小工具
have() { command -v "$1" >/dev/null 2>&1; }

# 非交互 CLI 子命令标记: 只读类不写日志、不建 logrotate、不抢单实例锁。
# 放在最前面，因为这些副作用发生在 root 检查 / 锁 / setup_logrotate 之前或之中。
SYSPRO_READONLY_CLI=0
case "${1:-}" in
    help|--help|-h|bbrplus-status|--bbrplus-status|bbrplus-check|--bbrplus-check|selftest|--selftest|plan|--plan|status-json|--status-json)
        SYSPRO_READONLY_CLI=1 ;;   # FIX-P3-11/12: plan/status-json 也设为只读

    dns)
        # dns check 只读；dns apply 会写 resolv.conf，必须保留完整 root/锁/日志路径。
        [ "${2:-check}" != "apply" ] && SYSPRO_READONLY_CLI=1 ;;
esac

# ------------------------------------------------------------------------------
#   无 systemd 环境（容器 / chroot）兜底
#   脚本里 systemctl 调用有几十处，宿主没有 systemd 时每一条都会往终端吐
#   "systemctl: command not found"。这里用同名函数顶掉它:
#   查询类返回"不存在/未激活"，操作类静默成功，让流程能走完而不是满屏报错。
# ------------------------------------------------------------------------------
if ! have systemctl; then
    systemctl() {
        case "$1" in
            is-active|is-enabled|show|status) return 1 ;;
            *) return 0 ;;
        esac
    }
fi

# ==============================================================================
#   状态快照 (State Snapshot)
#
#   卸载时"恢复默认值"是整个脚本里最容易出错的一步: 内核默认值随发行版/内核版本
#   而变（RHEL 的 kernel.sysrq 是 16，Debian 是 438；现代发行版的 core_pattern 是
#   systemd-coredump 的管道，不是 "core"）。凭记忆写死的"默认值"只会在别人的机器上
#   制造新问题。
#
#   所以改成: 改动之前先把原值记到 /var/lib/syspro/state.env，卸载时逐条回放。
#   记不到原值（键不存在 / /proc 只读）就什么都不恢复 —— 因为这时很可能我们
#   也没改成功。
#
#   文件格式: key|value   一行一条，首次写入为准（先到先得 = 真正的原始值）。
# ==============================================================================
STATE_DIR="/var/lib/syspro"
STATE_FILE="$STATE_DIR/state.env"

state_init() {
    [ -d "$STATE_DIR" ] || mkdir -p "$STATE_DIR" 2>/dev/null
    [ -f "$STATE_FILE" ] || : > "$STATE_FILE" 2>/dev/null
    return 0
}

# 取记录值；不存在时返回 1（stdout 为空）
state_get() {
    [ -f "$STATE_FILE" ] || return 1
    local v
    v=$(awk -F'|' -v k="$1" '$1==k { sub(/^[^|]*\|/, ""); print; exit }' "$STATE_FILE" 2>/dev/null)
    [ -n "$v" ] || return 1
    printf '%s' "$v"
}

state_has() {
    [ -f "$STATE_FILE" ] || return 1
    awk -F'|' -v k="$1" '$1==k { f=1 } END { exit(f?0:1) }' "$STATE_FILE" 2>/dev/null
}

# 只写一次。重复运行不会覆盖第一次记下的原值。
state_put() {
    local k=$1 v=$2
    [ -n "$k" ] || return 1
    case "$v" in *$'\n'*) return 1 ;; esac
    state_init
    state_has "$k" && return 0
    printf '%s|%s\n' "$k" "$v" >> "$STATE_FILE" 2>/dev/null
}

state_del() {
    [ -f "$STATE_FILE" ] || return 0
    # 固定 .tmp 文件名在并发/中断下会留下半成品，甚至被另一进程覆盖。
    # 用 PID 区分 + mv 原子替换（与 syspro 其它落盘规则一致）。
    local tmp="${STATE_FILE}.tmp.$$"
    if awk -F'|' -v k="$1" '$1!=k' "$STATE_FILE" > "$tmp" 2>/dev/null \
       && mv -f "$tmp" "$STATE_FILE" 2>/dev/null; then
        return 0
    fi
    rm -f "$tmp" 2>/dev/null
    return 1
}

# /proc/sys 上是否真的存在这个键。
# 老内核缺键是常态: fs.epoll.max_user_watches 是 5.11 才有，
# net.core.netdev_budget_usecs 是 4.10 才有 —— 把它们写进 sysctl.d，
# 每次开机 systemd-sysctl 都会报 "unknown key" 并让服务变红。
sysctl_key_exists() {
    [ -e "/proc/sys/${1//./\/}" ]
}

# 向 sysctl 配置文件追加一个键，键不存在就跳过（并在终端说明）。
# 必须逐键探测，这是 v5.8 "audit=0 写进 sysctl.d" 那个老问题的通用解法。
emit_sysctl() {
    local file=$1 key=$2 val=$3
    if sysctl_key_exists "$key"; then
        printf '%s = %s\n' "$key" "$val" >> "$file"
        return 0
    fi
    log_info "  - 内核不支持 $key，已跳过（避免开机 systemd-sysctl 报 unknown key）"
    return 1
}

# sysctl 配置里除了注释，是否还有真实的键
sysctl_file_has_keys() {
    grep -qE '^[[:space:]]*[a-zA-Z]' "$1" 2>/dev/null
}

# 记录某个内核参数的当前值（只在第一次记录时生效）
snapshot_sysctl() {
    local k=$1 v
    state_has "SYSCTL:$k" && return 0
    v=$(sysctl -n "$k" 2>/dev/null)
    case "$v" in ''|*$'\n'*) return 1 ;; esac
    state_put "SYSCTL:$k" "$v"
}

# 把快照里的内核参数逐条写回去。
# 注意: 只回放"我们确实记录过"的键，绝不猜测内核默认值。
restore_sysctl_snapshots() {
    local line k v n=0 failed=0 cur
    # FIX-P2-5: 容量型"地板"参数由 nftx 按实测只增不减地调，卸载时不应把
    # nftx 的成果降回脚本运行前的旧值。这些键回滚时若当前值已高于快照值，
    # 保留当前值（不降级）；其余参数照常精确回滚。
    local floor_keys=" net.core.somaxconn net.ipv4.tcp_max_syn_backlog net.core.netdev_max_backlog net.core.netdev_budget net.core.netdev_budget_usecs fs.nr_open fs.file-max fs.epoll.max_user_watches "
    [ -f "$STATE_FILE" ] || return 0
    while IFS= read -r line; do
        case "$line" in SYSCTL:*) ;; *) continue ;; esac
        k=${line#SYSCTL:}
        k=${k%%|*}
        v=${line#*|}
        [ -n "$k" ] && [ -n "$v" ] || continue
        sysctl_key_exists "$k" || continue
        # 地板键：当前值高于快照值时保留（nftx 或他人上调过）
        case "$floor_keys" in
            *" $k "*)
                cur=$(sysctl -n "$k" 2>/dev/null </dev/null)
                case "$cur" in ''|*[!0-9]*) cur=0 ;; esac
                case "$v" in ''|*[!0-9]*) : ;; *)
                    if [ "$cur" -gt "$v" ]; then
                        log_info "  - $k 当前值 $cur 高于快照 $v，保留高值（不抹掉 nftx 调整）"
                        continue
                    fi
                ;; esac
                ;;
        esac
        # </dev/null: 这个循环本身从 $STATE_FILE 读 stdin，任何会读 stdin 的子命令
        # 都会把后面的记录吃掉，导致"只回滚了第一条"。
        if sysctl -w "$k=$v" >/dev/null 2>&1 < /dev/null; then
            n=$((n + 1))
        else
            failed=$((failed + 1))
        fi
    done < "$STATE_FILE"
    [ "$n" -gt 0 ] && log_info "  - 已按快照回滚 $n 个内核参数"
    [ "$failed" -gt 0 ] && log_warn "  - 有 $failed 个内核参数回滚失败（重启后自然恢复为内核默认）"
    return 0
}

# 备份一个"可能已被本脚本改写过"的配置文件。
# 如果现有文件带着 SysPro 签名，说明它就是我们自己生成的 —— 绝不能拿它当原始备份，
# 否则卸载时会把"我们的配置"当成"用户的原配置"恢复回去。
# 返回 0 = 可用备份已存在（或刚刚建立）; 1 = 源文件不存在，或是我们自己的
backup_if_pristine() {
    local src=$1 bak=$2
    [ -f "$bak" ] && return 0
    [ -f "$src" ] || return 1
    if grep -q '由 SysPro 写入' "$src" 2>/dev/null; then
        return 1
    fi
    if cp -p "$src" "$bak" 2>/dev/null; then
        # FIX-P3-3: 写伴生标记，记录此备份由本脚本在某时刻建立。
        # 恢复时据此区分"本脚本的原始备份"与"用户自己的同名文件"，
        # 避免把用户文件当备份恢复。标记失败不影响备份本身。
        printf 'src=%s\ntime=%s\n' "$src" "$(date '+%F %T' 2>/dev/null)" \
            > "${bak}.syspro-origin" 2>/dev/null || true
        return 0
    fi
    return 1
}

# 取"当前值"与"目标下限"中较大的那个，只读不动系统
sysctl_at_least() {
    local key=$1 want=$2 cur
    cur=$(sysctl -n "$key" 2>/dev/null)
    case "$cur" in ''|*[!0-9]*) cur=0 ;; esac
    if [ "$cur" -ge "$want" ]; then printf '%s' "$cur"; else printf '%s' "$want"; fi
}

# 只上调、不下调。
# 这条规矩是给 nftx 让路的关键: nftx 会在运行时把 somaxconn / tcp_mem / netdev_budget
# 按实测值调到最优点，syspro 的任何"重新应用"都必须只升不降，否则会把它的成果抹掉。
# 返回值: 0 = 已达标 ; 1 = 写入失败 ; 2 = 内核不支持该键（调用方不应报警）
sysctl_raise() {
    local key=$1 want=$2 cur
    sysctl_key_exists "$key" || return 2
    cur=$(sysctl -n "$key" 2>/dev/null)
    case "$cur" in ''|*[!0-9]*) cur=0 ;; esac
    if [ "$cur" -lt "$want" ]; then
        sysctl -w "$key=$want" >/dev/null 2>&1
        cur=$(sysctl -n "$key" 2>/dev/null)
        case "$cur" in ''|*[!0-9]*) cur=0 ;; esac
    fi
    [ "$cur" -ge "$want" ] && return 0
    return 1
}

# 日志封装函数
LOG_FILE="/var/log/syspro-exec.log"
log_to_file() {
    [ "${SYSPRO_READONLY_CLI:-0}" = "1" ] && return 0
    # /var/log 只读、磁盘已满或目录不存在时都不应影响主流程。
    # 注意: 必须把重定向放进 { } 里再统一重定向 stderr，
    #       否则 ">>" 打开文件失败时，报错由 shell 直接打到终端，2>/dev/null 拦不住。
    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$$] $1" >> "$LOG_FILE"; } 2>/dev/null || true
}

log_info()    { local msg="${BLUE}[INFO]${PLAIN} $1"; echo -e "$msg"; log_to_file "[INFO] $1"; }
log_success() { local msg="${GREEN}[OK]${PLAIN} $1"; echo -e "$msg"; log_to_file "[OK] $1"; }
log_warn()    { local msg="${YELLOW}[WARN]${PLAIN} $1"; echo -e "$msg"; log_to_file "[WARN] $1"; }
log_err()     { local msg="${RED}[ERR]${PLAIN} $1"; echo -e "$msg"; log_to_file "[ERR] $1"; }

# 记录脚本启动信息
log_to_file "=========================================="
log_to_file "SysPro v6.1 started"
log_to_file "Hostname: $(hostname)"
log_to_file "User: $USER"
log_to_file "=========================================="

# 1. Root 权限检查
if [[ $EUID -ne 0 ]] && [ "${SYSPRO_READONLY_CLI:-0}" != "1" ]; then
    log_err "错误：本脚本需要 Root 权限才能执行底层优化。"
    exit 1
fi

# 1.1 单实例锁
# 两个终端同时跑，会在 fstab / resolv.conf / sysctl.d 上互相覆盖 —— 而且
# 各自的"备份"会互相当成对方留下的残留，回滚结果不可预期。用内核锁挡住。
LOCK_FILE="/run/syspro.lock"
{ [ -d /run ] && [ -w /run ]; } 2>/dev/null || LOCK_FILE="/tmp/syspro.lock"

if have flock && [ "${SYSPRO_READONLY_CLI:-0}" != "1" ]; then
    # 注意: 不能直接 `exec 9>"$LOCK_FILE"`。
    # 非交互 shell 里 exec 的重定向一旦失败，整个脚本会当场退出（POSIX 行为），
    # 连一句提示都没有。先确认可写，再让 exec 必然成功。
    if { : >> "$LOCK_FILE"; } 2>/dev/null; then
        exec 9>>"$LOCK_FILE"
        if ! flock -n 9; then
            log_err "另一个 SysPro 实例正在运行（锁文件: $LOCK_FILE）。"
            log_err "并发执行会互相覆盖系统配置，已退出。请等它结束后再试。"
            exit 1
        fi
    else
        log_warn "无法创建锁文件 $LOCK_FILE，本次跳过并发保护。"
    fi
fi

# 1.2 中断清理
# 只清"半成品"临时文件；*.syspro.bak / *.syspro.tmpbak 是完整的回滚点，
# 无论正常退出还是 Ctrl-C 都保留，便于人工兜底。
cleanup_on_exit() {
    rm -f /etc/fstab.syspro.tmp /etc/resolv.conf.syspro.new 2>/dev/null
    [ -n "${BBR_TMP:-}" ] && rm -f "$BBR_TMP" 2>/dev/null
    # mktemp -d 创建的临时解包目录，Ctrl-C 时一并清掉（只在 /tmp 下）
    case "${BBRPLUS_TMP:-}" in
        # FIX-P2-2: 原模式 /tmp/syspro-bbrplus.* 匹配不上 bbrplus-check 创建的
        # /tmp/syspro-bbrplus-check.XXXXXX，Ctrl-C 时会残留临时目录
        /tmp/syspro-bbrplus*) rm -rf "$BBRPLUS_TMP" 2>/dev/null ;;
    esac
    return 0
}
trap cleanup_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# 1.3 日志轮转
# 旧版本只往 /var/log/syspro-exec.log 追加，从不轮转；跑几十次就能把 /var 写满，
# 而"关闭日志系统"模块又把 rsyslog 屏蔽了，连个告警都不会有。
setup_logrotate() {
    [ -d /etc/logrotate.d ] || return 0
    [ -f /etc/logrotate.d/syspro ] && return 0
    cat > /etc/logrotate.d/syspro <<'EOF'
# 由 SysPro 写入
/var/log/syspro-exec.log {
    weekly
    rotate 4
    maxsize 5M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF
    return 0
}
[ "${SYSPRO_READONLY_CLI:-0}" = "1" ] || setup_logrotate

# 2. 系统发行版与架构深度检测 (ARM 适配关键)
RAW_ARCH=$(uname -m)
case $RAW_ARCH in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7l|armv6l) ARCH="armhf" ;; # 树莓派 32位 / Zero
    *) ARCH="unknown" ;;
esac

# 精确检测系统发行版
# 注意: Ubuntu 同样自带 /etc/debian_version，绝不能按"文件是否存在"去猜，
#       必须先读 /etc/os-release 的 ID（v5.3 会把 Ubuntu 一律判成 debian）。
detect_release() {
    local id="" like=""
    if [ -r /etc/os-release ]; then
        id=$(. /etc/os-release 2>/dev/null; printf '%s' "${ID:-}")
        like=$(. /etc/os-release 2>/dev/null; printf '%s' "${ID_LIKE:-}")
    fi
    id=$(printf '%s' "$id" | tr 'A-Z' 'a-z')
    like=$(printf '%s' "$like" | tr 'A-Z' 'a-z')

    case "$id" in
        ubuntu)      echo "ubuntu";    return ;;
        debian)      echo "debian";    return ;;
        almalinux)   echo "almalinux"; return ;;
        rocky)       echo "rocky";     return ;;
        fedora)      echo "fedora";    return ;;
        centos|rhel) echo "centos";    return ;;
    esac

    # os-release 缺失或 ID 非标准时，按 ID_LIKE 归类
    case "$like" in
        *rhel*|*fedora*|*centos*) echo "centos"; return ;;
        *debian*|*ubuntu*)        echo "debian"; return ;;
    esac

    # 最后兜底
    if   [ -f /etc/almalinux-release ]; then echo "almalinux"
    elif [ -f /etc/rocky-release ];     then echo "rocky"
    elif [ -f /etc/fedora-release ];    then echo "fedora"
    elif [ -f /etc/centos-release ] || [ -f /etc/redhat-release ]; then echo "centos"
    elif [ -f /etc/debian_version ];    then echo "debian"
    else echo "unknown"; fi
}

# 把发行版归一到包管理族，后续所有分支只判断 apt / rpm，不再判断具体发行版
detect_family() {
    case "$1" in
        debian|ubuntu)              echo "apt" ;;
        centos|almalinux|rocky|fedora) echo "rpm" ;;
        *)                          echo "unknown" ;;
    esac
}

RELEASE=$(detect_release)
RELEASE_FAMILY=$(detect_family "$RELEASE")

log_info "系统环境: ${GREEN}${RELEASE}${PLAIN} | 包管理: ${GREEN}${RELEASE_FAMILY}${PLAIN} | 架构: ${GREEN}${ARCH}${PLAIN} (${RAW_ARCH})"

# 注意: validate_dns_config / validate_system_compatibility 的调用已移动到
#       它们自己的定义之后（见"配置验证函数"区块结尾）。v5.3 在这里调用，
#       此时函数尚未定义，结果是 command not found + 校验被静默跳过。

# ==============================================================================
#   全局辅助函数：包管理器
# ==============================================================================

# 定义全局标记，0 表示未更新，1 表示已更新
PKG_UPDATED=0

smart_pkg_update() {
    # 只有当标记为 0 时才执行更新
    if [ "$PKG_UPDATED" -eq 0 ]; then
        log_info "正在刷新包管理器缓存 (只会执行一次)..."
        
        case "$RELEASE_FAMILY" in
            apt) apt-get update -y >/dev/null 2>&1 || log_warn "包索引刷新失败，继续执行" ;;
            rpm) pkg_makecache || log_warn "包索引刷新失败，继续执行" ;;
            *)   log_warn "未知的包管理族，跳过缓存刷新" ;;
        esac
        
        # 更新完成后，将标记设为 1，后续调用将直接跳过
        PKG_UPDATED=1
    else
        # 调试用
        # log_info "包管理器缓存已更新，跳过。" 
        :
    fi
}

# 包管理器统一封装
# 目的: 上游 v5.3 全脚本只区分 centos / 其它，导致 Alma、Rocky、Fedora
#       （头部明确声明支持）会走到 apt-get，直接 command not found。
pkg_mgr() {
    if [ "$RELEASE_FAMILY" = "rpm" ]; then
        if have dnf; then echo "dnf"; else echo "yum"; fi
    else
        echo "apt-get"
    fi
}

pkg_install() {
    [ $# -eq 0 ] && return 1
    case "$RELEASE_FAMILY" in
        # --force-confdef/--force-confold 是必须的: 少了它们，任何一次 conffile
        # 冲突（/etc/default/grub、/etc/ssh/sshd_config 之类）dpkg 都会弹交互式
        # 提问，而脚本在无人值守时会一直卡在那里等输入。
        # </dev/null 是第二道保险: 任何残留的提问都会立刻读到 EOF 而不是挂住。
        apt) DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical \
                apt-get install -y \
                    -o Dpkg::Options::=--force-confdef \
                    -o Dpkg::Options::=--force-confold \
                    "$@" < /dev/null ;;
        rpm) "$(pkg_mgr)" install -y "$@" < /dev/null ;;
        *)   log_err "不支持的发行版，无法安装: $*"; return 1 ;;
    esac
}

pkg_remove() {
    [ $# -eq 0 ] && return 1
    case "$RELEASE_FAMILY" in
        apt) DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical \
                apt-get purge -y \
                    -o Dpkg::Options::=--force-confdef \
                    -o Dpkg::Options::=--force-confold \
                    "$@" < /dev/null ;;
        rpm) "$(pkg_mgr)" remove -y "$@" < /dev/null ;;
        *)   return 1 ;;
    esac
}

pkg_makecache() {
    case "$RELEASE_FAMILY" in
        apt) apt-get update -y ;;
        rpm) "$(pkg_mgr)" makecache ;;
        *)   return 1 ;;
    esac
}

pkg_clean() {
    case "$RELEASE_FAMILY" in
        apt) apt-get clean ;;
        rpm) "$(pkg_mgr)" clean all ;;
        *)   return 1 ;;
    esac
}

# 识别 SSH 服务单元名（Debian 系是 ssh，RHEL 系是 sshd）
detect_ssh_service() {
    local u
    for u in sshd.service ssh.service; do
        if systemctl list-unit-files "$u" 2>/dev/null | grep -q "^${u}"; then
            echo "${u%.service}"
            return 0
        fi
    done
    if [ "$RELEASE_FAMILY" = "rpm" ]; then echo "sshd"; else echo "ssh"; fi
}

# ------------------------------------------------------------------------------
#   服务状态快照
#   只记录"这个单元在本脚本动手之前是什么状态"，卸载时按记录还原。
#   旧版本卸载时无条件 systemctl enable 一串服务，会把管理员主动禁用的
#   auditd / kdump / avahi-daemon 重新拉起来 —— 这不是"恢复"，是制造新变更。
# ------------------------------------------------------------------------------
svc_unit_exists() {
    systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "^$1\.service"
}

svc_snapshot() {
    local svc=$1 st
    state_has "SVC:$svc" && return 0
    if ! svc_unit_exists "$svc"; then
        st="absent"
    elif systemctl is-enabled "$svc" >/dev/null 2>&1; then
        st="enabled"
    else
        st="disabled"
    fi
    state_put "SVC:$svc" "$st"
}

# 按快照还原单个服务。未记录过（不属于本脚本管理）直接跳过。
svc_restore() {
    local svc=$1 st
    st=$(state_get "SVC:$svc") || return 0
    [ "$st" = "absent" ] && return 0

    systemctl unmask "$svc" >/dev/null 2>&1
    if [ "$st" = "enabled" ]; then
        systemctl enable "$svc" >/dev/null 2>&1
        systemctl restart "$svc" >/dev/null 2>&1
        log_info "  - 服务 $svc 已恢复为 enabled"
    else
        # 原本就是禁用状态: 只解除 mask，不要 enable
        systemctl disable "$svc" >/dev/null 2>&1
        log_info "  - 服务 $svc 原本已禁用，仅解除屏蔽"
    fi
    return 0
}

# --- 使用说明 ---
# 后续模块安装软件统一用 pkg_install，不要再直接写 apt-get / yum。

# ==============================================================================
#   配置验证函数
# ==============================================================================

# FIX-P1-11/P1-12: 统一的 IPv6 可用性判据，供 DNS 配置与 gai.conf 共用。
# 原代码两处口径不一：DNS 层要求"默认路由+全局地址"，gai 层只要"全局地址"；
# 且都只看地址存在性，不看出口是否真的可达。
# has_global_ipv6: 有默认路由且有全局地址（格式判断）
has_global_ipv6() {
    command -v ip >/dev/null 2>&1 || return 1
    ip -6 route show default 2>/dev/null | grep -q '^default' || return 1
    ip -6 addr show scope global 2>/dev/null | grep -q 'inet6'
}

# ipv6_reachable: 全局 v6 存在且出口实测可达（用 dig 直连公共 IPv6 DNS）。
# 无 dig/无 ping6 时保守返回 1（视为可达），避免因探测工具缺失而误判为无 v6。
ipv6_reachable() {
    has_global_ipv6 || return 1
    if have dig; then
        timeout 4 dig +short +time=2 +tries=1 @2606:4700:4700::1111 cloudflare.com A >/dev/null 2>&1 && return 0
        timeout 4 dig +short +time=2 +tries=1 @2001:4860:4860::8888 cloudflare.com A >/dev/null 2>&1 && return 0
        return 1
    fi
    return 0
}

validate_ipv4() {
    local ip=$1 octet
    [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    for octet in $ip; do
        # 10# 前缀强制十进制，避免 08 之类被当成八进制而报错
        (( 10#$octet <= 255 )) || return 1
    done
    return 0
}

validate_ipv6() {
    local ip=$1 grp n=0 has_compress=0
    [[ $ip == *:* ]] || return 1
    [[ $ip =~ ^[0-9a-fA-F:]+$ ]] || return 1
    [[ $ip == *::*::* ]] && return 1     # 不允许出现两个 "::"
    [[ $ip == *:::* ]] && return 1       # FIX-P2-1: 拒绝 ::: 这类三个以上连续冒号
    [[ $ip == *::* ]] && has_compress=1
    # FIX-P2-1: 原实现不校验组数，:::/1:2/九组地址都被误判合法。
    # 展开后总组数必须 <=8；无 "::" 压缩时必须正好 8 组。
    local IFS=':'
    for grp in $ip; do
        [ -z "$grp" ] && continue
        [[ $grp =~ ^[0-9a-fA-F]{1,4}$ ]] || return 1
        n=$((n + 1))
    done
    if [ "$has_compress" -eq 1 ]; then
        [ "$n" -le 7 ] || return 1    # 有 :: 但非空组已达 8 组，非法
    else
        [ "$n" -eq 8 ] || return 1
    fi
    return 0
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
    if [ -r /etc/os-release ]; then
        os_version=$(. /etc/os-release 2>/dev/null; printf '%s' "${VERSION_ID:-}")
    fi

    # 统一从 VERSION_ID 取版本号，不再依赖 lsb_release / rpm -E %rhel
    case "$RELEASE" in
        debian)
            [[ "$os_version" =~ ^(10|11|12|13)$ ]] || \
                log_warn "检测到 Debian ${os_version:-unknown}，推荐版本: 10/11/12/13"
            ;;
        ubuntu)
            [[ "$os_version" =~ ^(20\.04|22\.04|24\.04)$ ]] || \
                log_warn "检测到 Ubuntu ${os_version:-unknown}，推荐版本: 20.04/22.04/24.04"
            ;;
        centos|almalinux|rocky)
            local rhel_ver="${os_version%%.*}"
            [[ "$rhel_ver" =~ ^(7|8|9)$ ]] || \
                log_warn "检测到 RHEL 系 ${rhel_ver:-unknown}，推荐版本: 7/8/9"
            ;;
        fedora)
            log_info "检测到 Fedora ${os_version:-unknown}，该版本未做完整验证，请谨慎使用。"
            ;;
        *)
            log_warn "未针对 ${RELEASE} 做兼容性验证，继续执行但请自行承担风险。"
            ;;
    esac
    
    if [ "$compatible" -eq 1 ]; then
        log_success "系统兼容性检查通过。"
        return 0
    else
        return 1
    fi
}

# --- 校验入口 ---
# 必须放在上述两个函数定义之后。v5.3 在文件顶部调用，此时函数还不存在，
# bash 只会抛 command not found 然后继续执行，等于校验从未生效。
validate_dns_config || log_warn "DNS 配置存在无效项，写入时将自动跳过。"
validate_system_compatibility || log_warn "兼容性检查未完全通过，请确认发行版/架构受支持。"

# ==============================================================================
#   模块 1: 磁盘 I/O 调优 (Disk I/O)
#   修改说明: 移除 CPU 密集型的 bfq 算法，使用 mq-deadline/none
# ==============================================================================

# ------------------------------------------------------------------------------
#   探测当前内核真正支持的 I/O 调度器名字
#   CentOS 7 的 3.10 只有 noop / deadline / cfq；"none" 与 "mq-deadline" 都是
#   blk-mq 时代才出现的名字。写死这两个名字的 udev 规则在老内核上是纯空操作，
#   而脚本头部明确声明支持 CentOS 7。
#   参数: 候选名（按优先级从高到低），返回第一个"所有块设备都支持"的名字。
# ------------------------------------------------------------------------------
detect_scheduler_name() {
    local want d avail ok found
    for want in "$@"; do
        ok=1; found=0
        for d in /sys/block/*/queue/scheduler; do
            [ -f "$d" ] || continue
            found=1
            avail=$(cat "$d" 2>/dev/null)
            case "$avail" in
                *"$want"*) ;;
                *) ok=0; break ;;
            esac
        done
        if [ "$found" -eq 1 ] && [ "$ok" -eq 1 ]; then
            printf '%s' "$want"
            return 0
        fi
    done
    return 1
}

optimize_disk_io() {
    log_info "正在优化磁盘 I/O 策略 (低延迟/网络优先模式)..."
    local errors=0

    # --- 1.1 挂载参数优化 (noatime) ---
    if [ -f /etc/fstab ] && [ ! -f /etc/fstab.syspro.bak ]; then
        if ! cp -p /etc/fstab /etc/fstab.syspro.bak; then
            log_err "无法备份 fstab 文件"
            errors=$((errors + 1))
        fi
    fi
    
    if [ -f /etc/fstab ] && grep -qE '^[^#]*[[:space:]]/[[:space:]]' /etc/fstab \
       && grep -qE '^[^#]*[[:space:]]/[[:space:]].*noatime' /etc/fstab 2>/dev/null; then
        log_info "根分区已配置 noatime，跳过修改。"
    elif [ ! -f /etc/fstab ]; then
        log_warn "/etc/fstab 不存在（可能是容器环境），跳过挂载参数优化。"
    else
        log_info "尝试修改 /etc/fstab 添加 noatime..."
        local fstab_tmp="/etc/fstab.syspro.tmp"
        if ! awk '!/^[[:space:]]*#/ && $2 == "/" && ($3 == "ext4" || $3 == "xfs" || $3 == "btrfs") { $4 = $4 ",noatime,nodiratime" } { print }' /etc/fstab > "$fstab_tmp"; then
            log_err "生成 fstab 临时文件失败"
            rm -f "$fstab_tmp"
            errors=$((errors + 1))
        elif [ ! -s "$fstab_tmp" ]; then
            log_err "fstab 临时文件为空，已放弃修改"
            rm -f "$fstab_tmp"
            errors=$((errors + 1))
        elif cmp -s /etc/fstab "$fstab_tmp"; then
            rm -f "$fstab_tmp"
            log_warn "未检测到标准根分区格式（ext4/xfs/btrfs），跳过 fstab 修改。"
        else
            # 写回前做结构自检。
            # 关键认识: 上面那段 awk 只往第 4 字段尾部追加，所以正确的不变量是
            #   "字段数不变" + "第 4 字段 == 原值 + 固定后缀"
            # 而不是"字段数必须等于 6"。
            #
            # 这里必须和改写用的 awk 用同一套过滤条件（跳过注释行），否则会踩到
            # Debian/Ubuntu 安装器留下的这行注释:
            #     # / was on /dev/sda15 during installation
            # 它的 $2 正好是 "/"、$4 正好是 "on"、NF 正好是 7 —— 于是
            #   v5.5: 报"字段数异常 (7)"
            #   v5.6: 报"选项改写与预期不符 (期望 on,noatime...)"
            # 两次误报都是同一个根因：把注释当成了挂载项。
            local root_parse='!/^[[:space:]]*#/ && $2 == "/" { printf "%d %s\n", NF, $4; exit }'
            local old_info new_info old_nf old_opts new_nf new_opts fstab_ok=1
            old_info=$(awk "$root_parse" /etc/fstab)
            new_info=$(awk "$root_parse" "$fstab_tmp")
            old_nf=${old_info%% *}; old_opts=${old_info#* }
            new_nf=${new_info%% *}; new_opts=${new_info#* }

            if [ -z "$old_info" ] || [ -z "$new_info" ]; then
                log_err "无法解析 fstab 根分区行，已放弃修改"
                fstab_ok=0
            elif [ "$old_nf" -lt 4 ]; then
                log_err "fstab 根分区字段过少 (${old_nf})，已放弃修改"
                fstab_ok=0
            elif [ "$new_nf" != "$old_nf" ]; then
                log_err "fstab 字段数被改变 (${old_nf} -> ${new_nf})，已放弃修改"
                log_warn "    原始行: $(awk '!/^[[:space:]]*#/ && $2 == "/"' /etc/fstab | head -n 1)"
                fstab_ok=0
            elif [ "$new_opts" != "${old_opts},noatime,nodiratime" ]; then
                log_err "fstab 挂载选项改写结果与预期不符，已放弃修改"
                log_warn "    期望: ${old_opts},noatime,nodiratime"
                log_warn "    实际: ${new_opts}"
                fstab_ok=0
            fi

            # findmnt --verify 作为补充检查。
            # 走到这里已经证明"结构没被改动"，所以它报的 [E] 只可能是磁盘上
            # 既有的历史问题，不是本次修改引入的 —— 因此只提示、不拦截。
            # （把它做成硬拦截的话，别人的 fstab 有点旧毛病，我们连 noatime 都做不了。）
            if [ "$fstab_ok" -eq 1 ] && have findmnt; then
                local vlog="/tmp/syspro-fstab-verify.$$"
                if ! findmnt --verify --tab-file "$fstab_tmp" >"$vlog" 2>&1; then
                    if grep -q '\[E\]' "$vlog"; then
                        log_warn "  - findmnt 报告 fstab 中存在既有问题（非本次修改引入）："
                        grep '\[E\]' "$vlog" | head -n 3 | sed 's/^/      /'
                    fi
                fi
                rm -f "$vlog"
            fi

            if [ "$fstab_ok" -ne 1 ]; then
                rm -f "$fstab_tmp"
                errors=$((errors + 1))
            elif cp -p /etc/fstab /etc/fstab.syspro.tmpbak 2>/dev/null \
                 && mv "$fstab_tmp" /etc/fstab; then
                if mount -o remount / 2>/dev/null; then
                    rm -f /etc/fstab.syspro.tmpbak
                    log_success "根分区挂载参数已更新 (noatime)。"
                else
                    log_err "重挂载失败，自动回滚 fstab..."
                    cp -p /etc/fstab.syspro.tmpbak /etc/fstab 2>/dev/null
                    rm -f /etc/fstab.syspro.tmpbak
                    errors=$((errors + 1))
                fi
            else
                log_err "无法替换 fstab 文件"
                rm -f "$fstab_tmp" /etc/fstab.syspro.tmpbak
                errors=$((errors + 1))
            fi
        fi
    fi

    # --- 1.2 I/O 调度器优化 (Udev 规则 - 核心修改) ---
    if command -v udevadm >/dev/null 2>&1; then
        local rules_new="/etc/udev/rules.d/60-syspro-io-scheduler.rules"
        local rules_old="/etc/udev/rules.d/60-io-scheduler.rules"

        # 旧版本用的是社区脚本的通用文件名 60-io-scheduler.rules。
        # 直接覆盖会让别人的规则说没就没，所以: 认得出是自己写的（带 SysPro 标记）
        # 才删；认不出就备份成 .syspro-legacy.bak，原件一个字节都不动。
        if [ -f "$rules_old" ]; then
            if grep -q 'SysPro' "$rules_old" 2>/dev/null; then
                rm -f "$rules_old"
            else
                [ -f "${rules_old}.syspro-legacy.bak" ] || \
                    cp -p "$rules_old" "${rules_old}.syspro-legacy.bak" 2>/dev/null
                log_warn "检测到非本脚本的 $rules_old，已备份为 .syspro-legacy.bak 并保留原件"
            fi
        fi

        # 名字按实际内核能力选，不再假定 none / mq-deadline 一定存在
        local sched_fast sched_disk
        sched_fast=$(detect_scheduler_name none noop 2>/dev/null)
        sched_disk=$(detect_scheduler_name mq-deadline deadline bfq cfq 2>/dev/null)

        if [ -z "$sched_fast" ] && [ -z "$sched_disk" ]; then
            log_warn "无法探测可用的 I/O 调度器名称（无块设备？），跳过规则写入。"
        elif {
            echo '# SysPro v5.9 - I/O 调度与预读'
            echo '# 仅对整盘生效 (ENV{DEVTYPE}=="disk")，避免对 sda1 这类分区写入不存在的属性'
            echo '# 调度器名字由运行时探测得出: 3.10 老内核没有 none / mq-deadline。'
            echo
            if [ -n "$sched_fast" ]; then
                echo '# 1. NVMe SSD & 虚拟磁盘 (VPS/KVM)'
                printf 'ACTION=="add|change", KERNEL=="nvme[0-9]*n[0-9]*|vd[a-z]*", ENV{DEVTYPE}=="disk", ATTR{queue/scheduler}="%s"\n' "$sched_fast"
                echo
            fi
            if [ -n "$sched_disk" ]; then
                echo '# 2. 物理 SATA SSD / 机械硬盘 / SD卡与 eMMC (树莓派)'
                printf 'ACTION=="add|change", KERNEL=="sd[a-z]*|mmcblk[0-9]*", ENV{DEVTYPE}=="disk", ATTR{queue/scheduler}="%s"\n' "$sched_disk"
                echo
            fi
            echo '# 3. 减少预读 (Read-ahead)'
            echo '#    注意: bdi/read_ahead_kb 在 Linux 5.18 已被移除，必须写 queue/read_ahead_kb，'
            echo '#          否则新内核上这条规则会静默失效（v5.3 的老问题）。'
            printf 'ACTION=="add|change", KERNEL=="vd[a-z]*|sd[a-z]*", ENV{DEVTYPE}=="disk", ATTR{queue/read_ahead_kb}="256"\n'
        } > "$rules_new" 2>/dev/null; then
            chmod 644 "$rules_new"
            state_put "$FLAG_UDEV_RULES" "$rules_new"
            if udevadm control --reload && udevadm trigger --subsystem-match=block; then
                log_success "I/O 调度器规则已更新 (fast=${sched_fast:-不可用}, disk=${sched_disk:-不可用})。"
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
    local KERNEL_MAJOR KERNEL_MINOR
    KERNEL_MAJOR=$(uname -r | cut -d. -f1)
    KERNEL_MINOR=$(uname -r | cut -d. -f2)
    
    if [ "$KERNEL_MAJOR" -lt 5 ] || { [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 6 ]; }; then
        smart_pkg_update
        if [ "$RELEASE_FAMILY" = "rpm" ]; then
            pkg_install epel-release haveged || log_warn "haveged 安装失败（EPEL 可能不可用），已跳过"
        else
            pkg_install haveged || log_warn "haveged 安装失败，已跳过"
        fi
        # 只有确实装上了才启用，避免留下一个 failed 状态的服务
        if [ -x /usr/sbin/haveged ] || have haveged; then
            systemctl enable haveged --now >/dev/null 2>&1 || log_warn "haveged 启用失败"
        fi
    fi

    # --- 2.2 内核调度器参数 (按内核实际支持的 key 写入) ---

    local cfs_conf="/etc/sysctl.d/97-syspro-latency.conf"
    {
        echo '# SysPro v5.4 - 调度器参数'
        echo '#'
        echo '# 不再写入 sched_latency_ns / sched_min_granularity_ns /'
        echo '# sched_wakeup_granularity_ns: 这些键在 6.x (EEVDF) 已被 sched_base_slice'
        echo '# 取代，写入只会报 No such file or directory；而且把调度周期压到几毫秒'
        echo '# 属于"低延迟"取向，会增加上下文切换，对网络吞吐是负优化。'
        echo '#'
        echo '# 也不写 sched_rt_runtime_us = -1（彻底关闭 RT 节流），一旦有实时任务'
        echo '# 死循环会直接锁死整机；950000 本来就是内核默认值。'
        echo
        if [ -e /proc/sys/kernel/sched_autogroup_enabled ]; then
            # 关掉按会话分调度组，避免登录/退出改变进程组权重
            snapshot_sysctl kernel.sched_autogroup_enabled
            echo 'kernel.sched_autogroup_enabled = 0'
        fi
    } > "$cfs_conf"

    if grep -q '^kernel\.' "$cfs_conf" 2>/dev/null; then
        if sysctl -p "$cfs_conf" >/dev/null 2>&1; then
            log_success "调度器参数已应用 (Autogroup Disabled)。"
        else
            log_err "调度器参数写入失败，请检查 $cfs_conf"
        fi
    else
        log_warn "当前内核没有可调的 CFS 参数（EEVDF 内核属正常现象），已跳过。"
        rm -f "$cfs_conf"
    fi

    # --- 2.3 CPU 频率策略 ---
    # 原 governor 先记进快照，卸载时按原值还原。
    # 旧版本"只改不还"，卸载后机器会一直卡在 performance + C0。
    if [ "${CPU_GOVERNOR_MODE:-1}" = "1" ]; then
        local g0
        g0=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null)
        [ -n "$g0" ] && state_put "$KEY_GOVERNOR" "$g0"

        log_info "正在锁定 CPU 频率为 Performance 模式..."

        # 方法 A: 使用 cpupower (如果可用)
        if command -v cpupower >/dev/null 2>&1; then
            cpupower frequency-set -g performance >/dev/null 2>&1
        fi

        # 方法 B: 直接修改 Sysfs (更可靠，适配所有 Linux 发行版)
        local success_count=0
        for cpu_gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            if [ -w "$cpu_gov" ]; then
                if echo "performance" > "$cpu_gov" 2>/dev/null; then
                    success_count=$((success_count + 1))
                fi
            fi
        done

        if [ "$success_count" -gt 0 ]; then
            log_success "已强制锁定 $success_count 个核心为 Performance 模式。"
        else
            log_warn "无法修改 CPU 频率 (可能受母机限制)，已尝试但无权操作。"
        fi
    else
        log_info "CPU 频率策略已关闭 (CPU_GOVERNOR_MODE=0)，保持系统默认。"
    fi

    # --- 2.4 深度 C-State ---
    # 关闭 C1 以上状态能压低唤醒延迟，代价是空闲功耗/温度明显上升。
    # 在笔记本、小主机、被动散热的 ARM 板上容易把机器烤热，所以默认关闭、
    # 只在明确开启时才动，并且必须在卸载时能用 idle-set -E 撤回来。
    if [ "${CPU_DISABLE_DEEP_CSTATES:-0}" = "1" ]; then
        if command -v cpupower >/dev/null 2>&1; then
            if cpupower idle-set -D 2 >/dev/null 2>&1; then
                state_put "$FLAG_CSTATES" "1"
                log_success "已禁用 C1 以上深度 C-State（延迟优先）。"
                log_warn "注意: 空闲功耗与温度会明显上升，且需重启才能完全恢复。"
            else
                log_warn "cpupower 无法调整 C-State（虚拟机内通常被拒绝）。"
            fi
        else
            log_warn "未安装 cpupower，跳过 C-State 调整。"
        fi
    else
        log_info "保持内核默认 C-State（CPU_DISABLE_DEEP_CSTATES=0）。"
    fi
}

# ==============================================================================
#   模块 3-1: Systemd 全局配置与进程保护
# ==============================================================================
optimize_systemd() {
    log_info "优化 Systemd 全局配置与削减系统开销..."
    
    # --- 3.0 禁用 Auditd (审计服务) [新增关键步骤] ---
    # 原因: Auditd 会 Hook 每一个系统调用(Syscall)来记录日志。
    # 在高并发网络下(如 nftx_auto.sh 跑分/压测时)，这会极大拖慢 Socket 读写速度。
    if systemctl is-active auditd >/dev/null 2>&1 || systemctl is-enabled auditd >/dev/null 2>&1; then
        log_info "正在禁用 auditd 审计服务 (消除 Syscall 钩子延迟)..."
        # 记下原始状态，卸载时按原样还原（别人可能本来就是 disabled）
        svc_snapshot auditd
        systemctl stop auditd >/dev/null 2>&1
        systemctl disable auditd >/dev/null 2>&1
        # 只 disable 不够: auditd 常被其它 target 拉起，必须 mask 才能保证重启后不启动
        systemctl mask auditd >/dev/null 2>&1
        touch "$MARK_AUDIT"

        # 注意: 这里绝对不要往 sysctl.d 写 "audit=0"。它是内核启动参数，不是 sysctl 键，
        # 写进 /etc/sysctl.d/*.conf 会让每次 sysctl --system 都报 "unknown key"，
        # 进而让 systemd-sysctl.service 变红。v5.3 的老问题。
        log_success "Auditd 服务已禁用并屏蔽。"
        log_warn "提示: 关闭审计后系统不再满足等保/PCI-DSS 的日志留存要求，生产环境请慎用。"
    else
        log_info "auditd 未运行，跳过。"
    fi
    
    # --- 3.1 Systemd 全局 Limits 优化 ---
    # 具体数值统一由 align_systemd_limits 决定（与 nftx 的天花板对齐），
    # 避免这里一套、nftx 协同模块里又一套，两处迟早漂移。
    align_systemd_limits
    
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
        # v5.3 用 list-unit-files 的退出码判断服务是否存在，但这个命令"匹配不到"
        # 时同样返回 0，判断永远成立，于是给不存在的服务也建了 drop-in。
        # 必须检查输出内容。
        if systemctl list-unit-files "${service_name}.service" 2>/dev/null \
             | grep -q "^${service_name}\.service"; then
            if mkdir -p "$override_dir" && \
               printf '[Service]\nOOMScoreAdjust=%s\n' "$protect_val" > "${override_dir}/99-syspro-oom.conf"; then
                return 0
            fi
        fi
        return 1
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
    log_info "检查 Systemd 用户会话保留策略 (KillUserProcesses)..."

    if [ -f /etc/systemd/logind.conf ]; then
        [ ! -f /etc/systemd/logind.conf.syspro.bak ] && \
            cp -p /etc/systemd/logind.conf /etc/systemd/logind.conf.syspro.bak

        if grep -q '^KillUserProcesses=no' /etc/systemd/logind.conf; then
            log_info "KillUserProcesses 已是 no（现代 systemd 默认值），无需修改。"
        else
            sed -i 's/^#\?KillUserProcesses.*/KillUserProcesses=no/' /etc/systemd/logind.conf
            if grep -q '^KillUserProcesses=no' /etc/systemd/logind.conf; then
                # 这里刻意不重启 systemd-logind:
                # 重启会重建会话对象，在部分 systemd 版本上会连带终止该会话下的进程
                # （包括正在运行的优化任务，甚至当前 SSH 会话）。下次登录/开机生效即可。
                log_success "Logind 策略已更新: 重启后后台任务不再因登出被清理。"
            else
                log_warn "logind.conf 中没有 KillUserProcesses 字段，已跳过。"
            fi
        fi
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

# 判断 /etc/systemd/system/zram.service 是不是本脚本写的。
# 只认 unit 内容里的签名（Description 含 SysPro + ExecStart 指向我们的脚本），
# 不再"文件存在就当成自己的" —— zram.service 是极常见的用户自建文件名，
# 而注释里明明写着"不要动用户的 zram-tools"，条件却把这句话否掉了。
is_syspro_zram_unit() {
    local u="/etc/systemd/system/zram.service"
    [ -f "$u" ] || return 1
    grep -q 'SysPro' "$u" 2>/dev/null || return 1
    grep -q 'ExecStart=/usr/local/bin/zram-start.sh' "$u" 2>/dev/null || return 1
    return 0
}

optimize_memory() {
    log_info "正在优化内存结构 (网络吞吐优先模式 / 修复长期衰减)..."
    local errors=0
    
    # --- 1. 获取物理内存大小 (MB) ---
    # 不用 free -m 解析: 非英文 locale 下表头是本地化的（如 "Speicher:"），
    # awk '/Mem:/' 会直接取不到值。/proc/meminfo 的字段名永远不变。
    MEM_TOTAL_MB=$(awk '/^MemTotal:/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null)
    if [ -z "$MEM_TOTAL_MB" ] || [ "$MEM_TOTAL_MB" -eq 0 ]; then
        log_err "无法获取物理内存大小"
        return 1
    fi
    HAS_ZRAM=0

    # --- 2. ZRAM 策略调整 ---
    if [ "$MEM_TOTAL_MB" -gt "$MIN_MEM_FOR_ZRAM" ]; then
        log_info "物理内存充足 (>${MIN_MEM_FOR_ZRAM}MB)，不使用 ZRAM..."
        # 只清理本脚本自己装的东西，不要动用户的 zram-tools / zram-generator。
        # 判据必须是"标记文件"或"unit 内容里的签名"，不能只看文件名还在不在。
        if [ -f "$MARK_ZRAM" ] || is_syspro_zram_unit; then
            # FIX-P0-3: swapoff 失败说明换出页还没读回内存。此时若照旧删掉
            # zram.service 与标记文件，下次运行就"忘记"zram 仍在，会把 swappiness
            # 写回 10 导致 zram 闲置、小内存机器易 OOM；设备在重启前被 reset 还会
            # 真正丢掉驻留页。所以卸载失败时保留 unit 与标记，等下次能成功时再删。
            local zram_busy=0
            if grep -q '^/dev/zram0' /proc/swaps 2>/dev/null; then
                if swapoff /dev/zram0 >/dev/null 2>&1; then
                    :
                else
                    zram_busy=1
                    log_warn "zram 仍有页面占用，未能卸载；保留配置与标记，待下次重试"
                fi
            fi
            if [ "$zram_busy" -eq 0 ]; then
                systemctl disable --now zram >/dev/null 2>&1
                rm -f /etc/systemd/system/zram.service /usr/local/bin/zram-start.sh "$MARK_ZRAM"
                systemctl daemon-reload 2>/dev/null
                log_info "已移除本脚本创建的 ZRAM 配置。"
            fi
        elif [ -f /etc/systemd/system/zram.service ]; then
            log_info "检测到非本脚本创建的 zram.service，已保留。"
        fi
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
# SysPro ZRAM 启动脚本 (v5.4)
modprobe zram num_devices=1 || exit 1
[ -e /sys/block/zram0 ] || sleep 1
[ -e /sys/block/zram0 ] || exit 1

# 已经启用过就直接退出，避免重复 mkswap 覆盖正在使用的 swap
grep -q '^/dev/zram0' /proc/swaps 2>/dev/null && exit 0

[ -f /sys/block/zram0/reset ] && echo 1 > /sys/block/zram0/reset 2>/dev/null
echo "$ALGO" > /sys/block/zram0/comp_algorithm 2>/dev/null
echo "${ZRAM_SIZE}M" > /sys/block/zram0/disksize || exit 1
mkswap /dev/zram0 >/dev/null 2>&1 || exit 1
swapon -p 100 /dev/zram0 || exit 1
EOF
                then
                    chmod +x /usr/local/bin/zram-start.sh
                    
                    if cat > /etc/systemd/system/zram.service <<EOF
[Unit]
Description=SysPro Lightweight ZRAM
# swap 必须在多用户之前就位。原来的 "After=multi-user.target + WantedBy=multi-user.target"
# 等于把自己排在目标之后，实际要等系统起来很久才生效。
DefaultDependencies=no
After=local-fs.target
Before=swap.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/zram-start.sh

[Install]
WantedBy=swap.target
EOF
                    then
                        systemctl daemon-reload
                        if systemctl enable zram --now >/dev/null 2>&1; then
                            HAS_ZRAM=1
                            touch "$MARK_ZRAM"
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
    # 有 ZRAM 时不能再用 10: zram 是压缩内存，"少换出"等于把它闲置，
    # 小内存机器会直接 OOM。zram 场景用 100 让内核积极压缩换出。
    local swap_val="$SWAPPINESS_VALUE"
    [ "${HAS_ZRAM:-0}" -eq 1 ] && swap_val=100

    snapshot_sysctl vm.swappiness
    if sysctl -w vm.swappiness="$swap_val" >/dev/null 2>&1; then
        if {
            echo '# SysPro - 内存换出策略'
            echo '# 卸载时由 /var/lib/syspro/state.env 的快照还原为原值'
            if [ "${HAS_ZRAM:-0}" -eq 1 ]; then
                echo '# 已启用 ZRAM: 积极换出到压缩内存，避免小内存机器 OOM'
            else
                echo '# 无 ZRAM: TCP 缓冲区必须驻留物理内存，降低换出倾向'
            fi
            echo "vm.swappiness = $swap_val"
        } > /etc/sysctl.d/99-syspro-swap.conf; then
            chmod "$FILE_PERMISSION" /etc/sysctl.d/99-syspro-swap.conf
            if [ "${HAS_ZRAM:-0}" -eq 1 ]; then
                log_info "  - Swappiness 已设为 $swap_val（ZRAM 场景）。"
            else
                log_info "  - Swappiness 已锁定为 $swap_val。"
            fi
        else
            log_err "无法保存 swappiness 配置"
            errors=$((errors + 1))
        fi
    else
        log_err "无法设置 swappiness"
        errors=$((errors + 1))
    fi

    # --- 4. 保底磁盘 Swap ---
    # 同样避开 free -m 的本地化表头问题
    CURRENT_SWAP_MB=$(awk '/^SwapTotal:/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null)
    CURRENT_SWAP_MB=${CURRENT_SWAP_MB:-0}
    if [ "$CURRENT_SWAP_MB" -ge "$MIN_SWAP_REQUIRED" ] || [ "$MEM_TOTAL_MB" -gt "$MAX_MEM_FOR_SWAP" ]; then
        log_info "Swap 已存在或内存充足，跳过 Swap 创建。"
        return 0
    fi

    # 已经存在 /swapfile 但不是本脚本创建的 → 绝不覆盖用户数据
    if [ -f /swapfile ] && [ ! -f "$MARK_SWAP" ]; then
        log_warn "检测到已存在的 /swapfile（非本脚本创建），为避免破坏用户数据，跳过创建。"
        return 0
    fi

    # 本脚本创建过、且现在正作为 swap 在用 → 保持原样，不要重建。
    # 旧版本会直接 rm -f 再重建: 对"正在使用中的 swapfile"执行 rm，
    # 内核仍持有那个 inode（空间不释放），随后新建的文件再 swapon 会报
    # "Device or resource busy"，或者悄悄多出一份 1GB swap 直到重启。
    if [ -f /swapfile ] && [ -f "$MARK_SWAP" ] && \
       grep -q '^/swapfile[[:space:]]' /proc/swaps 2>/dev/null; then
        log_info "本脚本创建的 /swapfile 已在启用中，跳过重建。"
        return 0
    fi

    log_warn "系统无 Swap 且内存较小，正在创建保底 Swap..."
    SIZE=$SWAP_FILE_SIZE

    DISK_AVAIL=$(df -m / | awk 'NR==2 {print $4}')
    if [ -z "$DISK_AVAIL" ] || [ "$DISK_AVAIL" -lt 2048 ]; then
        log_err "磁盘空间不足（可用 ${DISK_AVAIL:-0}MB），跳过 Swap 创建。"
        return 0
    fi

    # 重建前再确认一次旧文件确实没在被使用。
    # 注意必须先看 /proc/swaps: 对"没启用的普通文件"调 swapoff 会直接报
    # Invalid argument，误判成"正在使用"就会永远重建不了。
    if [ -f /swapfile ] && grep -q '^/swapfile[[:space:]]' /proc/swaps 2>/dev/null; then
        if ! swapoff /swapfile >/dev/null 2>&1; then
            log_warn "/swapfile 仍在使用中（swapoff 失败），跳过重建以免破坏现有 Swap。"
            return 0
        fi
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
            if ! grep -q "^/swapfile" /etc/fstab; then
                echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
            fi
            # 标记"这个 swapfile 是本脚本创建的"，卸载时据此决定是否删除
            touch "$MARK_SWAP"
            log_success "保底磁盘 Swap (${SIZE}MB) 已创建。"
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

    local sec_conf="/etc/sysctl.d/98-syspro-security.conf"

    {
        echo '# SysPro v5.9 - 内核安全加固'
        echo '#'
        echo '# 每一项都逐键探测过（老内核缺键时不落盘，避免开机 systemd-sysctl 报错）。'
        echo '# 卸载时按 /var/lib/syspro/state.env 的快照逐条还原，'
        echo '# 不再套用硬编码的"发行版默认值"——RHEL 的 sysrq 默认是 16，'
        echo '# Debian 是 438，写死任何一个都会在另一边的机器上制造新问题。'
        echo
    } > "$sec_conf"

    # 限制暴露内核指针地址 (防止内核漏洞利用)
    snapshot_sysctl kernel.kptr_restrict
    emit_sysctl "$sec_conf" kernel.kptr_restrict 2

    # 限制普通用户读取 dmesg 日志
    snapshot_sysctl kernel.dmesg_restrict
    emit_sysctl "$sec_conf" kernel.dmesg_restrict 1

    # SysRq: 只保留 sync(16) + remount-ro(32) + reboot(128) = 176
    # 为什么不是 16: nftx 会在线改 qdisc / 绑中断，一旦网卡队列改坏，
    # SysRq-b 是云控制台之外唯一的远程自救手段。
    snapshot_sysctl kernel.sysrq
    emit_sysctl "$sec_conf" kernel.sysrq 176

    # ICMP 策略:
    #   默认(0) 什么都不写 —— 内核本来就会响应 ping，我们没有任何理由去"改回"它。
    #   旧版本在这里显式写 icmp_echo_ignore_all = 0，等于把管理员自己做的
    #   "禁 ping" 加固反向打开，属于越权修改，已移除。
    if [ "${SECURITY_BLOCK_ICMP:-0}" = "1" ]; then
        snapshot_sysctl net.ipv4.icmp_echo_ignore_all
        emit_sysctl "$sec_conf" net.ipv4.icmp_echo_ignore_all 1
    fi

    chmod 644 "$sec_conf" 2>/dev/null

    if sysctl_file_has_keys "$sec_conf"; then
        if sysctl -p "$sec_conf" >/dev/null 2>&1; then
            log_success "内核安全参数已加载。"
            if [ "${SECURITY_BLOCK_ICMP:-0}" = "1" ]; then
                log_warn "  - 已按配置屏蔽 ICMP 回显（云厂商探活/监控可能误判宕机）"
            else
                log_info "  - 未改动 ICMP 策略（保持系统原设置；如需屏蔽请把 SECURITY_BLOCK_ICMP 改为 1）"
            fi
        else
            log_err "无法加载内核安全参数"
        fi
    else
        rm -f "$sec_conf"
        log_warn "当前内核不支持任何安全加固键，已跳过。"
    fi
    return 0
}

# ==============================================================================
#   模块 4-B: nftx 协同层 (Network Fast-Path)
#
#   【定位: 只搭房间，不做 nftx 的家私】
#   nftx_auto 负责「按实测 带宽×RTT×并发 把参数推到当前链路的最优」，
#   本模块只负责「让这些参数有空间可推」。两者是"下限"与"动态最优"的关系，
#   不存在重叠:
#     房间 = 容量地板（下面 9 项）+ 模块可用性 + systemd 限制 + OOM 保护
#     家具 = qdisc / 拥塞控制 / 收发缓冲 / 在途上限 / 端口范围 / RPS / 中断
#            —— 一个都不写，由 assert_reserved_untouched 每次实扫保证
#
#   【常见顺序是 syspro 先跑、nftx 后装】
#   所以本模块在"完全没装 nftx"的机器上必须独立成立:
#     - 地板值都是"内核默认值不足"的安全下界，跟 nftx 在不在都有益
#     - drop-in 无条件预留（systemd 对没有对应 unit 的 .d 目录是静默忽略的）
#     - 将来装上 nftx，第一次 daemon-reload 就自动吃到全部预留资源
#
#   nftx_auto 的工作方式: 实测 带宽/RTT/CPU/内存/PPS/并发 → 推导 缓冲区、队列、
#   tcp_mem、RPS、中断绑定 → 应用 → 按重传率上下调增益。它的天花板完全取决于
#   "系统在它接手之前处于什么状态"。所以本模块只做三件事:
#
#     1. 预载 sch_fq / sch_cake / tcp_bbr —— nftx 首次 apply 时 tc 能直接建队列，
#        不会因为模块还没 autoload 而退回 fq_codel（丢掉带权整形和 ack-filter）
#     2. 持久化"容量型地板值" —— 开机到 nftx 启动之间有一段时间窗，
#        系统默认值（老内核 somaxconn=128、netdev_budget=300、file-max 偏低）
#        会先丢一批包，nftx 首轮采到的 PPS 与重传率就是被污染的数据
#     3. 对齐 systemd 限制 —— NOFILE/NPROC 不低于 nftx 上限，停止超时放宽到
#        能写完 model.state
#
#   【刻意不做】以下参数全部由 nftx 按"实测 带宽×RTT"动态接管，写死等于把它的
#   上限压成常量，因此 syspro 一个都不写:
#     net.core.default_qdisc          —— nftx 明确禁止持久化: 该值在网卡注册前
#                                        生效，若 sch_cake/sch_fq 那时未加载，
#                                        新建网卡会拿到 noqueue，整机直接失联
#     net.ipv4.tcp_congestion_control —— 由 nftx 的 apply_cc_once 决定（可能是 bbrplus）
#     net.core.rmem_max / wmem_max、net.ipv4.tcp_rmem / tcp_wmem
#     net.ipv4.tcp_limit_output_bytes / tcp_notsent_lowat / tcp_max_tw_buckets
#     net.ipv4.ip_local_port_range、net.core.busy_poll / busy_read
# ==============================================================================

# nftx_auto 是否已安装
detect_nftx() {
    [ -d /etc/nftx_auto ] && return 0
    [ -f /etc/systemd/system/nftx_auto.service ] && return 0
    have nftx_auto.sh && return 0
    return 1
}

# ------------------------------------------------------------------------------
#   nftx 独占参数域（"家具"清单）
#
#   边界约定:
#     房间（本模块写）= 容量地板 —— 这 8 项不存在时，机器连"正常待客"都做不到，
#                       而且它们在 nftx 启动之前就必须成立
#     家具（nftx 写）= 下面这些 —— 全部由 nftx 按"实测 带宽×RTT×并发"动态推导，
#                       syspro 写死任何一个，都等于把它的上限压成常量
#
#   这份清单不是为了"我记得别写"，而是给 assert_reserved_untouched 用来
#   每次实扫自己落盘的文件 —— 有人手工加过、或旧版本遗留，都会被清掉并报出来。
# ------------------------------------------------------------------------------
NFTX_RESERVED_KEYS=(
    net.core.default_qdisc
    net.ipv4.tcp_congestion_control
    net.core.rmem_max
    net.core.wmem_max
    net.core.rmem_default
    net.core.wmem_default
    net.ipv4.tcp_rmem
    net.ipv4.tcp_wmem
    net.ipv4.tcp_limit_output_bytes
    net.ipv4.tcp_notsent_lowat
    net.ipv4.tcp_max_tw_buckets
    net.ipv4.ip_local_port_range
    net.core.busy_poll
    net.core.busy_read
    net.core.rps_sock_flow_entries
    net.ipv4.tcp_fastopen
    net.ipv4.tcp_slow_start_after_idle
    net.ipv4.tcp_mtu_probing
    net.ipv4.tcp_ecn
    net.ipv4.tcp_autocorking
    net.ipv4.tcp_adv_win_scale
    net.ipv4.tcp_moderate_rcvbuf
    net.ipv4.tcp_base_mss
    net.ipv4.tcp_no_metrics_save
    net.ipv4.tcp_keepalive_time
    net.ipv4.tcp_keepalive_probes
    net.ipv4.tcp_keepalive_intvl
    net.ipv4.tcp_fin_timeout
    net.ipv4.tcp_syn_retries
    net.ipv4.tcp_retries2
    net.ipv4.tcp_max_orphans
    net.ipv4.neigh.default.gc_thresh1
    net.ipv4.neigh.default.gc_thresh2
    net.ipv4.neigh.default.gc_thresh3
    net.ipv4.udp_rmem_min
    net.ipv4.udp_wmem_min
    net.ipv4.udp_mem
    net.netfilter.nf_conntrack_max
    net.netfilter.nf_conntrack_tcp_timeout_established
    net.netfilter.nf_conntrack_tcp_timeout_time_wait
    vm.vfs_cache_pressure
)

# 自检 + 自动纠偏：扫描 syspro 自己写的所有 sysctl 文件，删掉任何越界键。
assert_reserved_untouched() {
    local f k pat hits=0
    for f in /etc/sysctl.d/95-syspro-silence.conf \
             /etc/sysctl.d/96-syspro-netfloor.conf \
             /etc/sysctl.d/97-syspro-latency.conf \
             /etc/sysctl.d/98-syspro-security.conf \
             /etc/sysctl.d/99-syspro-swap.conf; do
        [ -f "$f" ] || continue
        for k in "${NFTX_RESERVED_KEYS[@]}"; do
            pat="^[[:space:]]*${k//./\\.}[[:space:]]*="
            if grep -qE "$pat" "$f" 2>/dev/null; then
                sed -i "/${pat}/d" "$f" 2>/dev/null
                log_warn "  - 已从 ${f##*/} 移除 $k（该参数属于 nftx 的动态域）"
                hits=$((hits + 1))
            fi
        done
    done
    if [ "$hits" -gt 0 ]; then
        log_info "  - 越界参数已清理，共 $hits 条（这些键交给 nftx 运行时决定）"
    fi
    return 0
}

# systemd 全局限制对齐
# 单独成函数，是因为 optimize_systemd 和 optimize_net_floor 都要保证它成立，
# 而两边各写一遍必然漂移。
align_systemd_limits() {
    if [ ! -f /etc/systemd/system.conf ]; then
        log_warn "未找到 /etc/systemd/system.conf，跳过 systemd 限制对齐。"
        return 1
    fi

    [ ! -f /etc/systemd/system.conf.syspro.bak ] && \
        cp -p /etc/systemd/system.conf /etc/systemd/system.conf.syspro.bak

    # 停止超时 15s（不是 5s）:
    # nftx_auto-model.service 是 oneshot，正在写 model.state 时被 SIGKILL 会把
    # 校准进度截断；5s 对任何需要落盘的 oneshot 都太紧。
    sed -i -e 's/^#\?DefaultTimeoutStopSec=.*/DefaultTimeoutStopSec=15s/' /etc/systemd/system.conf

    # 句柄上限对齐 nftx 的天花板（它的 NOFILE 上限就是 1048576），
    # 但不得超过内核 fs.nr_open，否则 systemd 会告警并自行钳制。
    local nr_open_lim nofile_lim
    nr_open_lim=$(sysctl -n fs.nr_open 2>/dev/null)
    case "$nr_open_lim" in ''|*[!0-9]*) nr_open_lim=$NET_NOFILE_CEIL ;; esac
    nofile_lim=$NET_NOFILE_CEIL
    [ "$nr_open_lim" -lt "$nofile_lim" ] && nofile_lim=$nr_open_lim

    # NPROC 给到 nftx 的上限 65536。不要给到 100 万，那等于放开 fork 炸弹。
    sed -i 's/^#\?DefaultLimitNOFILE=.*/DefaultLimitNOFILE='"$nofile_lim"'/' /etc/systemd/system.conf
    sed -i 's/^#\?DefaultLimitNPROC=.*/DefaultLimitNPROC='"$NET_NPROC_CEIL"'/' /etc/systemd/system.conf

    # 服务的 core dump 由 systemd 的 DefaultLimitCORE 决定；
    # /etc/security/limits.d 只对 PAM 会话生效 —— 只写 limits.d 的话，
    # nginx / mysql 这类由 systemd 拉起的服务照样会产生 core 文件。
    # 这里补上，才真正做到"程序崩溃不写盘"。原值随 system.conf.syspro.bak 一起备份。
    sed -i 's/^#\?DefaultLimitCORE=.*/DefaultLimitCORE=0/' /etc/systemd/system.conf

    if grep -q '^DefaultLimitNOFILE=' /etc/systemd/system.conf; then
        log_success "Systemd 限制已对齐 nftx: NOFILE=${nofile_lim} / NPROC=${NET_NPROC_CEIL}"
    else
        log_warn "当前 systemd 不支持 DefaultLimitNOFILE（版本过旧），已跳过该项。"
    fi

    systemctl daemon-reload 2>/dev/null
    return 0
}

# 给 nftx_auto.service 挂 drop-in
#
# 这里刻意"无条件"创建，而不是等检测到 nftx 才建:
#   常见顺序是「先跑 syspro 调好系统 → 过几天才装 nftx」。如果只在检测到 nftx
#   时才写 drop-in，那个用户就永远拿不到这份配置（他不会再跑一次 syspro）。
#   systemd 对"没有对应 unit 的 .d 目录"是静默忽略的，所以提前放好没有任何副作用，
#   装上 nftx 后第一次 daemon-reload 就自动生效。
# 另外 nftx 每次 update 会重写自己的 unit 文件，但不会碰 drop-in 目录，
# 所以这份配置不会被它覆盖。
install_nftx_dropin() {
    local d="${NFTX_DROPIN%/*}" nofile_lim cur
    # 与 align_systemd_limits 用同一套钳制: LimitNOFILE 不能超过内核 fs.nr_open，
    # 否则 systemd 会告警并自行钳到上限（旧版本这里直接写死 1048576）。
    nofile_lim=$NET_NOFILE_CEIL
    cur=$(sysctl -n fs.nr_open 2>/dev/null)
    case "$cur" in
        ''|*[!0-9]*) ;;
        *) [ "$cur" -lt "$nofile_lim" ] && nofile_lim=$cur ;;
    esac

    if mkdir -p "$d" && cat > "$NFTX_DROPIN" <<EOF
# 由 SysPro 写入（nftx_auto 的 update 只重写主 unit，不会动 drop-in）
[Service]
# 校准进程被 OOM 杀掉 = 参数停在"应用了一半"的状态，比不优化更糟
OOMScoreAdjust=-500
LimitNOFILE=$nofile_lim
LimitNPROC=$NET_NPROC_CEIL
EOF
    then
        systemctl daemon-reload 2>/dev/null
        if detect_nftx; then
            log_info "  - 已为 nftx_auto.service 挂资源 drop-in（OOM 保护 + 句柄上限）"
        else
            log_info "  - 已预留 nftx_auto.service 的 drop-in（将来装 nftx 时自动生效，无需重跑）"
        fi
    else
        log_warn "  - 无法写入 $NFTX_DROPIN"
    fi
}

optimize_net_floor() {
    if [ "${NFTX_AWARE:-1}" != "1" ]; then
        log_info "nftx 协同已关闭 (NFTX_AWARE=0)，跳过。"
        return 0
    fi

    log_info "正在为 nftx 准备网络快通道底座..."
    local errors=0
    local ram_mb mods="" m

    ram_mb=$(awk '/^MemTotal:/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null)
    case "$ram_mb" in ''|*[!0-9]*) ram_mb=1024 ;; esac

    # --- 1. 模块预载 ---
    # bbrplus 内核把 tcp_bbrplus 编进内核 (CONFIG_TCP_CONG_BBRPLUS=y)，没有独立 .ko，
    # modprobe 对它没有意义。用内核导出的 tcp_available_congestion_control 判真实可用性，
    # 否则换了 bbrplus 内核后会误报"内核未提供 tcp_bbr，nftx 将退回 cubic"。
    local avail_cc="" builtin_cc=""
    avail_cc=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null)
    case " $avail_cc " in *" bbrplus "*) builtin_cc="bbrplus" ;; esac
    [ -n "$builtin_cc" ] && log_info "  - 内核已内建 bbrplus（可用拥塞控制: $avail_cc）"

    for m in sch_fq sch_cake tcp_bbr; do
        if modinfo "$m" >/dev/null 2>&1; then
            if modprobe "$m" >/dev/null 2>&1; then
                mods="$mods $m"
            else
                log_warn "  - 模块 $m 存在但加载失败（可能已内建或被黑名单）"
            fi
        fi
    done

    if [ -n "$mods" ]; then
        mkdir -p /etc/modules-load.d 2>/dev/null
        if printf '%s\n' $mods > "$NET_MODULES_CONF"; then
            log_success "已预载内核模块:${mods# }"
            log_info "  - 已写入 $NET_MODULES_CONF（重启后自动加载）"
        else
            log_err "无法写入 $NET_MODULES_CONF"
            errors=$((errors + 1))
        fi
    elif [ -n "$builtin_cc" ]; then
        log_success "拥塞控制由内核内建提供（${builtin_cc}），无需预载 .ko"
        # 旧版本可能把内建模块名写进 modules-load.d，开机时 kmod 会记一条无意义告警
        if [ -f "$NET_MODULES_CONF" ] && grep -qxF 'tcp_bbrplus' "$NET_MODULES_CONF" 2>/dev/null; then
            sed -i '/^tcp_bbrplus$/d' "$NET_MODULES_CONF" 2>/dev/null
        fi
    else
        log_warn "  - 内核未提供 sch_fq / sch_cake / tcp_bbr（nftx 将退回 fq_codel + cubic）"
    fi

    # cake 是否真的可用。
    # 注意: 不能用 `tc qdisc list | grep cake` 判断 —— 那列的是"已经挂到网卡上"的
    # 队列，cake 还没挂载时根本不会出现，必然误报"不可用"（v5.5 早期版本就错在这）。
    # 正确判据按优先级:
    #   1) /sys/module/sch_cake 存在  → 模块已加载
    #   2) modinfo 能查到             → 模块可加载
    #   3) kallsyms 里有 cake_qdisc_ops → 编译进内核（CONFIG_NET_SCH_CAKE=y）
    local cake_ok=0
    if [ -d /sys/module/sch_cake ]; then
        cake_ok=1
    elif have modinfo && modinfo sch_cake >/dev/null 2>&1; then
        cake_ok=1
    elif [ -r /proc/kallsyms ] && grep -qw cake_qdisc_ops /proc/kallsyms 2>/dev/null; then
        cake_ok=1
    fi

    if ! have tc; then
        # 只提示，不代装: nftx 的依赖由它自己的 deps 子命令准备
        log_warn "  - 未安装 tc(iproute2)，nftx 的核心调优无法生效"
        log_info "    装好后运行 nftx_auto.sh deps 会自动补齐（含 iproute2 / iptables / iputils）"
    elif [ "$cake_ok" -eq 1 ]; then
        log_info "  - cake 可用（sch_cake 已就绪），nftx 会用它做整形 + ack-filter"
    else
        log_warn "  - 当前内核没有 sch_cake，nftx 将退回 fq_codel（无带宽整形，突发更高）"
    fi

    # --- 2. 计算容量地板（全部只增不减，且对齐 nftx 自己的下限）---
    local v_nr_open v_file_max v_epoll v_somax v_syn v_backlog v_budget v_bud_usec
    local tm_cur tm1 tm2 tm3 tm_floor3 v_tm

    # nftx 的 NOFILE 上限就是 1048576；nr_open 必须 >= 它，否则 setrlimit 会 EPERM
    v_nr_open=$(sysctl_at_least fs.nr_open "$NET_NOFILE_CEIL")
    v_file_max=$(sysctl_at_least fs.file-max "$NET_NOFILE_CEIL")

    # epoll: nftx 用 RAM_MB×128 起算，硬下限 262144
    v_epoll=$(sysctl_at_least fs.epoll.max_user_watches $(( ram_mb * 128 )))
    [ "$v_epoll" -lt 262144 ] && v_epoll=262144

    v_somax=$(sysctl_at_least net.core.somaxconn 4096)
    v_syn=$(sysctl_at_least net.ipv4.tcp_max_syn_backlog 4096)
    v_backlog=$(sysctl_at_least net.core.netdev_max_backlog 1000)
    # netdev_budget 默认 300 是每轮 softirq 的收包上限，600 起才不容易被截断
    v_budget=$(sysctl_at_least net.core.netdev_budget 600)
    v_bud_usec=$(sysctl_at_least net.core.netdev_budget_usecs 2000)

    # tcp_mem 高水位下限 = RAM_MB×16 页（与 nftx 的 tm3_min 一致）。
    # 只抬"偏小"的元素，已经更高的值一律不动 —— 与整体"只增不减"的规矩一致。
    # （之前写成"tm3 不够就整组重建"，会把用户已经调高的 tm1 从 30000 打回 4096。）
    tm_cur=$(sysctl -n net.ipv4.tcp_mem 2>/dev/null)
    tm1=0; tm2=0; tm3=0
    set -- $tm_cur
    case "${1:-}" in ''|*[!0-9]*) ;; *) tm1=$1 ;; esac
    case "${2:-}" in ''|*[!0-9]*) ;; *) tm2=$2 ;; esac
    case "${3:-}" in ''|*[!0-9]*) ;; *) tm3=$3 ;; esac
    tm_floor3=$(( ram_mb * 16 ))
    [ "$tm_floor3" -lt 16384 ] && tm_floor3=16384
    [ "$tm3" -lt "$tm_floor3" ] && tm3=$tm_floor3

    if [ "$tm1" -gt 0 ] && [ "$tm2" -gt 0 ] && [ "$tm1" -lt "$tm2" ] && [ "$tm2" -lt "$tm3" ]; then
        # 现有三元组本身合法（低<中<高）: 只把偏小的元素抬到比例值
        local p1 p2
        p1=$(( tm3 / 4 )); p2=$(( tm3 / 2 ))
        [ "$tm1" -lt "$p1" ] && tm1=$p1
        [ "$tm2" -lt "$p2" ] && tm2=$p2
    else
        # 读不到 / 顺序非法: 按高水位重建一组合法值
        tm1=$(( tm3 / 4 ))
        tm2=$(( tm3 / 2 ))
    fi
    v_tm="$tm1 $tm2 $tm3"

    # --- 3. 落盘（重启后由 systemd-sysctl 在 nftx 之前应用）---
    # 先记快照，卸载时按原值回滚（tcp_mem 这类三元组也必须原样记下）
    local snap_k
    for snap_k in fs.nr_open fs.file-max fs.epoll.max_user_watches \
                  net.core.somaxconn net.ipv4.tcp_max_syn_backlog \
                  net.core.netdev_max_backlog net.core.netdev_budget \
                  net.core.netdev_budget_usecs net.ipv4.tcp_mem; do
        snapshot_sysctl "$snap_k"
    done

    if {
        echo '# SysPro v5.9 - nftx 网络快通道地板值'
        echo '#'
        echo '# 本文件只写"容量型"参数，全部是"只增不减"的下限。'
        echo '# 刻意不写下面这些（全部由 nftx_auto 按实测 带宽×RTT 动态接管）:'
        echo '#   net.core.default_qdisc          开机早期模块未就绪会让网卡拿到 noqueue'
        echo '#   net.ipv4.tcp_congestion_control'
        echo '#   net.core.rmem_max / wmem_max'
        echo '#   net.ipv4.tcp_rmem / tcp_wmem / tcp_limit_output_bytes'
        echo '#   net.ipv4.tcp_notsent_lowat / tcp_max_tw_buckets / ip_local_port_range'
        echo '#   net.core.busy_poll / busy_read'
        echo '#'
        echo '# 每个键都先探测 /proc/sys 是否真的有它:'
        echo '#   fs.epoll.max_user_watches   5.11 才有'
        echo '#   net.core.netdev_budget_usecs 4.10 才有'
        echo '# 写进不支持的键，等于让每次开机的 systemd-sysctl 报 unknown key 变红'
        echo '# （这正是 v5.3 把 audit=0 写进 sysctl.d 留下的老问题）。'
        echo
    } > "$NET_FLOOR_CONF" 2>/dev/null; then
        emit_sysctl "$NET_FLOOR_CONF" fs.nr_open "$v_nr_open"
        emit_sysctl "$NET_FLOOR_CONF" fs.file-max "$v_file_max"
        emit_sysctl "$NET_FLOOR_CONF" fs.epoll.max_user_watches "$v_epoll"
        emit_sysctl "$NET_FLOOR_CONF" net.core.somaxconn "$v_somax"
        emit_sysctl "$NET_FLOOR_CONF" net.ipv4.tcp_max_syn_backlog "$v_syn"
        emit_sysctl "$NET_FLOOR_CONF" net.core.netdev_max_backlog "$v_backlog"
        emit_sysctl "$NET_FLOOR_CONF" net.core.netdev_budget "$v_budget"
        emit_sysctl "$NET_FLOOR_CONF" net.core.netdev_budget_usecs "$v_bud_usec"
        emit_sysctl "$NET_FLOOR_CONF" net.ipv4.tcp_mem "$v_tm"

        if sysctl_file_has_keys "$NET_FLOOR_CONF"; then
            chmod 644 "$NET_FLOOR_CONF" 2>/dev/null
            log_success "容量地板已写入 $NET_FLOOR_CONF"
        else
            # 一个键都写不进去时留一个纯注释文件毫无意义，删掉更干净
            rm -f "$NET_FLOOR_CONF"
            log_warn "当前内核不支持任何地板值键，已跳过落盘。"
        fi
    else
        log_err "无法写入 $NET_FLOOR_CONF"
        errors=$((errors + 1))
    fi

    # --- 4. 运行时只上调 ---
    # 关键: 绝不覆盖 nftx 已经按实测值调好的结果。sysctl_raise 只在
    # "当前值 < 地板值" 时才写，等于"只补不足，不动成果"。
    local kv k v rc
    for kv in \
        "fs.nr_open:$v_nr_open" \
        "fs.file-max:$v_file_max" \
        "fs.epoll.max_user_watches:$v_epoll" \
        "net.core.somaxconn:$v_somax" \
        "net.ipv4.tcp_max_syn_backlog:$v_syn" \
        "net.core.netdev_max_backlog:$v_backlog" \
        "net.core.netdev_budget:$v_budget" \
        "net.core.netdev_budget_usecs:$v_bud_usec"
    do
        k=${kv%%:*}
        v=${kv##*:}
        sysctl_raise "$k" "$v"
        rc=$?
        case $rc in
            0) : ;;
            # 2 = 内核没这个键。这不是故障，不该计入 errors 也不该报"容器只读"
            2) log_info "  - 内核不支持 $k，已跳过" ;;
            *) log_warn "  - $k 低于地板值且写入失败（容器只读 /proc 或权限受限？）"
               errors=$((errors + 1)) ;;
        esac
    done

    # tcp_mem 三元组单独处理（没有 sysctl_raise 的单值语义）
    local ctm3
    ctm3=$(sysctl -n net.ipv4.tcp_mem 2>/dev/null | awk '{print $3}')
    case "$ctm3" in ''|*[!0-9]*) ctm3=0 ;; esac
    if [ "$ctm3" -lt "$tm3" ]; then
        if sysctl -w "net.ipv4.tcp_mem=$v_tm" >/dev/null 2>&1; then
            log_info "  - tcp_mem 高水位已上调至 ${tm3} 页"
        else
            log_err "  - tcp_mem 写入失败"
            errors=$((errors + 1))
        fi
    fi

    # --- 5. systemd 限制对齐 + nftx drop-in ---
    align_systemd_limits || true
    install_nftx_dropin

    # --- 6. 冲突自检 ---
    local dq others
    dq=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    case "$dq" in
        fq|fq_codel|cake|"") : ;;
        *) log_warn "  - net.core.default_qdisc=$dq（建议保持 fq/cake，nftx 会给主网卡单独设队列）" ;;
    esac

    others=$(grep -rls '^[[:space:]]*net\.core\.default_qdisc' /etc/sysctl.d 2>/dev/null \
             | grep -v -F -x "$NET_FLOOR_CONF")
    if [ -n "$others" ]; then
        log_warn "  - 以下文件持久化了 net.core.default_qdisc，nftx 明确建议不要这样做:"
        printf '%s\n' "$others" | sed 's/^/      /'
    fi

    # 旧版 nftx（v4.0.5 之前）会写 /etc/sysctl.d/99-nftx_auto.conf，并把它当成隐患：
    # 那份文件由 systemd-sysctl 在开机极早期无条件应用，一旦里面有偏小的
    # conntrack/file-max，机器会在任何自检之前先失联。
    if [ -f /etc/sysctl.d/99-nftx_auto.conf ]; then
        log_warn "  - 发现旧版 nftx 遗留的 /etc/sysctl.d/99-nftx_auto.conf"
        log_warn "    新版 nftx 已不再写该文件，官方建议删除: rm -f /etc/sysctl.d/99-nftx_auto.conf"
    fi

    # --- 7. 边界自检 ---
    # 实扫自己落盘的 sysctl 文件，确认没碰 nftx 的动态参数。
    # 这是个"可验证的边界"，而不是注释里的一句承诺。
    assert_reserved_untouched

    # --- 8. 结果 ---
    if [ "$errors" -gt 0 ]; then
        log_warn "网络底座已就绪，但有 $errors 项未完全生效。"
    elif detect_nftx; then
        log_success "网络底座已就绪（nftx 已安装，它下次启动就会吃到这些资源）。"
        log_info "  - 提示: 重跑 nftx calibrate 会用新天花板重新探增益"
    else
        log_success "网络底座已就绪（当前未安装 nftx，空间已按它的标准预留）。"
        log_info "  - 模块预载 / 容量地板 / 资源 drop-in 都已落盘，将来装 nftx 无需重跑本项"
        log_info "  - 以上配置本次已即时生效，不必等重启；重启只是让它们走开机自动重放"
    fi
    return 0
}


# ==============================================================================
#   模块 5: 接入层 - Cloudflared DoH 安装与启动
# ==============================================================================

install_cloudflared() {
    log_info "开始部署 DoH 本地加密 DNS 客户端..."
    # FIX-RUNTIME-2: 后端选择器。cloudflared 新版已移除 proxy-dns，自动降级到
    # dnscrypt-proxy；两者对外接口一致（syspro-doh.service 监听 DOH_LISTEN_ADDR:53）。
    local doh_backend="cloudflared"

    # FIX-P1-7: AmbientCapabilities= 需要 systemd 229+。CentOS 7 是 systemd 219，
    # 该指令不识别会导致 unit 加载失败、DoH 部署整个退回 UDP。
    # 旧 systemd 改用 Capabilities=...+ep + SecureBits=keep-caps 达到同样效果。
    local cap_lines sd_ver=0
    sd_ver=$(systemctl --version 2>/dev/null | awk 'NR==1 {print $2}')
    case "$sd_ver" in ''|*[!0-9]*) sd_ver=0 ;; esac
    if [ "$sd_ver" -ge 229 ]; then
        cap_lines="AmbientCapabilities=CAP_NET_BIND_SERVICE"
    else
        cap_lines="Capabilities=CAP_NET_BIND_SERVICE+ep
SecureBits=keep-caps"
        log_info "  - systemd ${sd_ver} 较旧，使用 Capabilities= 替代 AmbientCapabilities="
    fi

    # --- 0. 依赖检查 ---
    # 旧版本要等到"模块 6 维护清理"才安装 curl，而这里第 3 行就要用它，
    # 最小化镜像上 DoH 必然失败，用户还会以为是网络问题。
    if ! have curl; then
        log_info "未找到 curl，正在安装必要依赖..."
        smart_pkg_update
        if ! pkg_install curl ca-certificates >/dev/null 2>&1; then
            log_err "无法安装 curl / ca-certificates，DoH 部署中止"
            return 1
        fi
    fi
    if ! have curl; then
        log_err "curl 仍然不可用，DoH 部署中止"
        return 1
    fi

    # --- 1. 架构判断与下载 (保持不变) ---
    case $ARCH in
        amd64) URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64" ;;
        arm64) URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64" ;;
        armhf) URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm" ;;
        *) log_err "Cloudflared 不支持当前架构: $ARCH ($RAW_ARCH)"; return 1 ;;
    esac

    if [ ! -f /usr/local/bin/cloudflared ]; then
        log_info "正在下载 Cloudflared ($ARCH)..."
        # -f 必须加: 否则 404 页面会被当成二进制写进去，chmod 之后"看起来成功"
        if curl -fsSL --retry 3 --connect-timeout 10 --max-time 120 \
                -o /usr/local/bin/cloudflared "$URL" \
           && chmod +x /usr/local/bin/cloudflared \
           && /usr/local/bin/cloudflared --version >/dev/null 2>&1; then
            # 记下"这个二进制是本脚本放的"，卸载时才有资格删。
            # 旧版本只要 syspro-doh.service 在就删，连用户自己装的也一起删了。
            state_put "$FLAG_CLOUDFLARED" "1"
            log_success "Cloudflared 已下载并校验可执行。"
        else
            log_err "下载失败或文件不可执行，请检查网络与架构。"
            rm -f /usr/local/bin/cloudflared
            return 1
        fi
    else
        chmod +x /usr/local/bin/cloudflared
        if ! /usr/local/bin/cloudflared --version >/dev/null 2>&1; then
            log_err "已存在的 /usr/local/bin/cloudflared 无法执行，请先手动删除后重试"
            return 1
        fi
        log_info "  - 复用已存在的 cloudflared（卸载时不会删除它）"
    fi
    
    # --- 2. 创建运行用户 ---
    if ! id -u cloudflared >/dev/null 2>&1; then
        local nologin
        nologin=$(command -v nologin 2>/dev/null || echo /bin/false)
        useradd -M -s "$nologin" cloudflared || {
            log_err "无法创建 cloudflared 用户"
            return 1
        }
    fi

    # --- 3. 构造启动参数 ---
    local upstream_args=""
    while read -r url; do
        [[ -z "$url" || "$url" =~ ^# ]] && continue
        upstream_args="$upstream_args --upstream $url"
    done <<< "$DOH_URL_LIST"

    if [ -z "$upstream_args" ]; then
        log_err "DOH_URL_LIST 为空，无法启动 DoH"
        return 1
    fi

    # FIX-RUNTIME-2: 新版 cloudflared 已彻底移除 proxy-dns（proxy-dns 子命令是空存根，
    # --help 即失败；全局 --proxy-dns 选项也被忽略）。此时自动切换到 dnscrypt-proxy：
    # apt 源提供、活跃维护、原生 DoH，对外接口（unit 名/监听地址）保持一致。
    if ! /usr/local/bin/cloudflared proxy-dns --help >/dev/null 2>&1; then
        log_info "  - 当前 cloudflared 版本不支持 proxy-dns（官方已废弃），自动切换到 dnscrypt-proxy 后端"
        doh_backend="dnscrypt"
        if ! have dnscrypt-proxy; then
            log_info "  - 正在安装 dnscrypt-proxy..."
            smart_pkg_update
            if ! pkg_install dnscrypt-proxy >/dev/null 2>&1 || ! have dnscrypt-proxy; then
                log_err "dnscrypt-proxy 安装失败，DoH 部署中止（将回退 UDP）"
                return 1
            fi
        fi
        state_put "$FLAG_DNSCRYPT" "1"
        # 生成独立 Toml：监听 DOH_LISTEN_ADDR:53，上游用 cloudflare（在线 resolver 列表），
        # 不动系统自带的 dnscrypt-proxy.socket（127.0.2.1:53），避免端口冲突。
        if ! cat > "$DOH_DNSCRYPT_CONF" << EOF
# 由 SysPro 生成：本地 DoH 解析器
listen_addresses = ['${DOH_LISTEN_ADDR}:53']
server_names = ['cloudflare']
[query_log]
  file = '/var/log/syspro-dnscrypt-query.log'
[nx_log]
  file = '/var/log/syspro-dnscrypt-nx.log'
[sources]
  [sources.'public-resolvers']
  url = 'https://download.dnscrypt.info/resolvers-list/v2/public-resolvers.md'
  cache_file = '/var/cache/dnscrypt-proxy/public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 72
  prefix = ''
EOF
        then
            log_err "无法生成 dnscrypt-proxy 配置 $DOH_DNSCRYPT_CONF"
            return 1
        fi
        chmod 644 "$DOH_DNSCRYPT_CONF" 2>/dev/null
        log_success "  - dnscrypt-proxy 后端已就绪（上游: cloudflare DoH）"
    fi

    # --- 4. 生成 Systemd 服务 ---
    # FIX-RUNTIME-2: 根据后端生成不同的 ExecStart / User，其余沙箱选项一致。
    local doh_user="cloudflared" doh_exec="/usr/local/bin/cloudflared proxy-dns --port 53 --address ${DOH_LISTEN_ADDR} ${upstream_args} --bootstrap-dns 1.1.1.1"
    if [ "$doh_backend" = "dnscrypt" ]; then
        doh_user="root"
        doh_exec="/usr/sbin/dnscrypt-proxy -config ${DOH_DNSCRYPT_CONF}"
        [ -x /usr/sbin/dnscrypt-proxy ] || doh_exec="dnscrypt-proxy -config ${DOH_DNSCRYPT_CONF}"
    fi
    if cat > /etc/systemd/system/syspro-doh.service << EOF
[Unit]
Description=SysPro DoH Client (${doh_backend})
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${doh_user}
# 只监听本地回环，避免变成公网开放递归解析器（会被用于 DNS 放大攻击）
${cap_lines}
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ExecStart=${doh_exec}
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
    then
        chmod 644 /etc/systemd/system/syspro-doh.service
    else
        log_err "无法创建 DoH 服务文件"
        return 1
    fi

    # --- 5. 处理端口冲突（只停服务，不在这里动 resolv.conf）---
    if systemctl is-active systemd-resolved >/dev/null 2>&1 || \
       systemctl is-enabled systemd-resolved >/dev/null 2>&1; then
        # 先摘掉 nsswitch.conf 里的 resolve。
        # 否则 mask 掉 resolved 之后 glibc 仍然去连它（"resolve [!UNAVAIL=return]"），
        # 而 dns 兜底被 [!UNAVAIL=return] 挡住 —— 结果是全站域名解析直接失败。
        detach_nss_resolve || log_warn "  - nsswitch 未摘除 resolve，屏蔽 resolved 后可能无法解析"

        svc_snapshot systemd-resolved
        systemctl stop systemd-resolved >/dev/null 2>&1
        systemctl disable systemd-resolved >/dev/null 2>&1
        systemctl mask systemd-resolved >/dev/null 2>&1
        log_info "  - systemd-resolved 已停止并屏蔽（否则会占用 53 端口）"
    fi

    # --- 6. 启动服务并验证 ---
    systemctl daemon-reload
    systemctl enable syspro-doh >/dev/null 2>&1
    if ! systemctl restart syspro-doh; then
        log_err "syspro-doh 启动失败"
        systemctl status syspro-doh --no-pager -l 2>/dev/null | head -n 8
        return 1
    fi

    # v5.3 用 `ss -ln | grep ":53 "` 判断，端口被别的进程占用时也会误判成功。
    # 这里同时要求：服务处于 active + 53 端口确实在监听。
    local i started=0
    for ((i=1; i<=20; i++)); do
        if systemctl is-active syspro-doh >/dev/null 2>&1 && \
           ss -lun 2>/dev/null | grep -qE ':53[[:space:]]|:53$'; then
            started=1
            break
        fi
        sleep 0.5
    done

    if [ "$started" -ne 1 ]; then
        log_err "DoH 启动超时（10 秒内未监听 53 端口）"
        systemctl status syspro-doh --no-pager -l 2>/dev/null | head -n 8
        return 1
    fi

    # 端口开了不等于能解析，必须真的查一次。
    # FIX-RUNTIME-4: dnscrypt-proxy 端口几乎立即监听，但要下载 resolver 列表并连上
    # 上游（通常 1-3 秒）后才 ready；cloudflared 则是启动即可用。原代码端口一开就
    # 查一次，dnscrypt 后端会因尚未 ready 而误判失败、回退 UDP。改为重试到 ready。
    if have dig; then
        local resolved=0 ri
        for ((ri=1; ri<=20; ri++)); do
            if timeout 3 dig +short +time=2 +tries=1 @"$DOH_LISTEN_ADDR" cloudflare.com >/dev/null 2>&1; then
                resolved=1
                break
            fi
            sleep 0.5
        done
        if [ "$resolved" -ne 1 ]; then
            log_err "DoH 端口已监听，但 10 秒内实际域名解析始终失败"
            if [ "$doh_backend" = "dnscrypt" ]; then
                log_warn "  - dnscrypt-proxy 可能未能连通上游，请检查 download.dnscrypt.info 可达性"
            fi
            return 1
        fi
    fi

    touch "$MARK_DOH"
    log_success "DoH 服务启动成功（监听 ${DOH_LISTEN_ADDR}:53）。"
    if [ "$DOH_LISTEN_ADDR" = "127.0.0.1" ]; then
        log_info "  - 仅本机可解析。容器要用的话，请在 daemon.json 的 dns 指向 docker0 网关，"
        log_info "    或把 DOH_LISTEN_ADDR 改成 docker0 地址并用防火墙限制来源网段。"
    fi
    return 0
}

# ------------------------------------------------------------------------------
#   在 sshd_config 中确保某条指令生效
#   旧版本只做 sed 's/^#\?UseDNS.*/.../'：
#     - 配置里根本没有该指令时 → 静默无操作
#     - 与 Include drop-in 冲突时   → 改了也不生效（sshd 是先读到的赢）
#   这里改成: 有就改（大小写不敏感）、没有就追加。
# ------------------------------------------------------------------------------
sshd_ensure_directive() {
    local file=$1 key=$2 val=$3 lkey tmp
    lkey=$(printf '%s' "$key" | tr 'A-Z' 'a-z')
    tmp="${file}.syspro.aw"

    awk -v k="$lkey" -v kv="$key" -v v="$val" '
        {
            line=$0
            sub(/^[[:space:]]*#?[[:space:]]*/, "", line)
            n=split(line, a, /[[:space:]]+/)
            if (n >= 1 && tolower(a[1]) == k) { print kv " " v; done=1; next }
            print $0
        }
        END { if (!done) print kv " " v }
    ' "$file" > "$tmp" && cat "$tmp" > "$file"
    rm -f "$tmp"
}

optimize_ssh() {
    log_info "正在优化 SSH 配置..."

    local sshd_conf="/etc/ssh/sshd_config"
    if [ ! -f "$sshd_conf" ]; then
        log_warn "未找到 $sshd_conf，跳过 SSH 优化。"
        return 0
    fi

    [ ! -f "${sshd_conf}.syspro.bak" ] && cp -p "$sshd_conf" "${sshd_conf}.syspro.bak"

    # 另存一份"本次修改前"的快照，校验失败时回滚到这里，
    # 而不是回滚到很久以前那次运行留下的备份。
    cp -p "$sshd_conf" "${sshd_conf}.syspro.stage"

    sshd_ensure_directive "$sshd_conf" "UseDNS" "no"
    sshd_ensure_directive "$sshd_conf" "GSSAPIAuthentication" "no"

    # 服务名按实际存在的单元判断（Debian=ssh / RHEL=sshd），
    # 不再用 RELEASE == "centos" 二分，否则 Alma/Rocky/Fedora 会去重启不存在的 ssh 服务。
    local ssh_svc sshd_bin
    ssh_svc=$(detect_ssh_service)
    # 显式定位 sshd，避免 root 的 PATH 里没有 /usr/sbin 时误判"校验失败"
    sshd_bin=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)

    if [ -x "$sshd_bin" ] && "$sshd_bin" -t 2>/dev/null; then
        # 校验"实际生效值"，而不是"文件里写了什么"。
        # Ubuntu 22.04+ 的 sshd_config 顶部有 Include /etc/ssh/sshd_config.d/*.conf，
        # drop-in 里的同名设置优先级更高，只改主文件会出现"改了但没生效"。
        local include_dir="" eff=""
        include_dir=$(awk 'tolower($1)=="include" {print $2; exit}' "$sshd_conf" 2>/dev/null)
        if [ -n "$include_dir" ]; then
            include_dir=$(dirname "$include_dir")
            case "$include_dir" in
                /*) ;;
                *) include_dir="/etc/ssh/$include_dir" ;;
            esac
        fi

        eff=$("$sshd_bin" -T 2>/dev/null | awk 'tolower($1)=="usedns" {print tolower($2); exit}')
        if [ "$eff" != "no" ] && [ -n "$include_dir" ] && [ -d "$include_dir" ]; then
            if printf '# 由 SysPro 写入: 覆盖 Include drop-in 里的同名设置（sshd 先读到的生效）\nUseDNS no\nGSSAPIAuthentication no\n' \
                    > "${include_dir}/00-syspro.conf" 2>/dev/null; then
                state_put "$FLAG_SSHD_DROPIN" "${include_dir}/00-syspro.conf"
                log_info "  - drop-in 覆盖了 UseDNS，已写入 ${include_dir}/00-syspro.conf"
                eff=$("$sshd_bin" -T 2>/dev/null | awk 'tolower($1)=="usedns" {print tolower($2); exit}')
            fi
        fi

        if [ -n "$ssh_svc" ] && systemctl reload-or-restart "$ssh_svc" 2>/dev/null; then
            rm -f "${sshd_conf}.syspro.stage"
            if [ "$eff" = "no" ]; then
                log_success "SSH 配置优化完成 (已禁用 DNS 反查)，服务单元: $ssh_svc"
            else
                log_warn "SSH 配置已写入，但实际生效值无法确认（sshd -T 未返回 usedns），请手工核对"
            fi
        else
            log_err "SSH 服务重载失败，已回滚配置"
            cp -p "${sshd_conf}.syspro.stage" "$sshd_conf"
            rm -f "${sshd_conf}.syspro.stage"
            [ -n "$ssh_svc" ] && systemctl reload-or-restart "$ssh_svc" 2>/dev/null
            return 1
        fi
    else
        log_err "SSH 配置校验失败 (sshd -t)，已自动回滚。"
        cp -p "${sshd_conf}.syspro.stage" "$sshd_conf"
        rm -f "${sshd_conf}.syspro.stage"
        return 1
    fi
}

optimize_shell_env() {
    log_info "正在优化 Shell 环境..."
    
    cat > /etc/profile.d/syspro.sh << 'EOF'
# SysPro Shell Enhancements
export HISTTIMEFORMAT="%F %T "
export HISTSIZE=100000
export HISTFILESIZE=100000
# 刻意不带 ignorespace: 那个选项让"空格开头的命令"不进历史，
# 等于给 root 留了一个隐藏操作痕迹的开关，与审计要求相悖。
export HISTCONTROL=ignoredups

# Color prompt for root
if [ "$USER" = "root" ]; then
    PS1='\[\033[01;31m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
fi
EOF
    chmod "$FILE_PERMISSION" /etc/profile.d/syspro.sh
    log_success "Shell 环境优化完成。"
}

# ------------------------------------------------------------------------------
#   DNS 探测选优（v6.1，从 nftx v4.29 迁入）
#   原则（协议族无关 / 基于实测 / 保守）：
#   · v4 / v6 一视同仁，谁实测不可达才剔除谁；别的机器 v6 通就自然保留。
#   · N 次里 1 次成功就保留（容忍抖动）；连续 N 次全失败才判不可达。
#   · 全部不可达保守不动，避免把 resolv.conf 写空导致彻底断网。
#   关键坑：dig 超时 / SERVFAIL 会把 ";; communications error ..." 写到 stdout，
#   连 +short / +noall 都挡不住，所以必须严格匹配 ANSWER 段的真实 A 记录。
# ------------------------------------------------------------------------------

# 单次探测：<server> <domain> -> 成功打印 "ok <ms>"，失败返回 1
dns_probe_one() {
    local srv=$1 dom=$2 out t0 t1 ms
    have dig || return 1
    # FIX-P2-4: 优先用 %s%3N（毫秒，GNU date），BusyBox 不支持时退回秒级 %s*1000，
    # 避免 %N 输出字面量导致延迟恒为 0
    t0=$(date +%s%3N 2>/dev/null); case "$t0" in ''|*[!0-9]*)
        t0=$(date +%s 2>/dev/null); case "$t0" in ''|*[!0-9]*) t0=0 ;; *) t0=$((t0 * 1000)) ;; esac
    ;; esac
    out=$(dig +time="${DNS_PROBE_TIMEOUT:-2}" +tries=1 +noall +answer "@$srv" "$dom" A 2>/dev/null)
    t1=$(date +%s%3N 2>/dev/null); case "$t1" in ''|*[!0-9]*)
        t1=$(date +%s 2>/dev/null); case "$t1" in ''|*[!0-9]*) t1=$t0 ;; *) t1=$((t1 * 1000)) ;; esac
    ;; esac
    if ! grep -qE '[[:space:]]IN[[:space:]]+A[[:space:]]+[0-9]{1,3}(\.[0-9]{1,3}){3}[[:space:]]*$' <<< "$out"; then
        return 1
    fi
    ms=$(( (t1 - t0) ))   # FIX-P2-4: t0/t1 已是毫秒，无需再除 1000000
    case "$ms" in ''|*[!0-9]*) ms=0 ;; esac
    printf 'ok %s' "$ms"
}

# DNS 服务器连通性测试（供 configure_dns 建候选清单用）
# 返回值: 0 = 可用 ; 1 = 不可用 ; 2 = 无法判断（调用方不得据此做任何全局决策）
test_dns_server() {
    local ip="$1"
    local timeout_sec="${2:-2}"

    if have dig; then
        DNS_PROBE_TIMEOUT=$timeout_sec dns_probe_one "$ip" cloudflare.com >/dev/null 2>&1
        return $?
    fi

    # 没有 dig 时只能做 TCP 53 握手：这只能证明端口开放，不能证明真能解析。
    # 而且 bash 的 /dev/tcp 对 IPv6 字面量支持并不可靠（会按最后一个冒号切分端口），
    # 所以 IPv6 一律返回"无法判断"，避免误判。
    if [[ "$ip" == *:* ]]; then
        return 2
    fi
    timeout "$timeout_sec" bash -c "exec 3<>/dev/tcp/${ip}/53" 2>/dev/null
    return $?
}

# 对文件里的 nameserver 逐个实测并（可选）保守重写。
# 用法: dns_select_best <resolv.conf 路径> [check|apply] [备份:0|1]
# 返回: 0 = 正常 ; 1 = 参数/备份/重写错误 ; 2 = 全不可达（保守未改）
dns_select_best() {
    local rc_file=${1:-/etc/resolv.conf} sub=${2:-check} do_backup=${3:-1}
    local -a servers doms good=() bad=()
    local s i dom res st ms okcnt sum bakdir bak='' outf srvlist tries

    have dig || { log_err "DNS 选优需要 dig（apt install dnsutils / yum install bind-utils）"; return 1; }
    [ -r "$rc_file" ] || { log_err "无法读取 $rc_file"; return 1; }
    [ -L "$rc_file" ] && { log_err "DNS 选优不支持软链接 $rc_file（请先配置静态 resolv.conf）"; return 1; }

    mapfile -t servers < <(awk '/^[[:space:]]*nameserver[[:space:]]+/ {print $2}' "$rc_file" 2>/dev/null)
    [ ${#servers[@]} -gt 0 ] || { log_err "$rc_file 中没有 nameserver"; return 1; }
    read -ra doms <<< "${DNS_PROBE_DOMAINS:-example.com www.qq.com www.baidu.com}"
    [ ${#doms[@]} -gt 0 ] || doms=(example.com)

    tries=${DNS_PROBE_TRIES:-3}
    log_info "DNS 选优探测（协议族无关，基于实测）  域名: ${doms[*]}  每服务器 ${tries} 次"
    # FIX-P3-13: 各 server 之间并行探测（server 内部仍串行 tries 次），
    # 结果按索引写入临时文件保证聚合顺序与串行版一致。mktemp 失败时回退串行。
    local probe_dir="" pi
    probe_dir=$(mktemp -d /tmp/syspro-dns-probe.XXXXXX 2>/dev/null) || probe_dir=""
    if [ -n "$probe_dir" ]; then
        for ((pi = 0; pi < ${#servers[@]}; pi++)); do
            (
                local _s="${servers[pi]}" _i _dom _res _st _ms _ok=0 _sum=0
                for ((_i = 0; _i < tries; _i++)); do
                    _dom=${doms[_i % ${#doms[@]}]}
                    _res=$(dns_probe_one "$_s" "$_dom") || _res=''
                    case "$_res" in
                        ok*)
                            read -r _st _ms <<< "$_res"
                            case "$_ms" in ''|*[!0-9]*) _ms=0 ;; esac
                            _ok=$((_ok + 1)); _sum=$((_sum + _ms)) ;;
                    esac
                done
                printf '%s %s\n' "$_ok" "$_sum" > "${probe_dir}/${pi}.result" 2>/dev/null
            ) &
        done
        wait
    fi
    for ((pi = 0; pi < ${#servers[@]}; pi++)); do
        s="${servers[pi]}"
        okcnt=0; sum=0
        if [ -n "$probe_dir" ] && [ -f "${probe_dir}/${pi}.result" ]; then
            read -r okcnt sum < "${probe_dir}/${pi}.result" 2>/dev/null
            case "$okcnt" in ''|*[!0-9]*) okcnt=0 ;; esac
            case "$sum" in ''|*[!0-9]*) sum=0 ;; esac
        else
            # 回退：并行结果缺失时串行重探该 server
            for ((i = 0; i < tries; i++)); do
                dom=${doms[i % ${#doms[@]}]}
                res=$(dns_probe_one "$s" "$dom") || res=''
                case "$res" in
                    ok*)
                        read -r st ms <<< "$res"
                        case "$ms" in ''|*[!0-9]*) ms=0 ;; esac
                        okcnt=$((okcnt + 1)); sum=$((sum + ms)) ;;
                esac
            done
        fi
        if [ "$okcnt" -ge 1 ]; then
            good+=("$s")
            log_info "  - $s 可达 $okcnt/$tries，平均 $((sum / okcnt))ms -> 保留"
        else
            bad+=("$s")
            log_warn "  - $s 不可达 0/$tries -> 剔除"
        fi
    done
    [ -n "$probe_dir" ] && rm -rf "$probe_dir" 2>/dev/null

    if [ ${#good[@]} -eq 0 ]; then
        log_warn "所有 nameserver 都不可达：保守起见不修改 $rc_file（避免彻底断网）"
        return 2
    fi
    if [ "$sub" != "apply" ]; then
        log_info "check 模式：仅报告，未修改配置。要应用请执行: $0 dns apply"
        return 0
    fi
    if [ ${#bad[@]} -eq 0 ]; then
        log_info "全部可达，无需修改。"
        return 0
    fi

    outf="${rc_file}.syspro.select.$$"
    if [ "$do_backup" = "1" ]; then
        bakdir="/var/lib/syspro/dns"
        mkdir -p "$bakdir" 2>/dev/null
        bak="$bakdir/resolv.bak.$(date +%Y%m%d-%H%M%S)"
        cp -p "$rc_file" "$bak" 2>/dev/null || { log_err "备份失败，不修改配置"; return 1; }
    fi
    srvlist=$(printf '%s\n' "${good[@]}")
    awk -v keep="$srvlist" '
        BEGIN { n=split(keep, A, "\n"); for (i=1;i<=n;i++) if (A[i]!="") G[A[i]]=1 }
        /^[[:space:]]*nameserver[[:space:]]+/ { if ($2 in G) print; next }
        { print }
    ' "$rc_file" > "$outf" 2>/dev/null
    if [ -s "$outf" ] && mv -f "$outf" "$rc_file" 2>/dev/null; then
        log_success "已重写 $rc_file（剔除实测不可达: ${bad[*]}）"
        [ -n "$bak" ] && log_info "备份: $bak"
        return 0
    fi
    rm -f "$outf" 2>/dev/null
    log_err "重写失败，已保留原配置"
    [ -n "$bak" ] && log_info "备份仍在: $bak"
    return 1
}

# ------------------------------------------------------------------------------
#   内核 IPv6 状态同步 —— v5.4 起只做"恢复"，不再做"禁用"
#   原因: 用"IPv6 DNS 通不通"推断"整机 IPv6 能不能用"是不成立的。
#         上游 DNS 不通、防火墙拦了 53、或者没装 dig 导致探测不准，都会误判。
#         而 disable_ipv6=1 是全机开关，会立刻拆掉已配置的 IPv6 地址，
#         正在运行的 IPv6 SSH 会话会当场断开，而且重启后依然生效。
#   现在的行为: 只要发现旧版本留下的禁用标记，就撤销它并恢复 IPv6。
# ------------------------------------------------------------------------------
sync_ipv6_kernel_state() {
    local marker="/etc/sysctl.d/99-syspro-disable-ipv6.conf"

    if [ -f "$marker" ]; then
        # 兼容从 v5.3 升级上来的机器：老版本会因为 IPv6 DNS 探测失败而写入该文件。
        # 既然判定依据不成立，这里撤销它并恢复 IPv6。
        rm -f "$marker"
        sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1
        sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1
        log_info "已撤销旧版本遗留的 IPv6 禁用设置，IPv6 恢复启用。"
    fi
    return 0
}

# ------------------------------------------------------------------------------
#   nsswitch 与 systemd-resolved 的联动
#
#   不少发行版把 hosts 行写成:
#       hosts: files mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns
#   这时 glibc 走的是 resolved 的 varlink 接口，**根本不读 /etc/resolv.conf**。
#   如果直接 mask systemd-resolved 再改写 resolv.conf，等于把解析链路整条掐断:
#   既没有 resolved，dns 兜底又被 [!UNAVAIL=return] 挡住，所有域名查询立即失败。
#
#   所以: 屏蔽 resolved 之前先把 nsswitch 的 resolve 摘掉（留 dns 兜底），
#         并备份原文件，卸载时还原。
# ------------------------------------------------------------------------------
nss_has_resolve() {
    awk '
        tolower($1)=="hosts:" { if (index($0,"resolve")>0) r=1; exit }
        END { exit (r?0:1) }
    ' /etc/nsswitch.conf 2>/dev/null
}

detach_nss_resolve() {
    local f="/etc/nsswitch.conf"
    [ -f "$f" ] || return 0
    nss_has_resolve || return 0

    [ -f "${f}.syspro.bak" ] || cp -p "$f" "${f}.syspro.bak"

    # 只动 hosts 行: 删掉 resolve 及其后面的条件方括号，再确保还有 dns 兜底
    sed -i '/^[[:space:]]*hosts:[[:space:]]/ {
        s/[[:space:]]\+resolve\([[:space:]]\+\[[^]]*\]\)\?//g
        /[[:space:]]dns[[:space:]]*$/! s/[[:space:]]*$/ dns/
    }' "$f" 2>/dev/null

    if nss_has_resolve; then
        log_warn "  - 无法从 /etc/nsswitch.conf 摘除 resolve，已还原该文件"
        cp -p "${f}.syspro.bak" "$f" 2>/dev/null
        return 1
    fi
    log_info "  - 已从 /etc/nsswitch.conf 摘除 resolve（保留 dns 兜底）"
    return 0
}

restore_nss_resolve() {
    if [ -f /etc/nsswitch.conf.syspro.bak ]; then
        restore_from_backup "/etc/nsswitch.conf.syspro.bak" "/etc/nsswitch.conf" "nsswitch.conf"
    fi
    return 0
}

# /etc/resolv.conf 加锁（默认关闭，由 DNS_LOCK_IMMUTABLE 控制）
# 收益很小（防止被 dhclient 改回去），代价极大: DoH 进程开机没起来时，
# 机器会同时处于"DNS 全挂"和"文件改不动"两个状态，只能靠云控制台 chattr -i 抢救。
lock_resolv_if_requested() {
    # FIX-P0-2: 加锁目标必须与实际改写的 resolv.conf 一致。
    # CLI `dns apply <自定义文件>` 会改写自定义路径，若此处仍硬编码 /etc/resolv.conf，
    # 会给一个根本没被本命令改动的文件加上 immutable，导致 dhclient/cloud-init 无法回写。
    local target="${1:-/etc/resolv.conf}"
    if [ "${DNS_LOCK_IMMUTABLE:-0}" != "1" ]; then
        log_info "  - ${target} 保持可写（如需加锁请把 DNS_LOCK_IMMUTABLE 改为 1）"
        return 0
    fi
    if chattr +i "$target" >/dev/null 2>&1; then
        log_warn "  - 已按要求锁定 ${target}；解锁: chattr -i ${target}"
        log_warn "  - 注意: DoH 进程异常时本机将无法解析、也无法直接修改该文件"
    else
        log_info "  - 文件系统不支持 immutable 属性，保持可写"
    fi
    return 0
}

# FIX-P3-5: 从 configure_dns 拆出——按配置探测并构建标准 DNS 候选清单。
# 参数: $1 = 输出文件路径（函数会先清空该文件）
build_dns_candidates() {
    local outf="$1"
    local v4_added=0 v6_added=0 ip rc

    echo "# SysPro Standard DNS" > "$outf"

    log_info "正在测试 IPv4 DNS 服务器连通性..."
    while read -r ip; do
        [[ -z "$ip" || "$ip" =~ ^# ]] && continue
        validate_ipv4 "$ip" || { log_warn "  - $ip 格式非法，已跳过"; continue; }
        test_dns_server "$ip" 2; rc=$?
        case $rc in
            0) echo "nameserver $ip" >> "$outf"
               v4_added=$((v4_added + 1))
               log_success "  - $ip 可用，已加入" ;;
            1) log_warn "  - $ip 不可达，已跳过" ;;
            *) log_warn "  - $ip 无法判断（未安装 dig），按保守策略跳过" ;;
        esac
    done <<< "$DNS_IPV4_LIST"

    # 兜底：避免 resolv.conf 被写空
    if [ "$v4_added" -eq 0 ]; then
        log_warn "未发现验证通过的 IPv4 DNS，按配置原样写入"
        while read -r ip; do
            [[ -z "$ip" || "$ip" =~ ^# ]] && continue
            validate_ipv4 "$ip" && echo "nameserver $ip" >> "$outf"
        done <<< "$DNS_IPV4_LIST"
    fi

    # IPv6 DNS 只在"有默认路由且有全局地址"时才尝试。
    # 注意: 探测失败只跳过这一条 DNS，绝不再去动内核的 disable_ipv6 开关
    #       （v5.3 就是在这里把整机 IPv6 关掉的）。
    if has_global_ipv6; then
        log_info "正在测试 IPv6 DNS 服务器连通性..."
        while read -r ip; do
            [[ -z "$ip" || "$ip" =~ ^# ]] && continue
            validate_ipv6 "$ip" || { log_warn "  - $ip 格式非法，已跳过"; continue; }
            test_dns_server "$ip" 2; rc=$?
            if [ "$rc" -eq 0 ]; then
                echo "nameserver $ip" >> "$outf"
                v6_added=$((v6_added + 1))
                log_success "  - $ip (IPv6) 可用，已加入"
            else
                log_warn "  - $ip (IPv6) 未通过本次测试，已跳过（不改动内核 IPv6）"
            fi
        done <<< "$DNS_IPV6_LIST"
    else
        log_info "未检测到 IPv6 默认路由，跳过 IPv6 DNS 配置"
    fi

    echo "options timeout:$DNS_TIMEOUT attempts:$DNS_ATTEMPTS rotate" >> "$outf"
    return 0
}

configure_dns() {
    log_info "正在配置 DNS..."

    echo -e "${YELLOW}请选择 DNS 模式:${PLAIN}"
    echo -e " 1. ${GREEN}标准 UDP DNS${PLAIN} (使用脚本开头配置的 IP, 兼容性最佳)"
    echo -e " 2. ${GREEN}DoH 加密 DNS${PLAIN} (防劫持, 需要本机能访问 GitHub)"

    while true; do
        read -r -p "请输入选项 [1-2] (默认1): " DNS_CHOICE
        if [[ "$DNS_CHOICE" =~ ^[1-2]$ || -z "$DNS_CHOICE" ]]; then
            break
        fi
        log_err "无效输入，请输入 1 或 2"
    done
    DNS_CHOICE=${DNS_CHOICE:-1}

    # 首次修改前备份原始 resolv.conf（可能是指向 stub-resolv.conf 的符号链接），
    # 卸载时按原样恢复，而不是粗暴地写死 8.8.8.8。
    if [ ! -e /etc/resolv.conf.syspro.bak ] && [ ! -L /etc/resolv.conf.syspro.bak ]; then
        local _bak_ok=0
        if [ -L /etc/resolv.conf ]; then
            cp -P /etc/resolv.conf /etc/resolv.conf.syspro.bak 2>/dev/null && _bak_ok=1
        elif [ -f /etc/resolv.conf ]; then
            cp -p /etc/resolv.conf /etc/resolv.conf.syspro.bak 2>/dev/null && _bak_ok=1
        fi
        # FIX-P3-3: 伴生标记，供恢复/卸载时确认备份来源
        [ "$_bak_ok" -eq 1 ] && printf 'src=/etc/resolv.conf\ntime=%s\n' "$(date '+%F %T' 2>/dev/null)" \
            > /etc/resolv.conf.syspro.bak.syspro-origin 2>/dev/null || true
    fi

    chattr -i /etc/resolv.conf >/dev/null 2>&1

    # 无论选哪种模式，先把 v5.3 可能遗留的 disable_ipv6 设置撤掉
    # （该函数只会恢复 IPv6，不会新增禁用）
    sync_ipv6_kernel_state

    if [ -f /etc/systemd/system/syspro-doh.service ]; then
        systemctl stop syspro-doh >/dev/null 2>&1
        systemctl disable syspro-doh >/dev/null 2>&1
    fi

    if [[ "$DNS_CHOICE" == "2" ]]; then
        if install_cloudflared; then
            local tmp_dns="/etc/resolv.conf.syspro.new"
            cat > "$tmp_dns" <<EOF
# SysPro DoH (Cloudflared)
nameserver $DOH_LISTEN_ADDR
options timeout:$DNS_TIMEOUT attempts:$DNS_ATTEMPTS
EOF
            # 用 mv 原子替换，避免中途失败留下半截/空白的 resolv.conf
            mv -f "$tmp_dns" /etc/resolv.conf

            if verify_resolv; then
                # 默认不加锁: 上了 immutable 之后，cloudflared 一挂，
                # 机器就同时"解析不了"且"改不回来"，只能上控制台。
                lock_resolv_if_requested
                log_success "DoH 模式已生效（解析已验证）。"
                return 0
            fi

            log_err "DoH 已启动但解析验证失败，回退到标准 UDP 模式。"
            # 停掉没在用的 DoH 服务，避免它继续占着 53 端口
            systemctl disable --now syspro-doh >/dev/null 2>&1
            # FIX-P1-1: DoH 部署时 mask 了 resolved、摘掉了 nsswitch 的 resolve；
            # 回退 UDP 必须撤销这两个副作用，否则机器停留在状态不一致。
            restore_nss_resolve
            if state_has "SVC:systemd-resolved"; then
                svc_restore systemd-resolved
                systemctl start systemd-resolved >/dev/null 2>&1
            elif [ "$(systemctl is-enabled systemd-resolved 2>/dev/null)" = "masked" ]; then
                systemctl unmask systemd-resolved >/dev/null 2>&1
                systemctl enable --now systemd-resolved >/dev/null 2>&1
            fi
            DNS_CHOICE="1"
        else
            log_warn "DoH 部署失败，自动回退到标准 UDP 模式。"
            # FIX-P1-1: 同上，撤销 DoH 部署阶段对 resolved / nsswitch 的副作用
            restore_nss_resolve
            if state_has "SVC:systemd-resolved"; then
                svc_restore systemd-resolved
                systemctl start systemd-resolved >/dev/null 2>&1
            elif [ "$(systemctl is-enabled systemd-resolved 2>/dev/null)" = "masked" ]; then
                systemctl unmask systemd-resolved >/dev/null 2>&1
                systemctl enable --now systemd-resolved >/dev/null 2>&1
            fi
            DNS_CHOICE="1"
        fi
    fi

    if [[ "$DNS_CHOICE" != "2" ]]; then
        local new_dns="/etc/resolv.conf.syspro.new"
        # FIX-P3-5: 候选清单构建抽成独立函数，主函数只负责选择/提交
        build_dns_candidates "$new_dns"

        # v6.1: 写盘前自动做一次探测选优（菜单 5 / 一键优化都走这里）。
        # backup=0: 原始 resolv.conf 在本函数开头已备份，这里只是候选清单，
        # 对它再备份没有意义；真正写盘仍由下面的 mv 原子完成。
        if [ "${DNS_SELECT_ENABLED:-1}" = "1" ]; then
            dns_select_best "$new_dns" apply 0
            case $? in
                0|2) : ;;   # 2 = 全不可达，保守沿用原候选，交给 verify_resolv 兜底
                *) log_warn "DNS 选优执行失败，沿用原始候选清单" ;;
            esac
        fi

        # FIX-P3-2: 统一走原子提交原语（内部含 P0-1 的失败自动回滚）
        commit_config_atomic "$new_dns" /etc/resolv.conf /etc/resolv.conf.syspro.bak \
            "标准 DNS 模式已生效（解析已验证）。" "DNS" || return 1
    fi
}

# FIX-P0-1: DNS 写入后验证失败时自动回滚到原始 resolv.conf。
# configure_dns 在改动前已把原文件备份为 /etc/resolv.conf.syspro.bak；
# 验证失败若不回滚，就会把一组不可达 DNS 永久留在机器上，远程机器等于失联。
# 返回: 0 = 已回滚, 1 = 无法回滚（备份缺失或 mv 失败）
rollback_resolv_conf() {
    local bak="/etc/resolv.conf.syspro.bak"
    chattr -i /etc/resolv.conf >/dev/null 2>&1
    if [ -e "$bak" ] || [ -L "$bak" ]; then
        if mv -f "$bak" /etc/resolv.conf 2>/dev/null; then
            rm -f "${bak}.syspro-origin"   # FIX-P3-3: 清理伴生标记
            log_warn "  - 解析验证失败，已自动回滚 /etc/resolv.conf 到原始配置"
            return 0
        fi
        log_err "  - 自动回滚失败！请手动: cp -p ${bak} /etc/resolv.conf"
        return 1
    fi
    log_err "  - 找不到原始备份 ${bak}，无法自动回滚；请手动恢复 DNS"
    return 1
}

# FIX-P3-2: 通用"原子提交配置"原语：备份已存在 -> 原子写入 -> 验证 -> 失败回滚。
# 把散落在各处的"mv + verify + rollback"收敛为一处，避免每个调用点各写一遍
# 回滚逻辑（P0-1 正是这类重复导致遗漏）。当前用于标准 DNS 写入；
# DoH 分支因额外涉及服务停止/nsswitch 恢复，保留其专用逻辑。
# 参数: $1=候选新文件 $2=目标文件 $3=备份文件 $4=成功提示 $5=失败上下文描述
# 依赖调用方已建立 $3 备份；返回 0=成功 1=验证失败已回滚
commit_config_atomic() {
    local newf="$1" target="$2" bak="$3" okmsg="$4" ctx="$5"
    mv -f "$newf" "$target" 2>/dev/null || {
        log_err "写入 ${ctx} 失败"
        return 1
    }
    if verify_resolv; then
        lock_resolv_if_requested
        log_success "$okmsg"
        return 0
    fi
    log_err "${ctx}写入后解析验证失败，正在自动回滚。"
    if [ -e "$bak" ] || [ -L "$bak" ]; then
        mv -f "$bak" "$target" 2>/dev/null && {
            rm -f "${bak}.syspro-origin" 2>/dev/null
            log_warn "  - 已自动回滚 ${ctx} 到原始配置"
            return 1
        }
    fi
    log_warn "  - 回滚未完成，请手动恢复: cp -p ${bak} ${target}"
    return 1
}

# 验证 resolv.conf 是否真的可用
# FIX-P1-2: getent hosts 走 nsswitch 的 files dns，会先查 /etc/hosts。
# 若代理/科学上网工具在 hosts 里绑定了探测域名，DNS 全坏也会误报成功，掩盖 P0-1。
# 改为优先用 dig 直连实际写入的 nameserver（绕过 hosts），getent 仅作兜底。
verify_resolv() {
    local ns
    if have dig; then
        while read -r ns; do
            [[ -z "$ns" ]] && continue
            timeout "${DNS_VERIFY_TIMEOUT:-6}" dig +short +time="${DNS_PROBE_TIMEOUT:-2}" +tries=1 "@$ns" cloudflare.com A >/dev/null 2>&1 && return 0
        done < <(awk '/^[[:space:]]*nameserver[[:space:]]+/ {print $2}' /etc/resolv.conf 2>/dev/null)
        # 没有可直连的 nameserver（如 DoH 的 127.0.0.1 场景）才退回系统解析
    fi
    if have getent; then
        timeout "${DNS_VERIFY_TIMEOUT:-6}" getent hosts cloudflare.com >/dev/null 2>&1 && return 0
    fi
    return 1
}

# ------------------------------------------------------------------------------
#   地址族选择偏好 (gai.conf)
#   只调 glibc getaddrinfo 的排序，让 IPv4 排到 IPv6 前面；不碰内核 IPv6 开关。
# ------------------------------------------------------------------------------
tune_gai_preference() {
    local gai="/etc/gai.conf"

    # 开关关闭: 若之前写入过，还原
    if [ "${GAI_PREFER_IPV4:-1}" != "1" ]; then
        [ -f "${gai}.syspro.bak" ] && \
            restore_from_backup "${gai}.syspro.bak" "$gai" "gai.conf 地址选择"
        log_info "地址选择偏好已关闭 (GAI_PREFER_IPV4=0)，跳过。"
        return 0
    fi

    # FIX-P1-11: 判据从"有全局地址"升级为"有全局地址且出口实测可达"。
    # 原逻辑只看地址存在性：机器有全局 v6 但出口不通时误判为双栈、保持默认排序，
    # getaddrinfo 仍把 AAAA 排最前，不支持 Happy Eyeballs 的程序照样卡顿几秒。
    # 只有真正可达的双栈机器才跳过 IPv4 优先。
    if ipv6_reachable; then
        # 机器后来有了 v6（之前无 v6 时期写过 v4 优先）：还原掉，别让旧偏好干扰双栈
        [ -f "${gai}.syspro.bak" ] && \
            restore_from_backup "${gai}.syspro.bak" "$gai" "gai.conf 地址选择"
        log_info "检测到可达的全局 IPv6，保持系统默认地址选择。"
        return 0
    fi

    if [ ! -f "$gai" ]; then
        log_warn "未找到 $gai，跳过地址选择优化。"
        return 0
    fi

    [ ! -f "${gai}.syspro.bak" ] && cp -p "$gai" "${gai}.syspro.bak"

    # 幂等: 已经写过就不再追加（可能是旧版本、或用户手工加过）
    if grep -qE '^[[:space:]]*precedence[[:space:]]+::ffff:0:0/96' "$gai"; then
        log_info "gai.conf 已配置 IPv4 优先，跳过。"
        return 0
    fi

    # FIX-RUNTIME-3: 判据是"出口可达"，不一定是"没有地址"。服务器常配有全局 IPv6
    # 但出口不通，此时文案说"无全局 IPv6"与事实不符、误导排查，需区分两种情况。
    if has_global_ipv6; then
        local reason="全局 IPv6 出口不可达"
    else
        local reason="本机无全局 IPv6 地址"
    fi
    {
        echo ''
        echo "# SysPro: ${reason}，优先 IPv4（只调排序，不禁用 IPv6）"
        echo 'precedence ::ffff:0:0/96  100'
    } >> "$gai" || { log_err "无法写入 $gai"; return 1; }

    log_success "已让 getaddrinfo 优先 IPv4（${reason}）。"
    log_info "  - 立即生效于之后发起的解析；以后若 IPv6 出口恢复可达，重跑本项会自动还原"
    return 0
}

optimize_access() {
    log_info "正在优化接入层 (SSH & Environment)..."

    optimize_ssh
    optimize_shell_env
    configure_dns
    tune_gai_preference
}

# ==============================================================================
#   模块 6: 维护与清理 (Maintenance)
# ==============================================================================
maintenance_tasks() {
    log_info "执行系统维护任务..."
    
    # --- 6.1 基础工具与时间同步 ---
    # 只装 syspro 自身和日常运维用得上的工具。
    # 边界说明: nftx 的依赖（ip/tc/ss、ethtool、iptables、ping、python3 等）
    # 由它自己的 `nftx_auto.sh deps` 负责准备，这里一律不替它装 ——
    # 两边各管各的，避免包名（iproute2 vs iproute）和版本假设漂移。
    local TOOLS="curl wget vim nano htop iotop net-tools ca-certificates unzip"

    smart_pkg_update
    if [ "$RELEASE_FAMILY" = "rpm" ]; then
        pkg_install epel-release || log_warn "epel-release 安装失败，部分软件包可能不可用"
        SVC_CHRONY="chronyd"
    else
        SVC_CHRONY="chrony"
    fi

    # v5.3 只区分 centos / 其它，Alma、Rocky、Fedora 会走到 apt-get 分支直接失败
    if pkg_install $TOOLS chrony; then
        log_success "基础工具与 chrony 已安装。"
    else
        log_warn "部分软件包安装失败，请检查软件源是否可用。"
    fi
    
    # 优化 Chrony 配置
    CFG_CHRONY="/etc/chrony/chrony.conf"
    [ ! -f "$CFG_CHRONY" ] && CFG_CHRONY="/etc/chrony.conf"
    
    if [ -f "$CFG_CHRONY" ]; then
        if ! grep -q "^makestep" "$CFG_CHRONY"; then
            echo "makestep 1.0 3" >> "$CFG_CHRONY"
        fi
        # 服务名按实际单元判断: RHEL 系是 chronyd，Debian 系是 chrony
        if systemctl list-unit-files "${SVC_CHRONY}.service" 2>/dev/null \
             | grep -q "^${SVC_CHRONY}\.service"; then
            systemctl enable "$SVC_CHRONY" --now >/dev/null 2>&1
            if systemctl restart "$SVC_CHRONY" 2>/dev/null; then
                log_success "时间同步服务已优化 (Chrony + Makestep)，服务: $SVC_CHRONY"
            else
                log_err "chrony 重启失败，请检查 systemctl status $SVC_CHRONY"
            fi
        else
            log_warn "未找到 ${SVC_CHRONY}.service，跳过时间同步优化。"
        fi
    else
        log_warn "未找到 chrony 配置文件，跳过时间同步优化。"
    fi
    
    # --- 6.2 时区设置 ---
    # 三级回退，且每一步都不许往终端漏 stderr:
    # 容器里常常没有 timedatectl，也没有 /etc/timezone（只有 /etc/localtime 软链）。
    # 旧写法 `timedatectl ... || cat /etc/timezone` 会在这种机器上直接打印
    # "cat: /etc/timezone: No such file or directory"。
    CURRENT_TZ=$(timedatectl show --property=Timezone --value 2>/dev/null)
    if [ -z "$CURRENT_TZ" ] && [ -r /etc/timezone ]; then
        CURRENT_TZ=$(cat /etc/timezone 2>/dev/null)
    fi
    if [ -z "$CURRENT_TZ" ] && [ -L /etc/localtime ]; then
        CURRENT_TZ=$(readlink -f /etc/localtime 2>/dev/null | sed 's#.*/zoneinfo/##')
    fi
    echo -e "\n${YELLOW}当前时区: ${GREEN}${CURRENT_TZ:-Unknown}${PLAIN}"
    echo -e "请选择目标时区:"
    echo -e " 1. ${GREEN}Asia/Shanghai${PLAIN}       (北京时间 UTC+8)"
    echo -e " 2. ${GREEN}Asia/Hong_Kong${PLAIN}      (香港时间 UTC+8)"
    echo -e " 3. ${GREEN}Asia/Tokyo${PLAIN}          (东京时间 UTC+9)"
    echo -e " 4. ${GREEN}America/Los_Angeles${PLAIN}   (美西时间 UTC-7/8)"
    echo -e " 5. ${GREEN}America/New_York${PLAIN}      (美东时间 UTC-4/5)"
    echo -e " 6. ${GREEN}Europe/London${PLAIN}         (伦敦时间 UTC+0/1)"
    echo -e " 0. ${YELLOW}保持不变${PLAIN}"
    
    # 输入验证（时区无法自动推断，必须保留交互）
    # 默认值取 0（保持不变）: 既然无法判断用户在哪个时区，直接回车就不应改动系统时间，
    # 否则欧洲/美洲的机器会被默默改成 UTC+8，cron 任务时间全部错位。
    while true; do
        read -r -p "请输入选项 [0-6] (默认0: 保持不变): " TZ_CHOICE
        if [[ "$TZ_CHOICE" =~ ^[0-6]$ || -z "$TZ_CHOICE" ]]; then
            break
        fi
        log_err "无效输入，请输入 0-6 之间的数字"
    done

    case "${TZ_CHOICE:-0}" in
        1) SET_TZ="Asia/Shanghai" ;;
        2) SET_TZ="Asia/Hong_Kong" ;;
        3) SET_TZ="Asia/Tokyo" ;;
        4) SET_TZ="America/Los_Angeles" ;;
        5) SET_TZ="America/New_York" ;;
        6) SET_TZ="Europe/London" ;;
        0) SET_TZ="" ;;
        *) SET_TZ="" ;;
    esac

    if [ -n "$SET_TZ" ]; then
        if [ ! -f "/usr/share/zoneinfo/$SET_TZ" ]; then
            log_err "系统缺少时区数据 $SET_TZ（可能未安装 tzdata），时区未修改。"
        elif have timedatectl && timedatectl set-timezone "$SET_TZ" 2>/dev/null; then
            log_success "时区已更新为: $SET_TZ"
        elif ln -sf "/usr/share/zoneinfo/$SET_TZ" /etc/localtime; then
            # 容器 / 无 systemd 环境走软链接方式
            echo "$SET_TZ" > /etc/timezone 2>/dev/null
            log_success "时区已更新为: $SET_TZ (通过 /etc/localtime)"
        else
            log_err "时区设置失败，请手动执行: timedatectl set-timezone $SET_TZ"
        fi
    else
        log_info "保持当前时区不变。"
    fi

    # --- 6.3 日志限制与清理 ---
    if [ -f /etc/systemd/journald.conf ]; then
        # 只备份"真正的原始文件"。若它已经带 SysPro 签名（模块 9 先跑过），
        # 备份它等于把 Storage=none 当成用户配置，卸载时会把日志系统"恢复"成关闭。
        backup_if_pristine /etc/systemd/journald.conf /etc/systemd/journald.conf.syspro.bak || true
        sed -i 's/^#\?SystemMaxUse=.*/SystemMaxUse=100M/' /etc/systemd/journald.conf
        systemctl restart systemd-journald >/dev/null 2>&1 || \
            log_warn "journald 重启失败（若已关闭日志系统可忽略）"
    fi

    log_info "清理包管理器缓存..."
    pkg_clean >/dev/null 2>&1 || log_warn "缓存清理失败（可忽略）"
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

    # 获取内核列表（按包管理族判断，不再区分具体发行版）
    if [ "$RELEASE_FAMILY" = "apt" ]; then
        # 只取带版本号的实包，排除 linux-image-amd64 这类元包
        KERNELS=($(dpkg-query -W -f='${Package}\n' 'linux-image-*' 2>/dev/null \
                   | grep -E '^linux-image-[0-9]' | sort -V))
    elif [ "$RELEASE_FAMILY" = "rpm" ]; then
        KERNELS=($(rpm -qa 'kernel-[0-9]*' 2>/dev/null | sort -V))
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

            if ! pkg_remove "$KERNEL_PKG"; then
                log_err "卸载 $KERNEL_PKG 失败。"
                continue
            fi
            log_success "内核包 $KERNEL_PKG 已卸载。"

            if [ "$RELEASE_FAMILY" = "apt" ]; then
                local kver="${KERNEL_PKG#linux-image-}"
                local hpkg="linux-headers-${kver}"
                if dpkg -s "$hpkg" >/dev/null 2>&1; then
                    pkg_remove "$hpkg" && log_success "关联 Headers $hpkg 已卸载。"
                fi
                # 前缀没匹配上时 kver 会等于原包名，此时绝不能动 /lib/modules
                if [ -n "$kver" ] && [ "$kver" != "$KERNEL_PKG" ]; then
                    rm -f "/boot/initrd.img-${kver}"
                    rm -rf "/lib/modules/${kver}"
                fi
            else
                local kver="${KERNEL_PKG#kernel-}"
                if [ -n "$kver" ] && [ "$kver" != "$KERNEL_PKG" ]; then
                    rm -f "/boot/initramfs-${kver}.img"
                    rm -rf "/lib/modules/${kver}"
                fi
            fi
        else
            log_warn "无效编号: $NUM"
        fi
    done

    # 引导更新逻辑
    log_info "正在更新引导配置..."
    # 旧版本不管 update-grub 是否存在、是否成功，都无条件打印"已更新"。
    # 在只有 /sys/firmware/efi 却没有 grub 工具的环境里，这是假成功。
    local grub_rc=1
    if [ -f /boot/grub/grub.cfg ] || [ -f /boot/grub2/grub.cfg ]; then
        if have update-grub; then
            update-grub >/dev/null 2>&1; grub_rc=$?
        elif have grub2-mkconfig; then
            grub2-mkconfig -o /boot/grub2/grub.cfg >/dev/null 2>&1; grub_rc=$?
        fi
        if [ "$grub_rc" -eq 0 ]; then
            log_success "GRUB 引导配置已更新。"
        else
            log_err "GRUB 引导配置更新失败，重启前请手动执行 update-grub。"
        fi
        # 卸载掉内核后，grubenv 的 saved_entry 可能指向已不存在的菜单项。
        # GRUB_DEFAULT=saved 的机器不清理就会在下次开机落到空条目。
        if have grub-editenv && [ -f /boot/grub/grub.cfg ]; then
            local saved
            saved=$(grub-editenv list 2>/dev/null | awk -F= '/^saved_entry=/{print $2}')
            # saved_entry 可能是 "子菜单>条目" 的组合，只校验最后那段真实条目 ID，
            # 否则组合字符串在 grub.cfg 里必然找不到，会把正常默认项误判为失效。
            saved=${saved##*>}
            if [ -n "$saved" ] && ! grep -qF "$saved" /boot/grub/grub.cfg; then
                if have grub-set-default && grub-set-default 0 >/dev/null 2>&1; then
                    log_warn "  - 原默认内核已卸载，已把 GRUB 默认项重置为第 1 项"
                fi
            fi
        fi
    else
        log_warn "未检测到标准 GRUB 环境 (可能是 Raspberry Pi 或 U-Boot)，跳过引导更新。"
    fi
}

# 7.2 安装第三方 BBR
action_install_other_bbr() {
    clear
    echo -e "${YELLOW}======================================================${PLAIN}"
    echo -e " 准备运行第三方 BBR 安装脚本"
    echo -e " 来源: ${BBR_SCRIPT_URL}"
    echo -e " 注意: 这将从网络下载脚本并以 Root 权限执行。"
    
    # ARM 架构警告
    if [[ "$ARCH" == "arm64" || "$ARCH" == "armhf" ]]; then
        echo -e "${RED} [严重警告] 检测到您正在使用 ARM 架构 ($ARCH)！${PLAIN}"
        echo -e "${RED} 大多数一键 BBR 脚本会强制安装 x86 内核或不兼容的内核。${PLAIN}"
        echo -e "${RED} 在 Oracle Cloud ARM 或树莓派上执行此操作极大概率导致【无法开机】。${PLAIN}"
        echo -e "${RED} 除非您极其确定该脚本支持您的特定硬件，否则请按 q 退出。${PLAIN}"
    fi
    echo -e "${YELLOW}======================================================${PLAIN}"
    
    read -r -p "确认继续吗? [y/N]: " CONFIRM
    if [[ "$CONFIRM" =~ ^[yY]$ ]]; then
        # 二次确认
        if [[ "$ARCH" == "arm64" || "$ARCH" == "armhf" ]]; then
            read -r -p "请再次输入 'YES' (大写) 确认您愿意承担系统损坏风险: " DOUBLE_CHECK
            if [[ "$DOUBLE_CHECK" != "YES" ]]; then
                log_info "操作已取消。"
                return
            fi
        fi

        log_info "正在下载并执行..."
        pkg_install ca-certificates curl >/dev/null 2>&1 || log_warn "依赖安装失败，尝试继续"

        # 注意: v5.3 用的 https://git.io/kernel.sh 已经随 git.io 停止服务而失效（必然 404）。
        # 用全局变量而不是 local: cleanup_on_exit 的 trap 在函数返回后才会跑，
        # 那时 local 变量已经不可见，下载到一半被 Ctrl-C 就会在 /tmp 留下脚本。
        BBR_TMP="/tmp/syspro-bbr.$$.sh"
        if ! curl -fsSL --retry 2 --connect-timeout 10 --max-time 120 -o "$BBR_TMP" "$BBR_SCRIPT_URL"; then
            log_err "下载失败: $BBR_SCRIPT_URL"
            log_warn "可在脚本顶部修改 BBR_SCRIPT_URL 指向其它来源后重试"
            rm -f "$BBR_TMP"
            return 1
        fi

        # 至少确认拿到的是一段脚本，而不是错误页
        if [ ! -s "$BBR_TMP" ] || ! head -n 1 "$BBR_TMP" | grep -q '^#!'; then
            log_err "下载内容不是有效的 Shell 脚本，已中止。"
            rm -f "$BBR_TMP"
            return 1
        fi

        # 打印摘要，便于事后追溯到底执行了什么
        echo -e "  大小: $(wc -c < "$BBR_TMP") 字节"
        echo -e "  SHA256: $(sha256sum "$BBR_TMP" 2>/dev/null | awk '{print $1}')"
        read -r -p "确认执行该脚本? [y/N]: " CONFIRM2
        if [[ ! "$CONFIRM2" =~ ^[yY]$ ]]; then
            log_info "操作已取消。"
            rm -f "$BBR_TMP"
            return 0
        fi

        bash "$BBR_TMP"
        local rc=$?
        rm -f "$BBR_TMP"
        BBR_TMP=""
        return $rc
    else
        log_info "操作已取消。"
    fi
}


# ==============================================================================
#   7.3 bbrplus 内核 (amd64 / Debian / Ubuntu)
#
#   设计原则与 v5.9 的"可回滚"一致，且严格不越 nftx 的边界:
#     - 不执行任何在线 shell 脚本；只下载 release 的 .deb 并解包校验
#     - 安装前把 /etc/default/grub、grub.cfg、nftx 的 profile/model 复制到备份目录，
#       回滚信息写独立文件（不依赖 state.env，卸载 syspro 不会把它一起删掉）
#     - 只用 grub-reboot 做一次性启动，不改 GRUB_DEFAULT；新内核起不来，
#       下一次重启自动回原内核
#     - 只有重启后人工/CLI 确认 bbrplus 真的可用，才写 GRUB_DEFAULT=saved
#     - 全程不写 nftx 独占参数；换内核后由 nftx 自己重新探测 cc
# ==============================================================================

# 回滚信息独立落盘（uninstall_syspro 会删 state.env，不能依赖它）
bbrplus_rollback_put() {
    local k=$1 v=$2 f
    mkdir -p "$BBRPLUS_BACKUP_DIR" 2>/dev/null || return 1
    f="$BBRPLUS_BACKUP_DIR/rollback.env"
    [ -f "$f" ] || : > "$f" 2>/dev/null || return 1
    case "$v" in *$'\n'*) return 1 ;; esac
    grep -q "^${k}=" "$f" 2>/dev/null && return 0
    printf '%s=%s\n' "$k" "$v" >> "$f"
}

bbrplus_rollback_get() {
    local k=$1 f="$BBRPLUS_BACKUP_DIR/rollback.env"
    [ -f "$f" ] || return 1
    awk -F= -v key="$k" '$1==key { sub(/^[^=]*=/, ""); print; exit }' "$f" 2>/dev/null
}

# FIX-P3-4: 显式阶段状态机。rollback_put 是"只写一次"（保护原值快照），
# 阶段状态需要能覆盖更新，故单独提供 setter。
# 阶段: installed（已装待重启确认）→ confirmed（已设持久默认）→ rolled-back（已回退）
bbrplus_stage_set() {
    local stage=$1 f="$BBRPLUS_BACKUP_DIR/rollback.env"
    mkdir -p "$BBRPLUS_BACKUP_DIR" 2>/dev/null || return 1
    [ -f "$f" ] || : > "$f" 2>/dev/null || return 1
    if grep -q '^STAGE=' "$f" 2>/dev/null; then
        sed -i "s|^STAGE=.*|STAGE=${stage}|" "$f" 2>/dev/null
    else
        printf 'STAGE=%s\n' "$stage" >> "$f" 2>/dev/null
    fi
}
bbrplus_stage_get() {
    # 旧版本rollback.env无 STAGE 字段，awk 无匹配仍返回 0，不能靠 || 兜底，
    # 必须对输出判空（显示为 unknown 而非空白）。
    local st
    st=$(bbrplus_rollback_get "STAGE" 2>/dev/null)
    [ -n "$st" ] && printf '%s' "$st" || printf 'unknown'
}

bbrplus_pkg_installed() {
    [ "$RELEASE_FAMILY" = "apt" ] || return 1
    dpkg-query -W -f='${Status}' "linux-image-$BBRPLUS_KVER" 2>/dev/null \
        | grep -q 'install ok installed'
}

bbrplus_available_cc() {
    cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null
}

# 找一个非 bbrplus 的、vmlinuz + initrd 都齐备的回退内核
bbrplus_find_fallback() {
    local f kv best=""
    for f in /boot/vmlinuz-*; do
        [ -f "$f" ] || continue
        kv=${f##*/vmlinuz-}
        [ "$kv" = "$BBRPLUS_KVER" ] && continue
        [ -e "/boot/initrd.img-$kv" ] || continue
        if [ -z "$best" ] || { printf '%s\n%s\n' "$best" "$kv" | sort -V | tail -1 | grep -qxF "$kv"; }; then
            best=$kv
        fi
    done
    [ -n "$best" ] || return 1
    printf '%s' "$best"
}

# grub.cfg 里 bbrplus 的 menuentry_id_option
bbrplus_menu_id() {
    local kpat ent
    kpat=$(printf '%s' "$BBRPLUS_KVER" | sed 's/[.+]/\\&/g')
    ent=$(grep -oE "gnulinux-${kpat}-advanced-[0-9a-fA-F-]+" /boot/grub/grub.cfg 2>/dev/null | head -1)
    [ -n "$ent" ] || return 1
    printf '%s' "$ent"
}

# grub-reboot / grub-set-default 需要 "子菜单>条目" 的完整路径
# FIX-P1-3: 原先对整个 grub.cfg 取 head -1 得到 adv，双系统/多盘时第一个子菜单
# 未必是 bbrplus 条目所在的那个。改为从 ent 的 UUID 后缀反推匹配的 adv。
bbrplus_full_menu_id() {
    local ent adv uuid
    ent=$(bbrplus_menu_id) || return 1
    uuid=${ent##*-}
    adv=$(grep -oE "gnulinux-advanced-[0-9a-fA-F-]+" /boot/grub/grub.cfg 2>/dev/null \
          | grep -F -- "-$uuid" | head -1)
    if [ -n "$adv" ]; then
        printf '%s>%s' "$adv" "$ent"
    else
        # 找不到同 UUID 的子菜单时，退回纯条目 ID（grub 仍可在顶层匹配）
        printf '%s' "$ent"
    fi
}

# 只读：算出"回退内核"在 grub.cfg 里的完整菜单 ID。
# 抽成独立函数是为了让 selftest 能验证回退路径确实可用，而不必真的切内核。
bbrplus_rollback_target_id() {
    local fb fb_pat fb_id adv
    fb=$(bbrplus_rollback_get "FALLBACK_KERNEL" 2>/dev/null)
    [ -n "$fb" ] || fb=$(bbrplus_find_fallback 2>/dev/null)
    [ -n "$fb" ] || return 1
    [ -f /boot/grub/grub.cfg ] || return 1
    fb_pat=$(printf '%s' "$fb" | sed 's/[.+]/\\&/g')
    fb_id=$(grep -oE "gnulinux-${fb_pat}-advanced-[0-9a-fA-F-]+" /boot/grub/grub.cfg 2>/dev/null | head -1)
    [ -n "$fb_id" ] || return 1
    # FIX-P1-3: 同 bbrplus_full_menu_id，按 UUID 后缀匹配所属子菜单
    local fb_uuid=${fb_id##*-}
    adv=$(grep -oE "gnulinux-advanced-[0-9a-fA-F-]+" /boot/grub/grub.cfg 2>/dev/null \
          | grep -F -- "-$fb_uuid" | head -1)
    if [ -n "$adv" ]; then printf '%s>%s' "$adv" "$fb_id"; else printf '%s' "$fb_id"; fi
}

bbrplus_status() {
    local cur pkg="未安装" cc dflt fb saved
    cur=$(uname -r)
    if bbrplus_pkg_installed; then
        pkg=$(dpkg-query -W -f='${Version}' "linux-image-$BBRPLUS_KVER" 2>/dev/null)
    fi
    cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    dflt=$(awk -F= '/^GRUB_DEFAULT=/{print $2}' /etc/default/grub 2>/dev/null)
    fb=$(bbrplus_rollback_get "FALLBACK_KERNEL" 2>/dev/null)
    saved=$(grub-editenv list 2>/dev/null | tr '\n' ' ')
    printf '%-20s %s\n' '当前内核' "$cur"
    printf '%-20s %s\n' 'bbrplus 内核包' "$pkg"
    printf '%-20s %s\n' '可用拥塞控制' "$(bbrplus_available_cc)"
    printf '%-20s %s\n' '当前拥塞控制' "$cc"
    printf '%-20s %s\n' 'GRUB_DEFAULT' "${dflt:-未设置}"
    printf '%-20s %s\n' 'grubenv' "${saved:-空}"
    printf '%-20s %s\n' '回退内核' "${fb:-未记录}"
    printf '%-20s %s\n' '阶段' "$(bbrplus_stage_get)"   # FIX-P3-4
    printf '%-20s %s\n' '回滚信息' "$BBRPLUS_BACKUP_DIR/rollback.env"
    return 0
}

# 只读预检：架构 / 包管理 / GRUB / 空间 / 依赖 / 可回退内核
bbrplus_preflight() {
    local c avail_kb cur fb
    log_info "bbrplus 内核安装预检..."
    if [ "$ARCH" != "amd64" ]; then
        log_err "bbrplus 内核包只有 amd64 版本；当前架构 ${RAW_ARCH}，强装必无法开机"
        return 1
    fi
    if [ "$RELEASE_FAMILY" != "apt" ]; then
        log_err "该内核只提供 Debian/Ubuntu 的 .deb 包；当前包管理族 ${RELEASE_FAMILY}"
        return 1
    fi
    for c in curl dpkg-deb sha256sum update-grub grub-reboot grub-set-default grub-editenv lsinitramfs; do
        if ! have "$c"; then
            log_warn "  - 缺少 $c，尝试用包管理器补齐..."
            if [ "${SYSPRO_READONLY_CLI:-0}" != "1" ]; then
                pkg_install initramfs-tools grub2-common ca-certificates >/dev/null 2>&1 || true
            fi
            have "$c" || { log_err "  - 仍缺少 $c，无法继续"; return 1; }
        fi
    done
    [ -f /boot/grub/grub.cfg ] || {
        log_err "未找到 /boot/grub/grub.cfg（U-Boot / 容器环境不做内核切换）"
        return 1
    }
    # FIX-P3-10: 换内核前校验 grub 环境可写，遵循"宁可中止、不可假成功"。
    # grubenv 不可写时 grub-reboot/grub-set-default 会返回 0 却写不进 next_entry，
    # 导致一次性启动的安全网失效。
    local grubenv="/boot/grub/grubenv"
    if [ -f "$grubenv" ] && ! [ -w "$grubenv" ]; then
        log_err "grubenv 不可写（$grubenv），grub-reboot 将无法设置一次性启动项"
        return 1
    fi
    if ! grub-editenv list >/dev/null 2>&1; then
        log_err "grub-editenv 无法读取环境块（$grubenv），中止换内核"
        return 1
    fi
    have python3 || log_warn "  - 没有 python3，将用 grep 解析 GitHub release 资产"
    avail_kb=$(df -Pk /boot 2>/dev/null | awk 'NR==2{print $4}')
    case "$avail_kb" in ''|*[!0-9]*) avail_kb=0 ;; esac
    if [ "$avail_kb" -lt 250000 ]; then
        log_err "/boot 可用空间不足 250MB（当前 ${avail_kb}KB），中止"
        return 1
    fi
    cur=$(uname -r)
    fb=$(bbrplus_find_fallback) || {
        log_err "找不到可回退的原内核（/boot 下没有 vmlinuz + initrd 齐备的非 bbrplus 内核）"
        return 1
    }
    log_success "  - 预检通过: 当前内核 ${cur}，回退内核 ${fb}，/boot 可用 ${avail_kb}KB"
    return 0
}

# 从 GitHub release 下载 *_amd64.deb 资产（不执行任何远程脚本）
bbrplus_fetch() {
    local dir=$1 api json urls u f n=0
    api="https://api.github.com/repos/${BBRPLUS_REPO}/releases/tags/${BBRPLUS_TAG}"
    json="$dir/release.json"
    urls="$dir/urls.txt"
    log_info "正在查询 GitHub release: ${BBRPLUS_REPO} / ${BBRPLUS_TAG}"
    curl -fsSL --retry 2 --connect-timeout 10 --max-time 60 -o "$json" "$api" || {
        log_err "GitHub API 不可达 ($api)"
        return 1
    }
    if have python3; then
        python3 - "$json" > "$urls" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("release json parse error: %s" % e, file=sys.stderr)
    sys.exit(1)
for a in d.get("assets", []):
    name = a.get("name", "")
    url = a.get("browser_download_url", "")
    if name.endswith("_amd64.deb") and url.startswith("https://"):
        print(url)
PY
        [ $? -eq 0 ] || { log_err "release 资产解析失败"; return 1; }
    else
        grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+_amd64\.deb"' "$json" \
            | sed -E 's/.*"(https:[^"]+)".*/\1/' > "$urls"
    fi
    [ -s "$urls" ] || { log_err "该 release 没有 amd64 .deb 资产"; return 1; }
    while IFS= read -r u; do
        [ -n "$u" ] || continue
        f="$dir/$(basename "$u")"
        log_info "  - 下载 $(basename "$u")"
        curl -fsSL --retry 2 --connect-timeout 10 --max-time 300 -o "$f" "$u" || {
            log_err "下载失败: $u"
            return 1
        }
        n=$((n + 1))
    done < "$urls"
    [ "$n" -gt 0 ] || { log_err "没有下载到任何 deb"; return 1; }
    return 0
}

# 解包校验：必须是有效 deb、含对应 vmlinuz、且内核真的编进了 bbrplus
bbrplus_verify_pkgs() {
    local dir=$1 f img="" hdr="" x cfg bbr_ok=0
    for f in "$dir"/*_amd64.deb; do
        [ -f "$f" ] || continue
        if ! dpkg-deb -I "$f" >/dev/null 2>&1; then
            log_err "不是有效 deb: ${f##*/}"
            return 1
        fi
        # FIX-RUNTIME-1: 不能用 `dpkg-deb -c | grep -q`——grep -q 匹配即退出会让
        # 上游 dpkg-deb 收到 SIGPIPE；在 set -o pipefail 下整条管道返回非0，
        # 即使匹配成功 if 也判假（实测稳定 rc=2），导致 bbrplus 校验永远失败、
        # 换内核功能被完全阻断。改为把清单缓存到变量再用字符串匹配，消除管道。
        local listing
        listing=$(dpkg-deb -c "$f" 2>/dev/null)
        case "$listing" in
            *"boot/vmlinuz-${BBRPLUS_KVER}"*) img=$f ;;
            *"linux-headers-${BBRPLUS_KVER}"*) hdr=$f ;;
        esac
        printf '  %-62s %9s bytes  sha256=%s\n' "${f##*/}" "$(wc -c < "$f")" \
               "$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
    done
    [ -n "$img" ] || { log_err "缺少含 boot/vmlinuz-${BBRPLUS_KVER} 的 linux-image 包"; return 1; }

    x="$dir/unpack"
    mkdir -p "$x" 2>/dev/null
    dpkg-deb -x "$img" "$x" >/dev/null 2>&1 || { log_err "无法解包内核 deb"; return 1; }
    cfg=$(find "$x/boot" -maxdepth 1 -name "config-${BBRPLUS_KVER}" -print -quit 2>/dev/null)
    if [ -n "$cfg" ] && grep -q '^CONFIG_TCP_CONG_BBRPLUS=y' "$cfg"; then bbr_ok=1; fi
    # FIX-RUNTIME-1: 同上，避免 `grep -rl | grep -q` 在 pipefail 下的 SIGPIPE 风险
    if [ "$bbr_ok" -eq 0 ]; then
        local mod_hits
        mod_hits=$(grep -rl 'tcp_bbrplus' "$x/lib/modules" 2>/dev/null | head -1)
        [ -n "$mod_hits" ] && bbr_ok=1
    fi
    if [ "$bbr_ok" -eq 0 ]; then
        log_err "包内未找到 CONFIG_TCP_CONG_BBRPLUS=y / tcp_bbrplus，拒绝安装"
        log_err "（防止下载到同名但不带 bbrplus 的普通内核）"
        return 1
    fi
    log_success "  - 已确认包内 CONFIG_TCP_CONG_BBRPLUS=y（bbrplus 编进内核）"
    printf '%s' "$img" > "$dir/image.path"
    [ -n "$hdr" ] && printf '%s' "$hdr" > "$dir/headers.path"
    return 0
}

# 安装 + 落盘校验 + 一次性启动项
bbrplus_install_pkgs() {
    local dir=$1 img hdr="" cur fb dflt saved ent full drv f
    img=$(cat "$dir/image.path" 2>/dev/null)
    [ -n "$img" ] && [ -f "$img" ] || { log_err "image.path 缺失"; return 1; }
    [ -f "$dir/headers.path" ] && hdr=$(cat "$dir/headers.path")
    cur=$(uname -r)
    fb=$(bbrplus_find_fallback) || return 1
    dflt=$(awk -F= '/^GRUB_DEFAULT=/{print $2}' /etc/default/grub 2>/dev/null)
    # FIX-P1-4: GRUB_DEFAULT 合法值可以是带空格的菜单标题，如 "Ubuntu, with Linux 6.12"。
    # 原正则拒绝空格/引号导致 dflt 被强制置 0，回滚后启动项就错了。
    # 放宽为"非空且不含 shell 注入字符"，带空格/引号的标题原样保留。
    if [ -z "$dflt" ] || printf '%s' "$dflt" | grep -qE '[\n\r`$();&|<>]'; then
        dflt=0
    fi
    saved=$(grub-editenv list 2>/dev/null | awk -F= '/^saved_entry=/{print $2}')

    mkdir -p "$BBRPLUS_BACKUP_DIR" 2>/dev/null || { log_err "无法创建备份目录"; return 1; }
    backup_if_pristine /etc/default/grub "$BBRPLUS_BACKUP_DIR/default.grub" || true
    [ -f "$BBRPLUS_BACKUP_DIR/grub.cfg" ] || \
        cp -p /boot/grub/grub.cfg "$BBRPLUS_BACKUP_DIR/grub.cfg" 2>/dev/null
    # nftx 的参数只做快照，绝不改写
    for f in /etc/nftx_auto/profile.env /var/lib/nftx_auto/model.state; do
        [ -f "$f" ] && cp -p "$f" "$BBRPLUS_BACKUP_DIR/$(basename "$f")" 2>/dev/null
    done
    bbrplus_rollback_put "GRUB_DEFAULT" "$dflt"
    bbrplus_stage_set "installed"   # FIX-P3-4: 阶段 = 已安装待确认
    bbrplus_rollback_put "SAVED_ENTRY" "$saved"
    bbrplus_rollback_put "FALLBACK_KERNEL" "$fb"
    bbrplus_rollback_put "RUNNING_KERNEL_BEFORE" "$cur"
    log_info "已备份 GRUB / nftx 参数到 $BBRPLUS_BACKUP_DIR"
    log_info "  - 原 GRUB_DEFAULT=${dflt}，回退内核=${fb}"

    log_info "正在安装内核 deb（dpkg -i，不需要刷新 apt 索引）..."
    if [ -n "$hdr" ] && [ -f "$hdr" ]; then
        DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical \
            dpkg -i "$img" "$hdr" < /dev/null || { log_err "dpkg -i 失败"; return 1; }
    else
        DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical \
            dpkg -i "$img" < /dev/null || { log_err "dpkg -i 失败"; return 1; }
    fi

    [ -e "/boot/vmlinuz-${BBRPLUS_KVER}" ] || { log_err "安装后未找到 vmlinuz"; return 1; }
    [ -e "/boot/initrd.img-${BBRPLUS_KVER}" ] || { log_err "安装后未生成 initrd"; return 1; }
    # initrd 缺根盘/网卡驱动 = 重启必失联，这是换内核最致命的失败模式
    drv=$(lsinitramfs "/boot/initrd.img-${BBRPLUS_KVER}" 2>/dev/null \
          | grep -cE 'virtio_blk|virtio_net|ext4|nvme' || true)
    case "$drv" in ''|*[!0-9]*) drv=0 ;; esac
    if [ "$drv" -eq 0 ]; then
        log_warn "  - initrd 中未检到 virtio/ext4/nvme 关键字（压缩格式差异？），请人工确认"
    else
        log_success "  - initrd 已包含磁盘/网卡驱动（匹配 ${drv} 项）"
    fi

    update-grub >/dev/null 2>&1 || { log_err "update-grub 失败"; return 1; }
    ent=$(bbrplus_menu_id) || { log_err "GRUB 菜单里没有 bbrplus 条目"; return 1; }
    full=$(bbrplus_full_menu_id)
    bbrplus_rollback_put "BBRPLUS_MENU_ID" "$full"
    # 一次性启动：不改 GRUB_DEFAULT。起不来下次重启自动回原内核
    grub-reboot "$full" || { log_err "grub-reboot 设置失败"; return 1; }
    # FIX-P1-6: grub-reboot 返回 0 不代表引导程序真的会读 next_entry。
    # 校验 grubenv 中确实写入了 next_entry，且生成的 grub.cfg 含读取它的逻辑，
    # 否则"失败自动回原内核"的安全网是假的。
    local next_entry
    next_entry=$(grub-editenv list 2>/dev/null | awk -F= '/^next_entry=/{print $2}')
    if [ -z "$next_entry" ]; then
        log_err "grub-reboot 未生效：grubenv 中没有 next_entry，放弃一次性启动"
        return 1
    fi
    if ! grep -qE '\$\{?next_entry' /boot/grub/grub.cfg 2>/dev/null; then
        log_warn "  - grub.cfg 未检测到 next_entry 读取逻辑；该 GRUB 配置可能忽略一次性启动项"
        log_warn "  - 若重启后未进入 bbrplus，请用 bbrplus-confirm 手动设为默认"
    fi
    log_success "  - 已设置一次性启动项: $full（grubenv next_entry 已确认）"
    log_info "  - GRUB_DEFAULT 保持原值 '${dflt}'，未改持久默认（失败自动回退）"

    if [ "${BBRPLUS_KEEP_DEB:-1}" = "1" ]; then
        cp -n "$img" "$BBRPLUS_BACKUP_DIR/" 2>/dev/null
        [ -n "$hdr" ] && [ -f "$hdr" ] && cp -n "$hdr" "$BBRPLUS_BACKUP_DIR/" 2>/dev/null
    fi
    if [ -f /usr/local/bin/nftx_auto.sh ]; then
        log_warn "  - 检测到 nftx_auto：换内核后执行 nftx_auto.sh on --yes 让它重新探测 cc"
    fi
    return 0
}

# 重启后确认：只有真的跑在 bbrplus 内核且 cc 可用，才写持久默认
bbrplus_confirm() {
    local full dflt fb
    if [ "$(uname -r)" != "$BBRPLUS_KVER" ]; then
        log_err "当前内核是 $(uname -r)，不是 ${BBRPLUS_KVER}；请先重启进新内核"
        return 1
    fi
    case " $(bbrplus_available_cc) " in
        *" bbrplus "*) ;;
        *) log_err "当前内核没有 bbrplus 拥塞控制，拒绝设为持久默认"; return 1 ;;
    esac
    full=$(bbrplus_full_menu_id) || { log_err "GRUB 菜单找不到 bbrplus 条目"; return 1; }
    dflt=$(bbrplus_rollback_get "GRUB_DEFAULT" 2>/dev/null)
    [ -n "$dflt" ] || dflt=0
    if grep -qE '^GRUB_DEFAULT=' /etc/default/grub 2>/dev/null; then
        sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/' /etc/default/grub || return 1
    else
        printf '\nGRUB_DEFAULT=saved\n' >> /etc/default/grub || return 1
    fi
    grub-set-default "$full" || { log_err "grub-set-default 失败"; return 1; }
    # FIX-P1-5: update-grub 失败会导致 /etc/default/grub 已改但 grub.cfg 未同步，
    # 用户却看到"已设为持久默认"的假成功。失败时回滚本次修改并报错。
    if ! update-grub >/dev/null 2>&1; then
        log_err "update-grub 失败，正在回滚 GRUB_DEFAULT 修改"
        if grep -qE '^GRUB_DEFAULT=' "$BBRPLUS_BACKUP_DIR/default.grub" 2>/dev/null; then
            cp -p "$BBRPLUS_BACKUP_DIR/default.grub" /etc/default/grub 2>/dev/null
        else
            sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/' /etc/default/grub 2>/dev/null
        fi
        log_err "请检查 /boot 空间与 grub 配置后重试 bbrplus-confirm"
        return 1
    fi
    # 内核若是在 syspro 之外装的（手工 dpkg -i），rollback.env 里没有回退记录；
    # 这里补一条，保证后续 rollback 仍能定位到原内核的菜单项。
    fb=$(bbrplus_find_fallback 2>/dev/null)
    [ -n "$fb" ] && bbrplus_rollback_put "FALLBACK_KERNEL" "$fb"
    bbrplus_rollback_put "CONFIRMED" "$(date '+%F %T')"
    bbrplus_stage_set "confirmed"   # FIX-P3-4: 阶段 = 已确认持久默认
    log_success "已把 bbrplus 设为持久默认（GRUB_DEFAULT=saved）"
    log_info "回退: $0 bbrplus-rollback  或  grub-set-default ${dflt} && reboot"
    return 0
}

# 回退：恢复原默认项、清一次性启动项，不删内核包（保留回滚点）
bbrplus_rollback() {
    local dflt saved fb fb_target=""
    dflt=$(bbrplus_rollback_get "GRUB_DEFAULT" 2>/dev/null)
    [ -n "$dflt" ] || dflt=0
    # FIX-P1-4: 与安装侧一致，允许带空格/引号的合法菜单标题，只拒绝注入字符
    if printf '%s' "$dflt" | grep -qE '[\n\r`$();&|<>]'; then dflt=0; fi
    saved=$(bbrplus_rollback_get "SAVED_ENTRY" 2>/dev/null)
    fb=$(bbrplus_rollback_get "FALLBACK_KERNEL" 2>/dev/null)
    [ -n "$fb" ] || fb=$(bbrplus_find_fallback 2>/dev/null)

    # 没有安装记录时也要精确回到原内核，而不是笼统地 "第 1 项"
    fb_target=$(bbrplus_rollback_target_id 2>/dev/null)

    # FIX-P1-5: 先备份即将改写的 /etc/default/grub，任一步失败可回滚
    local grub_snapshot="${BBRPLUS_BACKUP_DIR}/default.grub.pre-rollback"
    cp -p /etc/default/grub "$grub_snapshot" 2>/dev/null
    if grep -qE '^GRUB_DEFAULT=' /etc/default/grub 2>/dev/null; then
        sed -i "s|^GRUB_DEFAULT=.*|GRUB_DEFAULT=${dflt}|" /etc/default/grub || return 1
    else
        printf '\nGRUB_DEFAULT=%s\n' "$dflt" >> /etc/default/grub || return 1
    fi
    grub-editenv /boot/grub/grubenv unset next_entry >/dev/null 2>&1 \
        || grub-editenv - unset next_entry >/dev/null 2>&1 || true
    local set_default_ok=0
    if [ -n "$fb_target" ]; then
        grub-set-default "$fb_target" >/dev/null 2>&1 && set_default_ok=1
    elif [ -n "$saved" ]; then
        { grub-set-default "$saved" >/dev/null 2>&1 || grub-set-default 0 >/dev/null 2>&1; } && set_default_ok=1
    else
        grub-set-default 0 >/dev/null 2>&1 && set_default_ok=1
    fi
    if ! update-grub >/dev/null 2>&1 || [ "$set_default_ok" -ne 1 ]; then
        log_err "grub-set-default 或 update-grub 失败，正在回滚 GRUB_DEFAULT 修改"
        [ -f "$grub_snapshot" ] && cp -p "$grub_snapshot" /etc/default/grub 2>/dev/null
        log_err "GRUB 配置可能处于半更新状态，请检查后重试 bbrplus-rollback"
        return 1
    fi
    bbrplus_stage_set "rolled-back"   # FIX-P3-4: 阶段 = 已回退
    log_success "已恢复 GRUB_DEFAULT=${dflt}，并清除一次性启动项"
    log_info "回退目标: ${fb_target:-${saved:-菜单第 1 项}}（${fb:-原内核}）"
    log_info "bbrplus 内核包仍保留，可再用 bbrplus-confirm 切回"
    return 0
}

# 交互菜单 / CLI 共用的安装入口
action_install_bbrplus() {
    local yes=0 force=0 want_reboot=0 a rc=0 tmpdir=""
    for a in "$@"; do
        case "$a" in
            --yes|-y)   yes=1 ;;
            --force)    force=1 ;;
            --reboot)   want_reboot=1 ;;
            *) log_warn "忽略未知参数: $a" ;;
        esac
    done

    echo -e "${YELLOW}======================================================${PLAIN}"
    echo -e " 安装 bbrplus 内核 (${BBRPLUS_KVER})"
    echo -e " 来源  : GitHub ${BBRPLUS_REPO} release ${BBRPLUS_TAG} 的 amd64 .deb"
    echo -e " 方式  : 解包校验 -> 保留原内核 -> grub-reboot 一次性启动"
    echo -e " 确认  : 重启后执行 '$0 bbrplus-confirm' 才改持久默认"
    echo -e "${RED} 风险  : 更换内核可能无法开机；仅 amd64 + Debian/Ubuntu${PLAIN}"
    echo -e "${YELLOW}======================================================${PLAIN}"

    bbrplus_preflight || return 1

    if bbrplus_pkg_installed && [ "$force" -ne 1 ]; then
        log_warn "已安装 linux-image-${BBRPLUS_KVER}，跳过重复安装"
        bbrplus_status
        log_info "重装用 --force；已重启进新内核则运行 '$0 bbrplus-confirm'"
        return 0
    fi

    if [ "$yes" -ne 1 ]; then
        read -r -p "确认下载并安装该内核? [y/N]: " CONFIRM
        case "$CONFIRM" in [yY]) ;; *) log_info "操作已取消。"; return 0 ;; esac
    fi

    tmpdir=$(mktemp -d /tmp/syspro-bbrplus.XXXXXX 2>/dev/null) || {
        log_err "无法创建临时目录"; return 1
    }
    BBRPLUS_TMP="$tmpdir"
    bbrplus_fetch "$tmpdir" || rc=1
    [ "$rc" -eq 0 ] && { bbrplus_verify_pkgs "$tmpdir" || rc=1; }
    if [ "$rc" -eq 0 ] && [ "$yes" -ne 1 ]; then
        read -r -p "包内容已校验，确认执行 dpkg -i? [y/N]: " CONFIRM2
        case "$CONFIRM2" in [yY]) ;; *) log_info "操作已取消。"; rc=2 ;; esac
    fi
    [ "$rc" -eq 0 ] && { bbrplus_install_pkgs "$tmpdir" || rc=1; }
    rm -rf "$tmpdir" 2>/dev/null
    BBRPLUS_TMP=""
    [ "$rc" -eq 2 ] && return 0
    [ "$rc" -ne 0 ] && return 1

    echo -e "${GREEN}======================================================${PLAIN}"
    log_success "bbrplus 内核已安装，一次性启动项已设置，但尚未重启"
    echo -e "  1) reboot"
    echo -e "  2) 重启后确认 uname -r 为 ${BBRPLUS_KVER}、cc 列表含 bbrplus，再执行:"
    echo -e "     $0 bbrplus-confirm"
    echo -e "  3) 起不来就再重启一次（自动回原内核），或 $0 bbrplus-rollback"
    echo -e "${GREEN}======================================================${PLAIN}"
    if [ "$want_reboot" -eq 1 ]; then
        log_warn "10 秒后重启（Ctrl-C 可取消）..."
        sleep 10
        sync
        systemctl reboot
    fi
    return 0
}

# 只读自检：真机运行时检查函数完整性、脚本语法、变量与运行环境
syspro_selftest() {
    local pass=0 fail=0 k
    _syspro_ck() {
        if eval "$2" >/dev/null 2>&1; then
            printf 'PASS  %s\n' "$1"; pass=$((pass + 1))
        else
            printf 'FAIL  %s\n' "$1"; fail=$((fail + 1))
        fi
    }
    for k in bbrplus_status bbrplus_preflight bbrplus_fetch bbrplus_verify_pkgs \
             bbrplus_install_pkgs bbrplus_confirm bbrplus_rollback \
             action_install_bbrplus syspro_selftest bbrplus_find_fallback \
             bbrplus_menu_id bbrplus_full_menu_id bbrplus_rollback_target_id \
             state_put state_del optimize_net_floor assert_reserved_untouched \
             action_uninstall_kernels dns_probe_one dns_select_best test_dns_server; do
        _syspro_ck "函数 ${k} 已定义" "declare -F ${k}"
    done
    _syspro_ck "主脚本 bash -n 通过" "bash -n '$0'"
    _syspro_ck "bbrplus 配置齐全" "test -n '$BBRPLUS_REPO' -a -n '$BBRPLUS_TAG' -a -n '$BBRPLUS_KVER'"
    _syspro_ck "保留键清单非空" "test \${#NFTX_RESERVED_KEYS[@]} -gt 20"
    _syspro_ck "CLI 分发存在" "grep -q 'bbrplus-install|--bbrplus-install' '$0'"
    _syspro_ck "菜单含 bbrplus 入口" "grep -q 'action_install_bbrplus' '$0'"
    _syspro_ck "DNS 选优随 configure_dns 自动应用" \
               "grep -qF 'dns_select_best \"\$new_dns\" apply 0' '$0'"
    _syspro_ck "DNS 选优 CLI 分发存在" "grep -qE '^[[:space:]]+dns\)' '$0'"
    _syspro_ck "DNS 探测严格匹配真实 A 记录" "grep -qF 'IN[[:space:]]+A[[:space:]]+' '$0'"
    _syspro_ck "DNS 全不可达时保守不动" "grep -qF '所有 nameserver 都不可达' '$0'"
    _syspro_ck "DNS apply 先备份再原子重写" \
               "grep -qF 'resolv.bak.' '$0' && grep -qF 'mv -f \"\$outf\" \"\$rc_file\"' '$0'"
    _syspro_ck "卸载路径不调用 sysctl --system（代码注释除外）" \
               "! grep -qE '^[[:space:]]*sysctl --system' '$0'"
    _syspro_ck "state_del 使用 PID 区分临时文件" "grep -qF 'tmp.\$\$' '$0'"
    # 以下是真机运行时检查（不猜数据、不造桩，读的是内核/GRUB 的真实状态）
    if [ -f /boot/grub/grub.cfg ]; then
        _syspro_ck "存在可回退的原内核" "bbrplus_find_fallback"
        _syspro_ck "回退内核菜单 ID 可解析" "bbrplus_rollback_target_id"
    fi
    if bbrplus_pkg_installed; then
        _syspro_ck "GRUB 能解析出 bbrplus 条目" "bbrplus_menu_id"
        case "$(uname -r)" in
            *bbrplus*) _syspro_ck "当前内核确实提供 bbrplus cc" \
                         "grep -q bbrplus /proc/sys/net/ipv4/tcp_available_congestion_control" ;;
        esac
    fi
    printf '总计 %d 项，失败 %d 项\n' "$((pass + fail))" "$fail"
    [ "$fail" -eq 0 ]
}

# 7. 手动管理子菜单
manual_tasks_menu() {
    while true; do
        clear
        echo -e "${BLUE}================================================================${PLAIN}"
        echo -e "${GREEN}    SysPro - 手动管理工具箱 (Manual Tools)                   ${PLAIN}"
        echo -e "${BLUE}================================================================${PLAIN}"
        echo -e " 1. ${RED}卸载旧内核${PLAIN}      (可视化选择，清理释放磁盘空间)"
        echo -e " 2. ${GREEN}安装其他 BBR${PLAIN}    (执行第三方在线脚本, ARM 慎用)"
        echo -e " 3. ${GREEN}安装 bbrplus 内核${PLAIN} (${BBRPLUS_KVER}, amd64, 可回滚)"
        echo -e " 4. ${GREEN}验证并设为默认${PLAIN}   (重启进新内核后执行 bbrplus-confirm)"
        echo -e " 5. ${YELLOW}回退到原内核${PLAIN}    (恢复 GRUB 默认项, 保留内核包)"
        echo -e " 6. ${YELLOW}查看 bbrplus 状态${PLAIN} (只读)"
        echo -e " 7. ${YELLOW}返回主菜单${PLAIN}"
        echo -e "${BLUE}================================================================${PLAIN}"
        echo -n "请输入选项: "
        read -r sub_choice || return 0
        
        case $sub_choice in
            1) action_uninstall_kernels; read -r -p "按回车键继续..." || return 0 ;;
            2) action_install_other_bbr; read -r -p "按回车键继续..." || return 0 ;;
            3) action_install_bbrplus; read -r -p "按回车键继续..." || return 0 ;;
            4) bbrplus_confirm; read -r -p "按回车键继续..." || return 0 ;;
            5) bbrplus_rollback; read -r -p "按回车键继续..." || return 0 ;;
            6) bbrplus_status; read -r -p "按回车键继续..." || return 0 ;;
            7) return ;;
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
    
    read -r -p "确认继续执行吗? [y/N]: " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[yY]$ ]]; then
        log_info "操作已取消。"
        return 0
    fi
    
    # 1. 创建状态标记文件
    touch "$MARK_LOGS"
    log_info "已创建状态标记: $MARK_LOGS"

    # 2. 内核层静音系统日志 (不影响应用日志)
    # 无条件重写: 老版本写进去的非法键 "audit=0" 也能借这次运行被清掉。
    # 注意: 这里绝不能写 audit=0 —— 它是内核启动参数，不是 sysctl 键，
    #       写进 sysctl.d 会让每次 sysctl --system 都报 unknown key，
    #       并把 systemd-sysctl.service 标成失败（v5.3 的老问题）。
    log_info "正在配置内核层系统日志静音..."
    {
        echo '# SysPro - 内核控制台日志静音'
        echo
    } > /etc/sysctl.d/95-syspro-silence.conf

    snapshot_sysctl kernel.printk
    snapshot_sysctl kernel.dmesg_restrict
    snapshot_sysctl kernel.core_pattern

    emit_sysctl /etc/sysctl.d/95-syspro-silence.conf kernel.printk "3 4 1 3"
    emit_sysctl /etc/sysctl.d/95-syspro-silence.conf kernel.dmesg_restrict "1"
    emit_sysctl /etc/sysctl.d/95-syspro-silence.conf kernel.core_pattern "/dev/null"

    if sysctl_file_has_keys /etc/sysctl.d/95-syspro-silence.conf && \
       sysctl -p /etc/sysctl.d/95-syspro-silence.conf >/dev/null 2>&1; then
        log_success "内核层系统日志已静音。"
    else
        log_err "内核日志参数写入失败，请检查 /etc/sysctl.d/95-syspro-silence.conf"
    fi

    # 3. 禁用系统级日志服务 (阻止系统日志收集，但保留应用日志路径)
    log_info "正在禁用系统日志服务..."
    # 重要: 绝对不要 mask systemd-journald。
    # journald 同时持有 /dev/log，任何以 StandardOutput=journal 运行的服务在 socket
    # 写满后会直接阻塞（表现为服务假死），syslog() 调用也会全部失败。
    # 只让它"不存储日志"(Storage=none) 就够了。
    local SERVICES=("rsyslog" "syslog" "rsyslogd" "kdump" "apport" "abrtd" "avahi-daemon")
    local handled=0
    
    for svc in "${SERVICES[@]}"; do
        # 检查服务单元文件是否存在 (同时检查 systemd 路径与符号链接)
        if [ -f "/etc/systemd/system/${svc}.service" ] || \
           [ -f "/lib/systemd/system/${svc}.service" ] || \
           [ -f "/usr/lib/systemd/system/${svc}.service" ]; then
            # 先记下"本来是不是启用着"，卸载时只恢复到这个状态。
            # 旧版本卸载时无条件 enable，会把管理员主动禁用的 auditd / kdump
            # / avahi-daemon 重新拉起来 —— 那是制造新变更，不是恢复。
            svc_snapshot "$svc"
            systemctl stop "$svc" >/dev/null 2>&1
            systemctl disable "$svc" >/dev/null 2>&1
            systemctl mask "$svc" >/dev/null 2>&1
            log_info "  - 服务已停止并屏蔽: $svc"
            handled=$((handled + 1))
        fi
    done
    
    if [ "$handled" -eq 0 ]; then
        log_info "  - 未检测到可被禁用的系统日志服务 (已跳过)"
    fi

    # 4. 配置 Journald 不存储日志 (仅作为转发通道)
    log_info "配置 systemd-journald 不存储日志..."
    mkdir -p /etc/systemd
    if ! backup_if_pristine /etc/systemd/journald.conf /etc/systemd/journald.conf.syspro.bak; then
        # 原机器上根本没有 journald.conf（容器 / 极简镜像很常见），
        # 或者它已经是本脚本写的。记下来: 卸载时应该删掉这个文件，
        # 而不是"恢复"一份我们自己的 Storage=none 配置。
        state_put "$FLAG_JOURNALD_ABSENT" "1"
    fi
    cat > /etc/systemd/journald.conf << EOF
[Journal]
# 由 SysPro 写入（原文件已备份为 journald.conf.syspro.bak，卸载时自动还原）
# 本文件为整体覆盖: 原文件里的 RateLimit* / SystemMaxUse 等设置在此模式下不再生效。
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

    # 必须重启 journald，否则 Storage=none 要等到下次开机才生效
    # （旧版本写完配置就直接往下走，等于这一项当场没有生效）。
    # 只 restart 不 mask: journald 仍持有 /dev/log，服务写日志不会阻塞。
    if systemctl restart systemd-journald >/dev/null 2>&1; then
        log_info "  - systemd-journald 已重启，Storage=none 立即生效"
    else
        log_warn "  - systemd-journald 重启失败，配置将在下次开机生效"
    fi

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
    
    # 重建记账文件必须用正确的属主/权限，否则 last / who / lastb 会直接失效：
    #   wtmp 664 root:utmp   btmp 660 root:utmp   lastlog 664 root:utmp
    touch /var/log/wtmp /var/log/btmp /var/log/lastlog
    chown root:utmp /var/log/wtmp /var/log/btmp /var/log/lastlog 2>/dev/null
    chmod 664 /var/log/wtmp /var/log/lastlog 2>/dev/null
    chmod 660 /var/log/btmp 2>/dev/null

    # 普通日志文件保持 644 root:root
    touch /var/log/auth.log /var/log/syslog /var/log/messages
    chown root:root /var/log/auth.log /var/log/syslog /var/log/messages 2>/dev/null
    chmod 644 /var/log/auth.log /var/log/syslog /var/log/messages 2>/dev/null

    # /var/log 本身保持默认 755 root:root 即可，注意不要再 chmod -R
    [ -d /var/log ] && chmod 755 /var/log
    
    log_success "系统日志文件已清理，应用日志目录保持可写。"

    # 6. 设置系统服务的日志级别为最低
    log_info "配置系统服务日志级别..."
    cat > /etc/profile.d/syspro-silent.sh << EOF
# 仅设置系统级日志级别，不影响应用日志
export SYSTEMD_LOG_LEVEL=err
EOF
    chmod +x /etc/profile.d/syspro-silent.sh

    # 7. 刷新系统配置
    # 只重放本模块自己写的那份文件。
    # 绝不能用 sysctl --system: 它会把 /etc/sysctl.d 下所有文件再砸一遍，
    # 而 nftx 已在运行时把 somaxconn / tcp_mem / netdev_budget 调到实测最优点，
    # 重放地板值等于当场抹掉它的成果；而 nftx 的漂移检测只盯 4 个键，
    # 不会自愈，要等 6 小时后的重整才会修回来。
    systemctl daemon-reload
    sysctl -p /etc/sysctl.d/95-syspro-silence.conf >/dev/null 2>&1

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
        # FIX-P3-3: 若存在伴生标记，读取备份来源时间用于日志；无标记则是旧版备份，
        # 仍按原样恢复（向后兼容）。恢复后一并清掉标记。
        local origin=""
        [ -f "${backup_file}.syspro-origin" ] && \
            origin=$(awk -F= '/^time=/{print $2; exit}' "${backup_file}.syspro-origin" 2>/dev/null)
        # -p: 保留权限/属主。fstab、system.conf 这类文件一旦变成 644 之外的模式，
        # systemd 和 mount 都会报权限错误，而这正是"恢复"最不该引入的副作用。
        if cp -p "$backup_file" "$target_file" 2>/dev/null; then
            rm -f "$backup_file" "${backup_file}.syspro-origin"
            [ -n "$origin" ] && log_info "已恢复${desc}（原始备份: ${origin}）" || log_info "已恢复${desc}"
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
    if [ ! -f "$MARK_LOGS" ]; then
        return 0
    fi

    log_info "检测到日志系统曾被禁用，正在恢复..."

    # FIX-P2-3: 原代码 chattr -R -i /var/log 递归清除整个日志目录的 immutable，
    # 会把管理员/合规为 audit.log 等设置的 +i 一并清掉；本脚本从未给 /var/log 加过锁。
    # 只对本脚本确实改动的记账文件精确解锁。
    if command -v chattr >/dev/null 2>&1; then
        chattr -i /var/log/wtmp /var/log/btmp /var/log/lastlog 2>/dev/null
    fi

    # 注意: 这里绝对不要 chmod -R 755 /var/log。
    # 那会把 auth.log 等敏感日志一并变成全局可读，并破坏原本 600/640 的
    # 应用日志权限（v5.3 的严重副作用）。只修正目录本身和记账文件。
    [ -d /var/log ] && chmod 755 /var/log
    touch /var/log/wtmp /var/log/btmp /var/log/lastlog 2>/dev/null
    chown root:utmp /var/log/wtmp /var/log/btmp /var/log/lastlog 2>/dev/null
    chmod 664 /var/log/wtmp /var/log/lastlog 2>/dev/null
    chmod 660 /var/log/btmp 2>/dev/null

    rm -f /etc/sysctl.d/95-syspro-silence.conf
    rm -f /etc/profile.d/syspro-silent.sh

    if [ -f /etc/systemd/journald.conf.syspro.bak ]; then
        restore_from_backup "/etc/systemd/journald.conf.syspro.bak" \
                            "/etc/systemd/journald.conf" "journald 配置"
    elif [ "$(state_get "$FLAG_JOURNALD_ABSENT" 2>/dev/null)" = "1" ]; then
        # 原本就没有这个文件（或只剩我们自己写的），删掉才是真正的还原
        rm -f /etc/systemd/journald.conf
        log_info "  - 原系统本无 journald.conf，已删除本脚本创建的副本"
    elif [ -f /etc/systemd/journald.conf ]; then
        # 没有备份时至少恢复成能存日志的状态
        printf '[Journal]\nStorage=auto\nSystemMaxUse=200M\n' > /etc/systemd/journald.conf
    fi

    # journald 无条件恢复: 它持有 /dev/log，任何情况下都不能缺
    systemctl unmask systemd-journald 2>/dev/null
    systemctl enable systemd-journald 2>/dev/null
    systemctl restart systemd-journald 2>/dev/null

    # 其余服务按快照还原。
    # 旧版本在这里无条件 systemctl enable 一整串服务，等于把管理员主动禁用的
    # auditd / kdump / avahi-daemon 全部重新拉起来 —— 是"制造变更"而不是"恢复"。
    # FIX-P1-10: auditd 由 cleanup_optimizations 的 MARK_AUDIT 专用分支单一处理。
    # 若这里也放 auditd，同一次卸载会两次 svc_restore auditd（两次服务重启窗口）。
    local SERVICES=("rsyslog" "syslog" "rsyslogd" "kdump" "apport" "abrtd" "avahi-daemon")
    for svc in "${SERVICES[@]}"; do
        svc_restore "$svc"
    done

    rm -f "$MARK_LOGS"
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
        rm -f /etc/systemd/system/syspro-doh.service "$MARK_DOH"

        # 只有确认"这个二进制是本脚本下载的"才删。
        # 旧版本的注释写着"可以确定由本脚本放置"，但 install_cloudflared 里
        # 明确有"复用已存在二进制"的分支 —— 那句话是错的，会删掉用户自己装的。
        if [ "$(state_get "$FLAG_CLOUDFLARED" 2>/dev/null)" = "1" ]; then
            rm -f /usr/local/bin/cloudflared
            log_info "  - DoH 服务与本脚本安装的 cloudflared 已移除"
        else
            if [ -f /usr/local/bin/cloudflared ]; then
                log_warn "  - DoH 服务已移除；/usr/local/bin/cloudflared 无法确认来源，已保留"
            else
                log_info "  - DoH 服务已移除"
            fi
        fi
        # FIX-RUNTIME-2: 清理 dnscrypt-proxy 后端。只删本脚本生成的配置与标志；
        # dnscrypt-proxy 包本身可能仍被系统其他服务使用，不擅自卸载。
        if [ "$(state_get "$FLAG_DNSCRYPT" 2>/dev/null)" = "1" ]; then
            rm -f "$DOH_DNSCRYPT_CONF" /var/log/syspro-dnscrypt-query.log /var/log/syspro-dnscrypt-nx.log
            log_info "  - 已移除本脚本生成的 dnscrypt-proxy 配置（dnscrypt-proxy 包保留）"
        fi
        systemctl daemon-reload 2>/dev/null
    fi
    
    # 清理防火墙规则（兼容早期版本可能留下的 53 端口规则）
    # FIX-P3-9: 这些规则是 v5.3 老版本留下的，本脚本当前版本从不添加 iptables 规则。
    # 只有当确认本脚本曾部署过 DoH（服务文件或标记存在）时才清理，避免误删用户
    # 自己添加的、规则内容恰好相同的 53 端口规则。
    local DEFAULT_IFACE
    DEFAULT_IFACE=$(ip route 2>/dev/null | awk '/^default/ {print $5; exit}')
    local had_doh=0
    [ -f /etc/systemd/system/syspro-doh.service ] || [ -f "$MARK_DOH" ] && had_doh=1
    if [ "$had_doh" -eq 1 ] && [ -n "$DEFAULT_IFACE" ] && command -v iptables >/dev/null 2>&1; then
        # -C 先检查规则存在再 -D，避免盲目删除
        iptables -C INPUT -i "$DEFAULT_IFACE" -p udp --dport 53 -j DROP 2>/dev/null \
            && iptables -D INPUT -i "$DEFAULT_IFACE" -p udp --dport 53 -j DROP 2>/dev/null
        iptables -C INPUT -i "$DEFAULT_IFACE" -p tcp --dport 53 -j DROP 2>/dev/null \
            && iptables -D INPUT -i "$DEFAULT_IFACE" -p tcp --dport 53 -j DROP 2>/dev/null
        iptables -C INPUT -i docker0 -p udp --dport 53 -j ACCEPT 2>/dev/null \
            && iptables -D INPUT -i docker0 -p udp --dport 53 -j ACCEPT 2>/dev/null
        iptables -C INPUT -i docker0 -p tcp --dport 53 -j ACCEPT 2>/dev/null \
            && iptables -D INPUT -i docker0 -p tcp --dport 53 -j ACCEPT 2>/dev/null
        log_info "  - 防火墙规则已清理"
    fi
    
    # 恢复 SSH 配置
    # drop-in 是后加的，必须先删，否则 sshd 仍会读到 UseDNS no
    local sshd_dropin
    sshd_dropin=$(state_get "$FLAG_SSHD_DROPIN" 2>/dev/null)
    if [ -n "$sshd_dropin" ] && [ -f "$sshd_dropin" ]; then
        rm -f "$sshd_dropin"
        log_info "  - 已移除 ${sshd_dropin##*/}"
    fi

    if [ -f /etc/ssh/sshd_config.syspro.bak ]; then
        cp -p /etc/ssh/sshd_config.syspro.bak /etc/ssh/sshd_config
        rm -f /etc/ssh/sshd_config.syspro.bak /etc/ssh/sshd_config.syspro.stage
        local ssh_svc
        ssh_svc=$(detect_ssh_service)
        if [ -n "$ssh_svc" ] && systemctl reload-or-restart "$ssh_svc" 2>/dev/null; then
            log_info "  - SSH 配置已恢复"
        else
            # FIX-P1-8: errors 此前从未递增，return 恒为 0，内部失败被吞
            errors=$((errors + 1))
            log_warn "  - SSH 配置已恢复，但服务重载失败，请手动执行 sshd -t 检查"
        fi
    fi

    # 恢复 Shell 环境
    rm -f /etc/profile.d/syspro.sh

    # 恢复地址选择偏好（若曾被写入）；备份存在但恢复失败时计入错误
    if [ -f /etc/gai.conf.syspro.bak ]; then
        restore_from_backup "/etc/gai.conf.syspro.bak" "/etc/gai.conf" "gai.conf 地址选择" 2>/dev/null \
            || errors=$((errors + 1))
    fi

    return $errors
}

# 恢复系统 DNS
restore_dns() {
    log_info "正在重置系统 DNS 配置..."

    if command -v chattr >/dev/null 2>&1; then
        chattr -i /etc/resolv.conf 2>/dev/null
    fi

    # nsswitch 里的 resolve 是本脚本屏蔽 resolved 时摘掉的，一并还原
    restore_nss_resolve

    # 优先还原 configure_dns 之前的原始文件（可能是指向 stub-resolv.conf 的软链接）。
    # v5.3 直接写死 8.8.8.8，会把 DHCP / cloud-init 下发的内网 DNS 永久丢掉。
    local rc=0 restored=0
    if [ -e /etc/resolv.conf.syspro.bak ] || [ -L /etc/resolv.conf.syspro.bak ]; then
        # FIX-P1-9: 恢复前校验当前文件是否仍带本脚本签名。
        # 本脚本写入的 resolv.conf 首行是 "# SysPro ..."；若当前文件不含该签名，
        # 说明优化之后又被用户/cloud-init/DHCP/Ansible 重新下发过，此时用旧备份
        # 覆盖会永久丢失那些后续修改。保留当前文件，仅提示用户。
        local current_signature=""
        [ -f /etc/resolv.conf ] && current_signature=$(head -1 /etc/resolv.conf 2>/dev/null)
        case "$current_signature" in
            "# SysPro"*)
                # 用 mv -f 直接覆盖，不要先 rm: 万一是跨设备/权限问题导致 mv 失败，
                # 先 rm 会让机器连一个 resolv.conf 都不剩。
                if mv -f /etc/resolv.conf.syspro.bak /etc/resolv.conf; then
                    rm -f /etc/resolv.conf.syspro.bak.syspro-origin   # FIX-P3-3: 清理伴生标记
                    log_info "  - /etc/resolv.conf 已按原始备份恢复"
                    restored=1
                else
                    log_err "  - 恢复 /etc/resolv.conf 失败，请手动处理"
                    rc=1
                fi
                ;;
            *)
                log_warn "  - /etc/resolv.conf 已被其他程序或用户修改（无 SysPro 标记），保留当前配置不覆盖"
                log_info "  - 原始备份仍在 /etc/resolv.conf.syspro.bak，如需可手动比对"
                restored=1
                ;;
        esac
    fi

    # 只要本脚本屏蔽过 systemd-resolved 就必须解除。
    # 注意这里**不看** resolv.conf 是不是软链接: 屏蔽发生在前、resolv.conf 的形态
    # 在后，两者没有必然关系。旧版本只在"恢复出来的是软链接"时才 unmask，
    # 结果是原机器用普通文件时，卸载完 resolved 仍然是 masked，下次开机 DNS 全挂。
    if state_has "SVC:systemd-resolved"; then
        svc_restore systemd-resolved
        systemctl start systemd-resolved >/dev/null 2>&1
    elif [ "$(systemctl is-enabled systemd-resolved 2>/dev/null)" = "masked" ]; then
        # FIX-P0-4: 老版本没留快照，但确实被 mask 过。
        # 原代码附加了 `&& [ "$restored" -eq 1 ]`：只跑过优化项 1/2/3、从未执行
        # configure_dns 的机器没有 resolv.conf 备份，restored=0，这个专为老版本
        # 设计的 unmask 分支就永远进不来，卸载后 resolved 仍是 masked、下次开机 DNS 全挂。
        # mask 与 resolv.conf 备份无必然关系，去掉这个条件。
        systemctl unmask systemd-resolved >/dev/null 2>&1
        systemctl enable --now systemd-resolved >/dev/null 2>&1
        log_info "  - systemd-resolved 已解除屏蔽并启用"
    fi

    if [ "$restored" -eq 1 ]; then
        return $rc
    fi

    # 没有备份 = 本脚本从来没改过 resolv.conf（configure_dns 一定先备份再写）。
    # 这种情况下**什么都不做** 才是正确行为。
    #
    # 旧版本在这里兜底写死 8.8.8.8 / 1.1.1.1，后果是: 只在别的模块做过优化的机器，
    # 一执行"卸载"，DHCP / cloud-init 下发的内网 DNS 就被永久替换成公共 DNS，
    # 内网域名（数据库、内部 API）当场解析不了。
    log_warn "  - 未找到 /etc/resolv.conf 的原始备份，说明本脚本未修改过它，保持现状"
    log_info "    如确需手动指定: printf 'nameserver 1.1.1.1\n' > /etc/resolv.conf"
    return 0
}

# 清理常规优化配置
cleanup_optimizations() {
    log_info "正在清理优化配置..."
    
    # ZRAM（只清理本脚本创建的）
    # 判据用标记文件 / unit 内容签名，不再"同名文件存在就删"——
    # zram.service 是用户自建 unit 的常见名字。
    if [ -f "$MARK_ZRAM" ] || is_syspro_zram_unit; then
        # FIX-P0-3: 同 optimize_memory，swapoff 失败时不可删 unit 与标记
        local zram_busy=0
        if grep -q '^/dev/zram0' /proc/swaps 2>/dev/null; then
            if swapoff /dev/zram0 >/dev/null 2>&1; then
                :
            else
                zram_busy=1
                log_warn "  - zram 仍有页面占用，未能卸载；保留配置与标记"
            fi
        fi
        if [ "$zram_busy" -eq 0 ]; then
            systemctl disable --now zram >/dev/null 2>&1
            rm -f /etc/systemd/system/zram.service /usr/local/bin/zram-start.sh "$MARK_ZRAM"
            log_info "  - ZRAM 已移除"
        fi
    elif [ -f /etc/systemd/system/zram.service ]; then
        log_info "  - 检测到非本脚本的 zram.service，已保留"
    fi
    
    # 内核参数文件
    local sysctl_files=(
        "/etc/sysctl.d/95-syspro-silence.conf"
        "/etc/sysctl.d/97-syspro-latency.conf"
        "/etc/sysctl.d/99-syspro-swap.conf"
        "/etc/sysctl.d/98-syspro-security.conf"
        "/etc/sysctl.d/96-no-audit.conf"
        "/etc/sysctl.d/99-syspro-disable-ipv6.conf"
        "$NET_FLOOR_CONF"
    )
    local sysctl_removed=0
    local ipv6_was_disabled=0
    for f in "${sysctl_files[@]}"; do
        if [ -f "$f" ]; then
            [ "$f" = "/etc/sysctl.d/99-syspro-disable-ipv6.conf" ] && ipv6_was_disabled=1
            rm -f "$f"
            sysctl_removed=$((sysctl_removed + 1))
        fi
    done
    if [ "$sysctl_removed" -gt 0 ]; then
        log_info "  - 已移除 $sysctl_removed 个内核参数文件"
    fi
    if [ "$ipv6_was_disabled" -eq 1 ]; then
        sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1
        sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1
        log_info "  - 内核 IPv6 已重新启用"
    fi
    
    # Swap: 只删本脚本创建的，用户原有的 /swapfile 一律不动
    if [ -f "$MARK_SWAP" ]; then
        if [ -f /swapfile ]; then
            swapoff /swapfile 2>/dev/null
            rm -f /swapfile
            [ -f /etc/fstab ] && sed -i '\:^/swapfile[[:space:]]:d' /etc/fstab 2>/dev/null
            log_info "  - 本脚本创建的 Swap 文件已移除"
        fi
        rm -f "$MARK_SWAP"
    elif [ -f /swapfile ]; then
        log_warn "  - 检测到 /swapfile 但非本脚本创建，已保留（确认无用请手动删除）"
    fi
    
    # fstab
    # FIX-P1-9: 与 resolv.conf 同理，fstab 若被用户/其他工具改过（无 SysPro 标记），
    # 用旧备份覆盖会丢失后续修改。本脚本写入的 fstab 会在挂载选项里留下 noatime 标记。
    if [ -f /etc/fstab.syspro.bak ]; then
        if grep -q 'noatime' /etc/fstab 2>/dev/null; then
            restore_from_backup "/etc/fstab.syspro.bak" "/etc/fstab" "fstab 配置" && mount -o remount / 2>/dev/null
        else
            log_warn "  - /etc/fstab 已被其他程序或用户修改（无 SysPro noatime 标记），保留当前配置不覆盖"
            log_info "  - 原始备份仍在 /etc/fstab.syspro.bak，如需可手动比对"
        fi
    fi
    
    # Udev 规则: 新版文件名 + 旧版文件名都要处理
    local udev_changed=0
    if [ -f /etc/udev/rules.d/60-syspro-io-scheduler.rules ]; then
        rm -f /etc/udev/rules.d/60-syspro-io-scheduler.rules
        udev_changed=1
    fi
    if [ -f /etc/udev/rules.d/60-io-scheduler.rules ] && \
       grep -q 'SysPro' /etc/udev/rules.d/60-io-scheduler.rules 2>/dev/null; then
        rm -f /etc/udev/rules.d/60-io-scheduler.rules
        udev_changed=1
    fi
    # 当初为了保护"别人的同名规则"做的备份，现在还原回去
    if [ -f /etc/udev/rules.d/60-io-scheduler.rules.syspro-legacy.bak ]; then
        mv -f /etc/udev/rules.d/60-io-scheduler.rules.syspro-legacy.bak \
              /etc/udev/rules.d/60-io-scheduler.rules
        log_info "  - 已还原非本脚本的 60-io-scheduler.rules"
    fi
    if [ "$udev_changed" -eq 1 ]; then
        if command -v udevadm >/dev/null 2>&1; then
            udevadm control --reload 2>/dev/null
            udevadm trigger --subsystem-match=block 2>/dev/null
        fi
        log_info "  - Udev I/O 调度规则已移除"
    fi
    
    # Systemd 额外配置: 只删本脚本写的 drop-in，不要整目录 rm -rf
    # （用户可能自己在 ssh.service.d 里放过别的配置，v5.3 会一并删掉）
    #
    # 注意: 优化时写了三份（ssh / sshd / systemd-journald），这里必须覆盖全部，
    # 旧版本只列了前两个，journald 的 drop-in 会永久留在机器上。
    local d
    for d in /etc/systemd/system/*.service.d; do
        [ -d "$d" ] || continue
        if [ -f "$d/99-syspro-oom.conf" ]; then
            rm -f "$d/99-syspro-oom.conf"
            rmdir "$d" 2>/dev/null
            log_info "  - 已移除 ${d##*/}/99-syspro-oom.conf"
        fi
    done

    # nftx 协同层
    if [ -f "$NFTX_DROPIN" ]; then
        rm -f "$NFTX_DROPIN"
        rmdir "${NFTX_DROPIN%/*}" 2>/dev/null
        log_info "  - 已移除 nftx_auto 的资源 drop-in（nftx 本身不受影响）"
    fi
    if [ -f "$NET_MODULES_CONF" ]; then
        rm -f "$NET_MODULES_CONF"
        log_info "  - 已移除模块预载配置（已加载的模块保持加载，重启后不再自动加载）"
    fi

    rm -f /etc/security/limits.d/99-disable-core.conf
    restore_from_backup "/etc/systemd/system.conf.syspro.bak" "/etc/systemd/system.conf" "Systemd 主配置"
    
    # Logind
    if [ -f /etc/systemd/logind.conf.syspro.bak ]; then
        mv /etc/systemd/logind.conf.syspro.bak /etc/systemd/logind.conf
        # 同样不重启 logind: 会重建会话对象，可能带走当前会话下的进程
        log_info "  - Logind 配置已恢复（重启后生效）"
    fi

    # 恢复 auditd（若曾被本脚本禁用）
    if [ -f "$MARK_AUDIT" ]; then
        if state_has "SVC:auditd"; then
            svc_restore auditd
        else
            # 老版本没留快照。优化时只有在 auditd 处于 active/enabled 才会动它，
            # 所以这里按"恢复启用"处理是安全的。
            systemctl unmask auditd 2>/dev/null
            systemctl enable auditd 2>/dev/null
            systemctl start auditd 2>/dev/null
            log_info "  - auditd 已恢复启用"
        fi
        rm -f "$MARK_AUDIT"
    fi

    # CPU 频率策略回滚
    local gov
    if gov=$(state_get "$KEY_GOVERNOR" 2>/dev/null) && [ -n "$gov" ]; then
        local cg gov_n=0
        for cg in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            if [ -w "$cg" ] && echo "$gov" > "$cg" 2>/dev/null; then
                gov_n=$((gov_n + 1))
            fi
        done
        [ "$gov_n" -gt 0 ] && log_info "  - CPU governor 已恢复为 $gov（$gov_n 个核心）"
    fi
    if [ "$(state_get "$FLAG_CSTATES" 2>/dev/null)" = "1" ] && have cpupower; then
        if cpupower idle-set -E >/dev/null 2>&1; then
            log_info "  - 深度 C-State 已重新启用"
        else
            log_warn "  - 深度 C-State 恢复失败，重启后由内核默认值接管"
        fi
    fi

    # 关键: 删掉 sysctl.d 里的文件并不会改回"当前已生效"的值。
    # 旧版本在这里凭记忆写了一批"发行版默认值"，问题是那些值并不通用:
    #   kernel.sysrq   RHEL 默认 16、Debian 默认 438
    #   core_pattern   现代发行版默认是 systemd-coredump 管道，不是 "core"
    # 于是"卸载"反而在别人的机器上制造了新问题。
    # 现在改为按 /var/lib/syspro/state.env 里记录的原值逐条回放。
    restore_sysctl_snapshots

    # 本脚本自己加的日志轮转配置
    rm -f /etc/logrotate.d/syspro

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
    echo "    3. DNS 配置 - 已按原始备份还原（无备份则保持现状，不再写死公共 DNS）"
    echo "    4. SSH 配置 - 已从备份恢复 (如存在)"
    echo "    5. I/O 优化 - Udev 规则已移除"
    echo "    6. 系统优化 - 内核参数、fstab、ZRAM 已按快照回滚"
    echo "    7. Systemd 配置 - 主配置与 logind 已恢复"
    echo "    8. nftx 协同 - 资源 drop-in 与模块预载配置已移除（nftx 本身不受影响）"
    echo "    9. bbrplus 内核 - 不在卸载范围（换内核属引导层变更，请用手动工具箱回退）"
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
    echo -e "${RED}   - 移除本脚本创建的 Swap 文件        ${PLAIN}"
    echo -e "${RED}   - 还原系统配置文件                  ${PLAIN}"
    echo -e "${RED}----------------------------------------------------------------${PLAIN}"
    echo -e "${YELLOW} 注意: 此操作不可逆，请确保已备份重要数据！${PLAIN}"
    echo -e "${RED}================================================================${PLAIN}"
    
    read -r -p "确认继续卸载吗? [y/N]: " CONFIRM
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

    # 这里刻意**不调用** sysctl --system。
    # 那会把 /etc/sysctl.d 下所有文件重放一遍 —— 包括 nftx 已经按实测值调好的
    # 参数被重新按"地板值"覆盖。脚本自己在 optimize_logging_killer 的注释里
    # 明确写过"绝不能用 sysctl --system"，卸载路径不应该违反同一条规矩。
    # 该恢复的运行时参数已经由 restore_sysctl_snapshots 精确回放了。

    # --- 6. 清理状态文件（放在最后: 前面的步骤还要读它）---
    rm -f "$STATE_FILE" 2>/dev/null
    rmdir "$STATE_DIR" 2>/dev/null

    # --- 7. 显示卸载摘要 ---
    show_uninstall_summary
}

show_menu() {
    clear
    echo -e "${BLUE}================================================================${PLAIN}"
    echo -e "${GREEN}    SysPro High Performance Network Edition   ${PLAIN}"
    echo -e "${BLUE}================================================================${PLAIN}"
    echo -e " 1. ${GREEN}I/O 优化${PLAIN}   (Noatime, Udev 调度)"
    echo -e " 2. ${GREEN}CPU 与熵池${PLAIN}      (调度器参数, BBR 适配)"
    echo -e " 3. ${GREEN}进程与内存${PLAIN}      (禁用 Auditd, 智能 ZRAM, 文件句柄)"
    echo -e " 4. ${GREEN}安全配置${PLAIN}        (隐藏内核地址, dmesg 限制)"
    echo -e " 5. ${GREEN}接入与 DNS${PLAIN}      (SSH, DoH/UDP 双模 + DNS 探测选优)"
    echo -e " 6. ${GREEN}维护与清理${PLAIN}      (常用工具, 时区, 缓存清理)"
    echo -e " 7. ${YELLOW}手动管理工具${PLAIN}    (bbrplus 内核 / 卸载内核 / 其他 BBR)"
    echo -e " a. ${GREEN}网络底座${PLAIN}        (模块预载/容量地板, 为 nftx 预留空间)"
    echo -e "${BLUE}----------------------------------------------------------------${PLAIN}"
    echo -e " 9. ${RED}关闭日志系统${PLAIN}    (停 syslog/kdump，journald 只转发不落盘)"
    echo -e "${BLUE}----------------------------------------------------------------${PLAIN}"
    echo -e " 0. ${GREEN}一键执行所有优化${PLAIN}    (推荐: 先运行此项，重启后再跑 nftx_auto.sh)"
    echo -e " 8. ${RED}卸载/还原${PLAIN}       (还原系统默认状态)"
    echo -e " q. 退出"
    echo -e "${BLUE}================================================================${PLAIN}"
    echo -n "请输入选项: "
    # read 失败 = stdin 已关闭（SSH 断开、管道结束）。
    # 返回非 0 让主循环退出，否则菜单会在一秒内空转几千次，把 CPU 打满。
    read -r choice || return 1

    case $choice in
        1) optimize_disk_io ;;
        2) optimize_compute ;;
        3) optimize_systemd; optimize_memory ;;
        4) optimize_security ;;
        5) optimize_access ;;
        6) maintenance_tasks ;;
        7) manual_tasks_menu ;;
        a|A) optimize_net_floor ;;
        9) optimize_logging_killer ;;
        8) uninstall_syspro ;;
        0)
            optimize_disk_io
            optimize_compute
            optimize_systemd
            optimize_memory
            optimize_security
            # 先把容量与模块准备好，再动 DNS/SSH（接入层的改动不影响网络底座）
            optimize_net_floor
            optimize_access
            maintenance_tasks
            echo -e "\n${GREEN}SysPro 基础优化已完成！${PLAIN}"
            echo -e "${YELLOW}建议: 1. 重启服务器 (reboot)。${PLAIN}"
            echo -e "${YELLOW}      2. 运行 nftx_auto.sh 做网络协议栈动态调优。${PLAIN}"
            ;;
        q) exit 0 ;;
        *) log_err "无效输入，请重新选择。" ;;
    esac
    return 0
}


# FIX-P3-11: dry-run 预览（plan）——只读列出"一键优化 0"将执行的所有模块，
# 不执行任何写操作。给用户一个零风险的"看清楚再动手"入口。
cli_plan() {
    echo "SysPro 执行计划（dry-run，只读预览，不会修改系统）"
    echo "  0 一键优化将按顺序执行:"
    echo "    1. I/O 优化 (Noatime, Udev 调度)"
    echo "    2. CPU 与熵池 (调度器参数, BBR 适配)"
    echo "    3. 进程与内存 (禁用 Auditd, 智能 ZRAM, 文件句柄)"
    echo "    4. 安全配置 (隐藏内核地址, dmesg 限制)"
    # FIX-RUNTIME-5: 顺序与主菜单 case 0 保持一致——网络底座(a)在接入DNS(5)之前。
    # 实际代码注释明确写了"先把容量与模块准备好，再动 DNS/SSH"，原 plan 顺序写反了，
    # dry-run 预览与真实执行不符会误导用户判断。
    echo "    a. 网络底座 (模块预载/容量地板)"
    echo "    5. 接入与 DNS (SSH, DoH/UDP 双模 + DNS 探测选优)"
    echo "    6. 维护与清理 (常用工具, 时区, 缓存清理)"
    echo "  卸载 (菜单 8) 将:"
    echo "    还原 state.env 快照中的内核参数、按备份恢复配置文件、"
    echo "    移除本脚本创建的 ZRAM/Swap/DoH 与标记文件"
    echo "  提示: 以上模块会改动系统配置，请在理解后于交互菜单中执行。"
    return 0
}

# FIX-P3-12: 巡检用 JSON 状态输出（只读，不改日志函数、不影响现有 CLI）
cli_status_json() {
    local cur cc stage fb pkg="false"
    cur=$(uname -r 2>/dev/null)
    cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    stage=$(bbrplus_stage_get 2>/dev/null)
    fb=$(bbrplus_rollback_get "FALLBACK_KERNEL" 2>/dev/null)
    bbrplus_pkg_installed && pkg="true"
    printf '{"kernel":"%s","cc":"%s","bbrplus_pkg":%s,"stage":"%s","fallback_kernel":"%s"}\n' \
        "$cur" "$cc" "$pkg" "$stage" "${fb:-}"
    return 0
}

# ==============================================================================
#   非交互 CLI（自动化 / 巡检 / 测试用，优先级高于交互菜单）
#   除 install / confirm / rollback 外都是只读，不改系统配置。
# ==============================================================================
case "${1:-}" in
    help|--help|-h)
        cat <<'EOF'
SysPro v6.1
  交互菜单 : bash syspro.sh
  非交互子命令:
    bbrplus-status                 只读查看内核 / cc / grub 默认项 / 回滚信息
    bbrplus-check                  真实预检 + 下载并解包校验 bbrplus deb（不安装）
    bbrplus-install [--yes] [--force] [--reboot]
                                    安装内核并设一次性启动项（默认不自动重启）
    bbrplus-confirm                重启进新内核后验证 bbrplus 并设为持久默认
    bbrplus-rollback               恢复原 GRUB 默认项，清一次性启动项
    dns [check|apply] [文件]        逐个实测 nameserver；apply 只剔除实测不可达的
                                   （默认 check，文件默认 /etc/resolv.conf）
    selftest                       只读自检（函数完整性 / 语法 / 环境）
    plan                           dry-run 预览：列出一键优化将执行的模块（不改系统）
    status-json                    巡检用 JSON 格式状态输出（只读）
EOF
        exit 0 ;;
    bbrplus-status|--bbrplus-status) bbrplus_status; exit $? ;;
    bbrplus-check|--bbrplus-check)
        bbrplus_preflight || exit 1
        _bt=$(mktemp -d /tmp/syspro-bbrplus-check.XXXXXX 2>/dev/null) || exit 1
        BBRPLUS_TMP="$_bt"
        bbrplus_fetch "$_bt" && bbrplus_verify_pkgs "$_bt"
        _brc=$?
        rm -rf "$_bt" 2>/dev/null
        BBRPLUS_TMP=""
        exit "$_brc" ;;
    bbrplus-install|--bbrplus-install) shift; action_install_bbrplus "$@"; exit $? ;;
    bbrplus-confirm|--bbrplus-confirm) bbrplus_confirm; exit $? ;;
    bbrplus-rollback|--bbrplus-rollback) bbrplus_rollback; exit $? ;;
    dns)
        _dnssub=${2:-check}
        case "$_dnssub" in
            check|apply) ;;
            *) log_err "用法: $0 dns [check|apply] [文件]"; exit 1 ;;
        esac
        _dnsfile=${3:-/etc/resolv.conf}
        [ -f "$_dnsfile" ] || { log_err "找不到 $_dnsfile"; exit 1; }
        [ -L "$_dnsfile" ] && { log_err "DNS 选优不支持软链接 $_dnsfile（请先配置静态 resolv.conf）"; exit 1; }
        [ "$_dnssub" = "apply" ] && chattr -i "$_dnsfile" 2>/dev/null
        dns_select_best "$_dnsfile" "$_dnssub" 1
        _dnsrc=$?
        [ "$_dnssub" = "apply" ] && [ "$_dnsrc" -eq 0 ] && lock_resolv_if_requested "$_dnsfile"
        exit "$_dnsrc" ;;
    selftest|--selftest) syspro_selftest; exit $? ;;
    plan|--plan) cli_plan; exit $? ;;                    # FIX-P3-11
    status-json|--status-json) cli_status_json; exit $? ;;  # FIX-P3-12
esac

# 非交互环境（curl | bash、CI、无终端）下 read 会立即返回，菜单会无限空转。
# 这里提前拦一下，给出明确提示。
if [ ! -t 0 ]; then
    log_err "当前标准输入不是终端，交互式菜单无法运行。"
    log_info "请把脚本下载到本机后在真实终端中执行，例如: bash $0"
    exit 1
fi

# 注意: 两个 read 都要判返回值。
# 只用 `read -r _` 的话，终端断开时 read 立刻返回 1，循环条件仍是 true，
# 脚本会在后台以满 CPU 空转下去（这正是 v5.8 在 SSH 掉线后的表现）。
while true; do
    show_menu || break
    echo -n "按回车键继续..."
    read -r _ || break
done
exit 0
