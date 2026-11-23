#!/bin/bash
# ==============================================================================
#   SysPro 离线回归测试（只读静态检查，不修改系统、不产生假数据）
#
#   用法: bash tests/offline_selftest.sh
#   目的: 在把 syspro.sh 上传到真机之前，先挡住语法、结构、危险命令与
#         已知 bug 回退。真机运行时另用 `syspro.sh selftest`。
# ==============================================================================

SCRIPT_DIR=$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)
SRC="$SCRIPT_DIR/syspro.sh"
BASE="$SCRIPT_DIR/syspro.sh.v5.9.bak"

[ -f "$SRC" ] || { echo "FAIL 找不到 $SRC"; exit 1; }

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); printf 'PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf 'FAIL  %s\n' "$1"; }
check(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }
has()  { grep -qF -- "$1" "$SRC" 2>/dev/null; }
hasre(){ grep -qE -- "$1" "$SRC" 2>/dev/null; }
nre()  { ! grep -qE -- "$1" "$SRC" 2>/dev/null; }

echo "=== 0. 文件与格式 ==="
check "主脚本存在且非空"            "[ -s '$SRC' ]"
check "bash -n 语法通过"            "bash -n '$SRC'"
check "无 CRLF 行尾"               "! grep -q \$'\r' '$SRC'"
check "无 UTF-8 BOM"               "[ \"\$(head -c3 '$SRC')\" = '#!/' ]"
check "shebang 为 bash"            "[ \"\$(head -n1 '$SRC')\" = '#!/bin/bash' ]"
check "版本号 v6.0"                "has 'v6.0'"
check "v5.9 备份存在"              "[ -f '$BASE' ]"

echo "=== 1. bbrplus 配置与函数 ==="
for v in BBRPLUS_REPO BBRPLUS_TAG BBRPLUS_KVER BBRPLUS_BACKUP_DIR BBRPLUS_KEEP_DEB; do
    check "配置变量 $v"             "hasre '^${v}='"
done
check "仓库为 UJX6N/bbrplus-6.6"   "has 'BBRPLUS_REPO=\"UJX6N/bbrplus-6.6\"'"
check "内核版本 6.6.21-bbrplus"    "has 'BBRPLUS_KVER=\"6.6.21-bbrplus\"'"

FN_LIST="bbrplus_rollback_put bbrplus_rollback_get bbrplus_pkg_installed
bbrplus_available_cc bbrplus_find_fallback bbrplus_menu_id bbrplus_full_menu_id
bbrplus_status bbrplus_preflight bbrplus_fetch bbrplus_verify_pkgs
bbrplus_install_pkgs bbrplus_confirm bbrplus_rollback action_install_bbrplus
syspro_selftest"
for fn in $FN_LIST; do
    check "函数 $fn 已定义"        "hasre '^${fn}\(\) *\{'"
done

echo "=== 2. 能力要点（真机验证过的路径） ==="
check "校验 CONFIG_TCP_CONG_BBRPLUS=y"   "has '^CONFIG_TCP_CONG_BBRPLUS=y'"
check "解包校验而非执行远程脚本"         "has 'dpkg-deb -x'"
check "逐包显示 SHA256"                 "has 'sha256sum \"\$f\"'"
check "initrd 驱动检查"                 "has 'lsinitramfs'"
check "grub-reboot 一次性启动"           "has 'grub-reboot \"\$full\"'"
check "GRUB_DEFAULT 保持原值"            "has 'GRUB_DEFAULT 保持原值'"
check "confirm 才写持久默认"             "has 'GRUB_DEFAULT=saved'"
check "confirm 校验 bbrplus cc"          "has '当前内核没有 bbrplus 拥塞控制'"
check "rollback 清 next_entry"           "has 'unset next_entry'"
check "rollback 用显式 grubenv 路径"      "has 'grub-editenv /boot/grub/grubenv unset next_entry'"
check "保留原内核作回退"                 "has 'bbrplus_find_fallback'"
check "备份 GRUB 与 nftx 参数"           "has '已备份 GRUB / nftx 参数'"
check "提示 nftx 重新探测 cc"            "has 'nftx_auto.sh on --yes'"
check "不写 nftx 独占参数（保留键清单）" "has 'NFTX_RESERVED_KEYS=('"
check "架构限制 amd64"                   "has 'bbrplus 内核包只有 amd64 版本'"
check "包管理族限制 apt"                 "has '该内核只提供 Debian/Ubuntu 的 .deb 包'"
check "/boot 空间下限"                   "has '250000'"
check "deb 保留到备份目录"               "has 'BBRPLUS_KEEP_DEB'"

echo "=== 3. 菜单与 CLI 一致性 ==="
check "手动菜单含安装入口"      "has '3) action_install_bbrplus;'"
check "手动菜单含确认入口"      "has '4) bbrplus_confirm;'"
check "手动菜单含回退入口"      "has '5) bbrplus_rollback;'"
check "手动菜单含状态入口"      "has '6) bbrplus_status;'"
check "手动菜单保留旧功能"      "has '2) action_install_other_bbr;'"
check "主菜单描述已更新"        "has 'bbrplus 内核 / 卸载内核 / 其他 BBR'"
check "一键优化不含换内核"      "nre '^[[:space:]]*action_install_bbrplus$'"
for sub in bbrplus-status bbrplus-check bbrplus-install bbrplus-confirm bbrplus-rollback selftest; do
    check "CLI 分发 $sub"       "has '${sub}|--${sub})'"
done
check "help 说明含 install"     "has 'bbrplus-install [--yes]'"
check "CLI 分发在交互检查之前"  "[ \"\$(grep -n '^case \"\${1:-}\" in' '$SRC' | tail -1 | cut -d: -f1)\" -lt \"\$(grep -n 'if \[ ! -t 0 \]' '$SRC' | cut -d: -f1)\" ]"
check "交互菜单仍保留 read 返回值保护" "has 'read -r choice || return 1'"

echo "=== 4. 只读 CLI 不产生副作用 ==="
check "只读标记在最前面定义"        "has 'SYSPRO_READONLY_CLI=0'"
check "log_to_file 跳过只读 CLI"    "has '[ \"\${SYSPRO_READONLY_CLI:-0}\" = \"1\" ] && return 0'"
check "logrotate 跳过只读 CLI"      "has '[ \"\${SYSPRO_READONLY_CLI:-0}\" = \"1\" ] || setup_logrotate'"
check "单实例锁跳过只读 CLI"        "has 'if have flock && [ \"\${SYSPRO_READONLY_CLI:-0}\" != \"1\" ]; then'"
check "root 检查跳过只读 CLI"       "has 'if [[ \$EUID -ne 0 ]] && [ \"\${SYSPRO_READONLY_CLI:-0}\" != \"1\" ]; then'"
check "只读预检不装包"              "has 'if [ \"\${SYSPRO_READONLY_CLI:-0}\" != \"1\" ]; then'"
check "临时目录受 cleanup 托管"     "has '/tmp/syspro-bbrplus.*'"

echo "=== 5. 已修复缺陷的回归断言 ==="
check "state_del 用 PID 临时文件"       "has 'local tmp=\"\${STATE_FILE}.tmp.\$\$\"'"
check "state_del 原子 mv"               "has 'mv -f \"\$tmp\" \"\$STATE_FILE\"'"
check "grub 更新检查返回码"             "has 'grub_rc=\$?'"
check "grub 更新失败会报错"             "has 'GRUB 引导配置更新失败'"
check "saved_entry 只取最后一段 ID"     "has 'saved=\${saved##*>}'"
check "bbrplus 内建 cc 识别"            "has 'tcp_available_congestion_control'"
check "内建 cc 不再误报退回 cubic"      "has '拥塞控制由内核内建提供'"
check "Debian 13 推荐版本提示"          "has '推荐版本: 10/11/12/13'"
check "卸载摘要说明内核不卸载"          "has 'bbrplus 内核 - 不在卸载范围'"
if grep -qF "printf '\nGRUB_DEFAULT=saved\n' >> /etc/default/grub" "$SRC"; then
    ok "confirm 处理被注释的 GRUB_DEFAULT"
else
    bad "confirm 处理被注释的 GRUB_DEFAULT"
fi
if grep -qF "printf '\nGRUB_DEFAULT=%s\n' \"\$dflt\" >> /etc/default/grub" "$SRC"; then
    ok "rollback 处理被注释的 GRUB_DEFAULT"
else
    bad "rollback 处理被注释的 GRUB_DEFAULT"
fi
check "rollback 无记录时动态定位原内核"    "has 'fb_target='"
check "confirm 补记外部安装的回退内核"     "has '补一条'"
check "selftest 含真机运行时检查"          "has 'GRUB 能解析出 bbrplus 条目'"
check "回退目标解析抽成只读函数"          "hasre '^bbrplus_rollback_target_id\(\) *\{'"
check "rollback 调用只读解析函数"          "has 'fb_target=\$(bbrplus_rollback_target_id'"

echo "=== 5.5 DNS 选优（v6.1，从 nftx 迁入，自动启用） ==="
check "版本号 v6.1"                       "has 'v6.1'"
for v in DNS_SELECT_ENABLED DNS_PROBE_TRIES DNS_PROBE_TIMEOUT DNS_PROBE_DOMAINS; do
    check "DNS 选优配置 $v"               "hasre '^${v}='"
done
for fn in dns_probe_one dns_select_best test_dns_server; do
    check "DNS 选优函数 $fn 已定义"       "hasre '^${fn}\(\) *\{'"
done
check "configure_dns 写盘前自动选优"      "has 'dns_select_best \"\$new_dns\" apply 0'"
check "选优开关默认开启"                  "has 'DNS_SELECT_ENABLED=1'"
check "CLI dns 子命令分发"                "hasre '^    dns\)$'"
check "help 含 dns check/apply"           "has 'dns [check|apply] [文件]'"
check "dns check 标记为只读 CLI"          "has 'SYSPRO_READONLY_CLI=1'"
check "严格匹配真实 A 记录"               "has 'IN[[:space:]]+A[[:space:]]+'"
check "记录 dig 错误行污染 stdout 的坑"   "has 'communications error'"
check "v4/v6 一视同仁"                    "has 'v4 / v6 一视同仁'"
check "全不可达保守不动"                  "has '所有 nameserver 都不可达'"
check "apply 前备份到 syspro 状态目录"    "has '/var/lib/syspro/dns'"
check "原子重写 tmp+mv"                   "has 'mv -f \"\$outf\" \"\$rc_file\"'"
check "保留非 nameserver 行"              "has '{ print }'"

# 真跑：用桩 dig 模拟「真实 A 记录 / 超时错误行」，验证不会把错误行当成功。
_dnsdir=$(mktemp -d 2>/dev/null || printf '/tmp/syspro-dns-test.%s' "$$")
mkdir -p "$_dnsdir"
cat > "$_dnsdir/dig" <<'DIGEOF'
#!/bin/bash
srv=''
for a in "$@"; do
    case "$a" in @*) srv=${a#@} ;; esac
done
case "$srv" in
    8.8.8.8) printf 'example.com. 30 IN A 1.2.3.4\n' ;;
    *)       printf ';; communications error to %s#53: timed out\n' "$srv" ;;
esac
DIGEOF
chmod +x "$_dnsdir/dig"
(
    PATH="$_dnsdir:$PATH"
    have() { command -v "$1" >/dev/null 2>&1; }
    eval "$(awk '/^dns_probe_one\(\)/,/^}/' "$SRC")"
    r=$(dns_probe_one 8.8.8.8 example.com)
    case "$r" in ok*) exit 0 ;; *) exit 1 ;; esac
) && ok "桩 dig：真实 A 记录判可达" || bad "桩 dig：真实 A 记录判可达"
(
    PATH="$_dnsdir:$PATH"
    have() { command -v "$1" >/dev/null 2>&1; }
    eval "$(awk '/^dns_probe_one\(\)/,/^}/' "$SRC")"
    r=$(dns_probe_one 2001:4860::8888 example.com)
    [ -z "$r" ] && exit 0 || exit 1
) && ok "桩 dig：超时错误行不误判为可达" || bad "桩 dig：超时错误行不误判为可达"

printf 'nameserver 8.8.8.8\nnameserver 2001:4860::8888\noptions timeout:2\n' > "$_dnsdir/resolv"
(
    PATH="$_dnsdir:$PATH"
    have()      { command -v "$1" >/dev/null 2>&1; }
    log_info()  { :; }; log_warn() { :; }
    log_err()   { :; }; log_success() { :; }
    eval "$(awk '/^dns_probe_one\(\)/,/^}/' "$SRC")"
    eval "$(awk '/^dns_select_best\(\)/,/^}/' "$SRC")"
    dns_select_best "$_dnsdir/resolv" apply 0 >/dev/null 2>&1 || exit 1
    grep -q '^nameserver 8.8.8.8$' "$_dnsdir/resolv" || exit 1
    grep -q '2001:4860' "$_dnsdir/resolv" && exit 1
    grep -q '^options timeout:2$' "$_dnsdir/resolv" || exit 1
    exit 0
) && ok "桩 apply：只剔除实测不可达 NS，保留可达项与非 NS 行" \
   || bad "桩 apply：只剔除实测不可达 NS，保留可达项与非 NS 行"
rm -rf "$_dnsdir" 2>/dev/null

echo "=== 6. 危险模式与边界 ==="
check "无 sysctl --system 实际调用"      "nre '^[[:space:]]*sysctl --system'"
check "无 curl | bash 直接执行"          "nre '^[[:space:]]*[^#].*curl[^|]*\|[[:space:]]*(ba)?sh'"
check "无 chmod 777"                     "nre 'chmod[[:space:]]+(-R[[:space:]]+)?777'"
check "无 eval 用户输入"                 "nre 'eval[[:space:]]+\"\\\$(read|CONFIRM|choice|SELECTION)'"
check "rm -rf 仅受限路径"                "nre 'rm -rf[[:space:]]+\"/\"|rm -rf[[:space:]]+\\\$HOME|rm -rf[[:space:]]+/etc'"
check "nftx 独占键仍在清单"              "has 'net.ipv4.tcp_congestion_control'"
check "assert_reserved_untouched 仍调用" "has 'assert_reserved_untouched'"
check "卸载不重放 sysctl.d"              "has '这里刻意**不调用** sysctl --system'"

echo "=== 7. heredoc 与旧功能保留 ==="
for tag in EOF PY; do
    o=$(grep -cE "<<[[:space:]]*'?${tag}'?" "$SRC")
    c=$(grep -c "^${tag}\$" "$SRC")
    if [ "$o" -eq "$c" ]; then ok "heredoc $tag 配对 ($o)"; else bad "heredoc $tag 不配对 open=$o close=$c"; fi
done
if [ -f "$BASE" ]; then
    missing=0
    while IFS= read -r fn; do
        [ -n "$fn" ] || continue
        grep -qF "$fn" "$SRC" || { bad "旧函数丢失: $fn"; missing=$((missing + 1)); }
    done < <(grep -oE '^[A-Za-z_][A-Za-z_0-9]*\(\)' "$BASE" | sort -u)
    [ "$missing" -eq 0 ] && ok "v5.9 原有函数全部保留"
fi
check "原有 action_install_other_bbr 保留" "hasre '^action_install_other_bbr\(\) *\{'"
check "原有 action_uninstall_kernels 保留" "hasre '^action_uninstall_kernels\(\) *\{'"
check "原有 uninstall_syspro 保留"         "hasre '^uninstall_syspro\(\) *\{'"

echo "=============================================="
printf '总计 %d 项，通过 %d，失败 %d\n' "$((PASS + FAIL))" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
