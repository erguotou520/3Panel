#!/bin/bash
#
# 3Panel 节点安装器（只装 agent，不装面板本体）。
#
# 这个脚本随「agent 独立包」一起分发：
#
#   3panel-agent-<version>-linux-<arch>/
#   ├── 3panel-agent          -> /usr/local/bin/3panel-agent
#   ├── 3pctl                 -> /usr/local/bin/3pctl   (配置载体：BASE_DIR / 版本)
#   ├── install-agent.sh      (本文件)
#   ├── lang/                 -> /usr/local/bin/lang
#   └── initscript/           -> <base-dir>/3panel/initscript  + agent 服务定义
#
# 正常由 packaging/join.sh 一键引导调用；也可以在解压后的目录里手工执行：
#
#   ./install-agent.sh --master https://10.0.0.1:9999 --token <TOKEN>
#
# 环境变量等价形式（用于 join.sh 这类引导脚本）：
#
#   PANEL3_MASTER / PANEL3_TOKEN / PANEL3_ADDR / PANEL3_PORT
#   PANEL3_BASE_DIR(默认 /opt) / PANEL3_LANG(zh|en) / PANEL3_NO_FIREWALL=1
#   PANEL3_NO_JOIN=1   只换二进制、不重新 join —— 升级已加入的节点走这条，
#                      节点上已有证书，且 token 是一次性的、重跑也拿不到新的
#   PANEL3_VERSION     覆盖包内记录的版本（正常由 join.sh 传入，无需手工设置）
#
# 安装完成后的运维方式：
#   systemctl {status,restart} 3panel-agent     或     3pctl {status,restart}
# （节点上的 3pctl 已被改写成管理 agent 服务，不会去碰不存在的面板 core。）
#
set -Eeuo pipefail

CURRENT_DIR="$(cd "$(dirname "$0")" && pwd)"

AGENT_BIN_NAME="3panel-agent"
CTL_BIN_NAME="3pctl"
SERVICE_NAME="3panel-agent"
SERVICE_UNIT="3panel-agentd"

MASTER="${PANEL3_MASTER:-}"
TOKEN="${PANEL3_TOKEN:-}"
NODE_ADDR="${PANEL3_ADDR:-}"
NODE_PORT="${PANEL3_PORT:-9999}"
BASE_DIR="${PANEL3_BASE_DIR:-/opt}"
# 留空表示「自动」：detect_lang 按终端字符集决定，GBK 终端直接退英文（见下）。
LANG_CODE="${PANEL3_LANG:-}"
# join.sh 解析完版本后显式传进来；手工执行时为空，退回读包内 3pctl。
VERSION_OVERRIDE="${PANEL3_VERSION:-}"
NO_FIREWALL="${PANEL3_NO_FIREWALL:-0}"
# 升级路径：节点早已加入，证书和注册关系都在 <base-dir>/3panel 下，重跑只需换二进制。
# token 是一次性的，升级时既没有也不该有可用的 token，所以这条路径跳过 run_join。
NO_JOIN="${PANEL3_NO_JOIN:-0}"
LOG_FILE="${PANEL3_INSTALL_LOG:-/var/log/3panel-agent-install.log}"

# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------
say() { # say <中文> <English>
    if [[ "$LANG_CODE" == "zh" ]]; then printf '%s\n' "$1"; else printf '%s\n' "$2"; fi
}
step() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }
warn() { printf '\033[0;33m[warn] %s\033[0m\n' "$1"; }

log() {
    local line="$1"
    printf '%s\n' "$line"
    if [[ -n "$LOG_FILE" ]]; then
        printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$line" >>"$LOG_FILE" 2>/dev/null || true
    fi
}

err() {
    printf '\033[0;31m[error] %s\033[0m\n' "$1" >&2
    [[ -n "$LOG_FILE" ]] && printf '[%s] [error] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >>"$LOG_FILE" 2>/dev/null || true
    exit 1
}

info() { printf '    %s\n' "$1"; }

# 终端字符集不是 UTF-8（GBK 等）时中文必乱码，直接退英文；PANEL3_LANG / --lang 永远优先。
# 判定只用环境变量、不用 `locale charmap`：后者会被「导出但为空的 LC_ALL」骗成 C locale。
# 没有任何 locale 信息时按 zh 处理（主力用户；面板界面也是中文）。
detect_lang() {
    [[ -n "$LANG_CODE" ]] && return 0
    local loc=""
    if [[ -n "${LC_ALL:-}" ]]; then
        loc="$LC_ALL"
    elif [[ -n "${LC_CTYPE:-}" ]]; then
        loc="$LC_CTYPE"
    else
        loc="${LANG:-}"
    fi
    case "$loc" in
        "") LANG_CODE="zh" ;;
        *[Uu][Tt][Ff]*8*) LANG_CODE="zh" ;;
        *) LANG_CODE="en" ;;
    esac
}

# set -e 的失败是安静的：加 ERR trap 把「哪一行挂了」打到眼前，顺带提示日志位置。
trap 'rc=$?; printf "\033[0;31m[error] %s\033[0m\n" "$(say "第 ${LINENO} 行的命令失败（exit ${rc}）。完整日志：${LOG_FILE}" "command on line ${LINENO} failed (exit ${rc}). full log: ${LOG_FILE}")" >&2' ERR

# 日志路径不可写（比如还没提权的冒烟环境）就退到 /tmp，别让每次写日志都喷一行 Permission denied。
if [[ -n "$LOG_FILE" ]] && ! : >>"$LOG_FILE" 2>/dev/null; then
    LOG_FILE="${TMPDIR:-/tmp}/3panel-agent-install.log"
    : >>"$LOG_FILE" 2>/dev/null || LOG_FILE=""
fi

# GNU sed 与 BSD sed 的 -i 参数不同；本脚本的目标平台是 Linux，但保留这个
# 兼容层是为了能在开发机上跑通流程（同 quick_start.sh 的做法）。
sed_i() {
    if sed --version >/dev/null 2>&1; then
        sed -i "$@"
    else
        local expr="$1"
        local file="$2"
        sed -i '' "$expr" "$file"
    fi
}

usage() {
    cat <<'EOF'
Usage: ./install-agent.sh --master <master-url> --token <token> [options]

  --master URL    面板地址，例如 https://10.0.0.1:9999   (env PANEL3_MASTER)
  --token  TOKEN  面板「多机管理」里创建节点时生成的一次性 token (env PANEL3_TOKEN)
  --addr   ADDR   面板回连本机的地址，留空自动探测            (env PANEL3_ADDR)
  --port   PORT   本机 agent 监听端口，默认 9999              (env PANEL3_PORT)
  --base-dir DIR  安装目录，默认 /opt                         (env PANEL3_BASE_DIR)
  --version  VER  覆盖包内记录的版本，默认读包内 3pctl        (env PANEL3_VERSION)
  --lang   zh|en  脚本提示语言，默认 zh                       (env PANEL3_LANG)
  --no-firewall   不自动放行端口                              (env PANEL3_NO_FIREWALL=1)
  --no-join       只安装/替换二进制，不向面板换取证书          (env PANEL3_NO_JOIN=1)
                  升级已加入的节点时用；配合 upgrade-agent.sh
  -h, --help      显示本帮助

例：./install-agent.sh --master https://10.0.0.1:9999 --token 0f3d...
    ./install-agent.sh --no-join          # 升级：保留现有证书
EOF
}

# ---------------------------------------------------------------------------
# 参数
# ---------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --master) MASTER="${2:-}"; shift 2 ;;
            --token) TOKEN="${2:-}"; shift 2 ;;
            --addr) NODE_ADDR="${2:-}"; shift 2 ;;
            --port) NODE_PORT="${2:-}"; shift 2 ;;
            --base-dir) BASE_DIR="${2:-}"; shift 2 ;;
            --version) VERSION_OVERRIDE="${2:-}"; shift 2 ;;
            --lang) LANG_CODE="${2:-}"; shift 2 ;;
            --no-firewall) NO_FIREWALL=1; shift ;;
            --no-join) NO_JOIN=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *) err "unknown argument: $1" ;;
        esac
    done
    # 换证书才需要 master/token；--no-join 是升级路径，节点上已有证书。
    if [[ "$NO_JOIN" != "1" ]]; then
        [[ -n "$MASTER" ]] || { usage; err "missing --master"; }
        [[ -n "$TOKEN" ]] || { usage; err "missing --token"; }
    fi
}

check_env() {
    [[ "$(id -u)" -eq 0 ]] || err "$(say "请用 root（或 sudo）执行" "run this script as root (or with sudo)")"
    [[ "$(uname -s)" == "Linux" ]] || err "$(say "只支持 Linux 主机" "only Linux hosts are supported")"
    [[ -f "$CURRENT_DIR/$AGENT_BIN_NAME" ]] || err "package is incomplete: $AGENT_BIN_NAME not found next to this script"
    [[ -f "$CURRENT_DIR/$CTL_BIN_NAME" ]] || err "package is incomplete: $CTL_BIN_NAME not found next to this script"
}

# ---------------------------------------------------------------------------
# 安装
# ---------------------------------------------------------------------------
install_binaries() {
    step "$(say "安装二进制到 /usr/local/bin" "Installing binaries into /usr/local/bin")"
    install -m 0755 "$CURRENT_DIR/$AGENT_BIN_NAME" "/usr/local/bin/$AGENT_BIN_NAME"
    install -m 0755 "$CURRENT_DIR/$CTL_BIN_NAME" "/usr/local/bin/$CTL_BIN_NAME"
    log "  $AGENT_BIN_NAME -> /usr/local/bin/$AGENT_BIN_NAME"
    log "  $CTL_BIN_NAME -> /usr/local/bin/$CTL_BIN_NAME"
}

# 3pctl 在这里不是「管理面板」用的，而是 agent 读取 BASE_DIR / 版本的配置文件
# （agent/utils/ctl_conf 直接读 /usr/local/bin/3pctl）。BASE_DIR 决定 agent 的
# 数据目录，写错会让它把数据丢到当前工作目录里，所以这一步不能省。
configure_ctl() {
    local ctl="/usr/local/bin/$CTL_BIN_NAME"
    local version="$1"
    sed_i "s|^BASE_DIR=.*|BASE_DIR=$BASE_DIR|" "$ctl"
    sed_i "s|^ORIGINAL_PORT=.*|ORIGINAL_PORT=$NODE_PORT|" "$ctl"
    sed_i "s|^ORIGINAL_VERSION=.*|ORIGINAL_VERSION=$version|" "$ctl"
    sed_i "s|^LANGUAGE=.*|LANGUAGE=$LANG_CODE|" "$ctl"
    # 节点上没有面板 core，让 3pctl 的 status/restart 指向 agent 服务本身。
    sed_i "s|^CORE_SERVICE=.*|CORE_SERVICE=\"$SERVICE_NAME\"|" "$ctl"
    log "  $CTL_BIN_NAME: BASE_DIR=$BASE_DIR version=$version port=$NODE_PORT"
}

install_assets() {
    if [[ -d "$CURRENT_DIR/lang" ]]; then
        cp -rf "$CURRENT_DIR/lang" /usr/local/bin || warn "copy lang failed (non-fatal)"
    fi
    if [[ -d "$CURRENT_DIR/initscript" ]]; then
        mkdir -p "$BASE_DIR/3panel"
        cp -rf "$CURRENT_DIR/initscript" "$BASE_DIR/3panel" || warn "copy initscript failed (non-fatal)"
    fi
}

# 有 systemctl 不等于有 systemd：docker / wsl / chroot 里它只是个会报错的壳。
# /run/systemd/system 是标准判据；再兜一层 is-system-running（自动化测试环境里
# systemctl shim 恒返回 0，也能走到 systemd 分支）。
is_systemd() {
    [[ -d /run/systemd/system ]] && return 0
    command -v systemctl >/dev/null 2>&1 || return 1
    if systemctl is-system-running >/dev/null 2>&1; then return 0; fi
    [[ "$(systemctl is-system-running 2>/dev/null || true)" == "degraded" ]] && return 0
    return 1
}

install_service() {
    local init_dir="$CURRENT_DIR/initscript"
    step "$(say "注册 agent 服务（已设开机自启）" "Registering the agent service (enabled at boot)")"
    if is_systemd; then
        install -m 0644 "$init_dir/$SERVICE_NAME.service" "/etc/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload >>"$LOG_FILE" 2>&1 || true
        systemctl enable "$SERVICE_NAME.service" >>"$LOG_FILE" 2>&1 || true
        log "  systemd: /etc/systemd/system/$SERVICE_NAME.service"
    elif [[ -f /sbin/openrc-run ]]; then
        install -m 0755 "$init_dir/$SERVICE_NAME.openrc" "/etc/init.d/$SERVICE_UNIT"
        rc-update add "$SERVICE_UNIT" default >>"$LOG_FILE" 2>&1 || true
        log "  openrc: /etc/init.d/$SERVICE_UNIT"
    else
        install -m 0755 "$init_dir/$SERVICE_NAME.init" "/etc/init.d/$SERVICE_UNIT"
        log "  sysvinit: /etc/init.d/$SERVICE_UNIT"
    fi
}

# 输出同时给控制台和安装日志 —— 之前只进日志文件，服务起不来时终端上什么都看不到。
service_cmd() {
    local cmd="$1" out rc
    if is_systemd; then
        out="$(systemctl "$cmd" "$SERVICE_NAME.service" 2>&1)" && rc=0 || rc=$?
    elif command -v rc-service >/dev/null 2>&1; then
        out="$(rc-service "$SERVICE_UNIT" "$cmd" 2>&1)" && rc=0 || rc=$?
    else
        out="$(service "$SERVICE_UNIT" "$cmd" 2>&1)" && rc=0 || rc=$?
    fi
    if [[ -n "$out" ]]; then
        printf '%s\n' "$out"
        printf '[%s] %s: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$cmd" "$out" >>"$LOG_FILE" 2>/dev/null || true
    fi
    return "$rc"
}

open_firewall() {
    [[ "$NO_FIREWALL" == "1" ]] && return 0
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        firewall-cmd --zone=public --add-port="$NODE_PORT"/tcp --permanent >>"$LOG_FILE" 2>&1 || true
        firewall-cmd --reload >>"$LOG_FILE" 2>&1 || true
        log "  firewalld: opened $NODE_PORT/tcp"
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "$NODE_PORT"/tcp >>"$LOG_FILE" 2>&1 || true
        log "  ufw: opened $NODE_PORT/tcp"
    fi
}

# ---------------------------------------------------------------------------
# 加入主控
# ---------------------------------------------------------------------------
run_join() {
    step "$(say "向面板换取证书并切换到节点模式" "Exchanging the token for certificates")"
    local args=("join" "--master" "$MASTER" "--token" "$TOKEN" "--port" "$NODE_PORT")
    local attempt output_file joined_addr
    [[ -n "$NODE_ADDR" ]] && args+=("--addr" "$NODE_ADDR")
    output_file="$(mktemp "${TMPDIR:-/tmp}/3panel-join.XXXXXX")"
    # 主控只在成功时消耗 token，重试是安全的；TLS 握手偶发被重置不值得整个失败。
    for attempt in 1 2 3; do
        if [[ "$attempt" -gt 1 ]]; then
            warn "$(say "第 ${attempt} 次尝试…" "attempt ${attempt}…")"
            sleep 2
        fi
        if "/usr/local/bin/$AGENT_BIN_NAME" "${args[@]}" 2>&1 | tee "$output_file"; then
            if [[ -z "$NODE_ADDR" ]]; then
                joined_addr="$(sed -n 's/^joined master .* (\(.*\))$/\1/p' "$output_file" | tail -n 1)"
                case "$joined_addr" in
                    \[*\]:*) NODE_ADDR="${joined_addr#\[}"; NODE_ADDR="${NODE_ADDR%\]:*}" ;;
                    *:*) NODE_ADDR="${joined_addr%:*}" ;;
                esac
            fi
            rm -f "$output_file"
            return 0
        fi
    done
    rm -f "$output_file"
    err "$(say "加入失败（已尝试 3 次）：确认面板地址可达、token 未过期且未被使用" \
        "join failed after 3 attempts: the master must be reachable and the token unused and unexpired")"
}

# 启动失败时把 unit 最近日志直接打到控制台 —— 别让用户再去翻日志文件。
dump_unit_logs() {
    is_systemd || return 0
    command -v journalctl >/dev/null 2>&1 || return 0
    info "$(say "最近 15 行 agent 日志：" "last 15 agent log lines:")"
    journalctl -u "$SERVICE_NAME.service" --no-pager -n 15 2>/dev/null || true
}

start_service() {
    step "$(say "启动 agent 服务" "Starting the agent service")"
    if ! service_cmd start; then
        dump_unit_logs
        err "$(say "agent 启动失败" "the agent failed to start")" \
            "$(say "查看日志：journalctl -u $SERVICE_NAME -e" "see: journalctl -u $SERVICE_NAME -e")"
    fi
    # Type=simple 也要一两秒才真正 active；轮询而不是只看一次。
    local i
    for ((i = 1; i <= 15; i++)); do
        if is_systemd; then
            if systemctl is-active --quiet "$SERVICE_NAME.service" >/dev/null 2>&1; then return 0; fi
        elif command -v rc-service >/dev/null 2>&1; then
            if rc-service "$SERVICE_UNIT" status >/dev/null 2>&1; then return 0; fi
        else
            if service "$SERVICE_UNIT" status >/dev/null 2>&1; then return 0; fi
        fi
        sleep 1
    done
    dump_unit_logs
    err "$(say "agent 未进入运行状态" "the agent did not become active")" \
        "$(say "查看日志：journalctl -u $SERVICE_NAME -e" "see: journalctl -u $SERVICE_NAME -e")"
}

print_summary() {
    step "$(say "完成" "Done")"
    if [[ "$NO_JOIN" == "1" ]]; then
        cat <<EOF
  $(say "节点地址" "node address")  ${NODE_ADDR:-<auto>}:$NODE_PORT
  $(say "数据目录" "data dir")      $BASE_DIR/3panel
  $(say "日志" "log")               $LOG_FILE
  $(say "服务管理" "service")       systemctl {status,restart} $SERVICE_NAME   $(say "或" "or")   3pctl {status,restart}
EOF
        say "升级完成。回面板的「多机管理」点一次「健康检查」，节点版本号即刷新。" \
            "Upgrade done. Hit the health check button in the panel to refresh the reported version."
        return 0
    fi
    cat <<EOF
  $(say "节点地址" "node address")  ${NODE_ADDR:-<auto>}:$NODE_PORT
  $(say "面板地址" "master")        $MASTER
  $(say "数据目录" "data dir")      $BASE_DIR/3panel
  $(say "日志" "log")               $LOG_FILE
  $(say "服务管理" "service")       systemctl {status,restart} $SERVICE_NAME   $(say "或" "or")   3pctl {status,restart}
EOF
    say "agent 已注册为系统服务并设为开机自启，无需手动挂到后台。" \
        "the agent is installed as a system service and enabled at boot; no manual daemonizing needed."
    say "回到面板的「多机管理」点一次「健康检查」，节点状态变成 Online 即接入成功。" \
        "Back in the panel, hit the health check button once — the node turns Online when it is reachable."
    warn "$(say "面板要主动连回本机的 $NODE_PORT 端口，云厂商安全组也要放行。" \
        "the panel dials back to this host on port $NODE_PORT; open it in your cloud security group too.")"
}

main() {
    detect_lang
    parse_args "$@"
    check_env

    local version="$VERSION_OVERRIDE"
    if [[ -z "$version" ]]; then
        # 包内 3pctl 由 build-release.sh 盖章；手工解压一份没盖章的包时这里会读到
        # 占位值 "version"，那也比空强 —— 主控只拿它做展示。
        version="$(grep -m1 '^ORIGINAL_VERSION=' "$CURRENT_DIR/$CTL_BIN_NAME" 2>/dev/null | cut -d= -f2 || true)"
    fi
    version="${version:-unknown}"

    if [[ "$NO_JOIN" == "1" ]]; then
        step "$(say "升级 3Panel agent 到 $version" "Upgrading 3Panel agent to $version")"
    else
        step "$(say "安装 3Panel agent $version" "Installing 3Panel agent $version")"
    fi

    # 重复加入 / 更换主控 / 升级时都先停掉旧进程：一是避免它和 join 抢同一个数据库，
    # 二是覆盖正在运行的二进制会 Text file busy。
    service_cmd stop || true
    # 老进程也可能是手工裸起的（不归服务管理管）：兜底再清一次，
    # 否则新 agent 绑不上端口，服务起了又退，面板上节点永远是 Offline。
    pkill -x "$AGENT_BIN_NAME" >/dev/null 2>&1 || true

    install_binaries
    configure_ctl "$version"
    install_assets
    install_service
    if [[ "$NO_JOIN" == "1" ]]; then
        # 升级：端口没变、证书还在，既不重开防火墙也不重新 join。
        log "  $(say "保留现有证书与注册关系，未重新加入" "kept the existing certificate, no re-join")"
    else
        open_firewall
        run_join
    fi
    start_service
    print_summary
}

main "$@"
