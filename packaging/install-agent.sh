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
set -euo pipefail

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
LANG_CODE="${PANEL3_LANG:-zh}"
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

install_service() {
    local init_dir="$CURRENT_DIR/initscript"
    step "$(say "注册 agent 服务" "Registering the agent service")"
    if [[ -d /run/systemd/system ]] || command -v systemctl >/dev/null 2>&1; then
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

service_cmd() {
    local cmd="$1"
    if [[ -d /run/systemd/system ]] || command -v systemctl >/dev/null 2>&1; then
        systemctl "$cmd" "$SERVICE_NAME.service" >>"$LOG_FILE" 2>&1 || return 1
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service "$SERVICE_UNIT" "$cmd" >>"$LOG_FILE" 2>&1 || return 1
    else
        service "$SERVICE_UNIT" "$cmd" >>"$LOG_FILE" 2>&1 || return 1
    fi
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
    [[ -n "$NODE_ADDR" ]] && args+=("--addr" "$NODE_ADDR")

    if ! "/usr/local/bin/$AGENT_BIN_NAME" "${args[@]}"; then
        err "$(say "加入失败，请确认面板地址可达、token 未过期且未被使用" \
            "join failed — check that the master is reachable and the token is still valid")"
    fi
}

start_service() {
    step "$(say "启动 agent 服务" "Starting the agent service")"
    service_cmd start || err "$(say "agent 启动失败，查看 journalctl -u $SERVICE_NAME" \
        "the agent failed to start, see: journalctl -u $SERVICE_NAME")"
    sleep 2
    # systemd 用 is-active，openrc/sysvinit 用 status；都不是的话就不做这层校验。
    if [[ -d /run/systemd/system ]] || command -v systemctl >/dev/null 2>&1; then
        service_cmd is-active || err "$(say "agent 未处于运行状态，查看 journalctl -u $SERVICE_NAME" \
            "the agent is not active, see: journalctl -u $SERVICE_NAME")"
    elif command -v rc-service >/dev/null 2>&1; then
        service_cmd status || err "$(say "agent 未处于运行状态" "the agent is not running")"
    fi
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
    say "回到面板的「多机管理」点一次「健康检查」，节点状态变成 Online 即接入成功。" \
        "Back in the panel, hit the health check button once — the node turns Online when it is reachable."
    warn "$(say "面板要主动连回本机的 $NODE_PORT 端口，云厂商安全组也要放行。" \
        "the panel dials back to this host on port $NODE_PORT; open it in your cloud security group too.")"
}

main() {
    parse_args "$@"
    check_env

    local version="$VERSION_OVERRIDE"
    if [[ -z "$version" ]]; then
        # 包内 3pctl 由 build-release.sh 盖章；手工解压一份没盖章的包时这里会读到
        # 占位值 "version"，那也比空强 —— 主控只拿它做展示。
        version="$(grep -m1 '^ORIGINAL_VERSION=' "$CURRENT_DIR/$CTL_BIN_NAME" 2>/dev/null | cut -d= -f2)"
    fi
    version="${version:-unknown}"

    if [[ "$NO_JOIN" == "1" ]]; then
        step "$(say "升级 3Panel agent 到 $version" "Upgrading 3Panel agent to $version")"
    else
        step "$(say "安装 3Panel agent $version" "Installing 3Panel agent $version")"
    fi

    # 重复加入 / 更换主控 / 升级时都先停掉旧进程：一是避免它和 join 抢同一个数据库，
    # 二是覆盖正在运行的二进制会 Text file busy。
    service_cmd stop >/dev/null 2>&1 || true

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
