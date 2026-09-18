#!/bin/bash
# 3Panel installer.
#
# This script is shipped inside the release tarball and is used for FRESH
# installs only. Upgrades are performed by the panel itself
# (core/app/service/upgrade.go) and do not use this file.

set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

CURRENT_DIR=$(
    cd "$(dirname "$0")" || exit
    pwd
)

LANG_FILE=".selected_language"
LANG_DIR="$CURRENT_DIR/lang"
AVAILABLE_LANGS=("en" "zh")
declare -A LANG_NAMES
LANG_NAMES=(["en"]="English" ["zh"]="Chinese  中文(简体)")

DEFAULT_BASE_DIR="/opt"
PANEL_DIR_NAME="3panel"
CORE_BIN_NAME="3panel-core"
AGENT_BIN_NAME="3panel-agent"
CTL_BIN_NAME="3pctl"

LOG_FILE="${CURRENT_DIR}/install.log"

function log() {
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[3Panel ${timestamp} install]: $1 " | tee -a "$LOG_FILE"
}

function err() {
    log "$1"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "Please run this script as root or with sudo permissions"
    fi
}

check_tar() {
    if ! command -v tar >/dev/null 2>&1; then
        err "/bin/tar not exists in the system, please install it first"
    fi
}

select_language() {
    if [ -f "$CURRENT_DIR/$LANG_FILE" ]; then
        selected_lang=$(cat "$CURRENT_DIR/$LANG_FILE")
    else
        selected_lang="en"
        echo "$selected_lang" >"$CURRENT_DIR/$LANG_FILE"
    fi
    if [ ! -f "$LANG_DIR/$selected_lang.sh" ]; then
        selected_lang="en"
    fi
    # shellcheck disable=SC1090
    source "$LANG_DIR/$selected_lang.sh"
}

# ---------------------------------------------------------------------------
# Prompts (accept env vars so the install can be fully unattended)
# ---------------------------------------------------------------------------
PANEL_BASE_DIR=${PANEL_BASE_DIR:-$DEFAULT_BASE_DIR}
PANEL_PORT=${PANEL_PORT:-}
PANEL_USERNAME=${PANEL_USERNAME:-}
PANEL_PASSWORD=${PANEL_PASSWORD:-}
PANEL_ENTRANCE=${PANEL_ENTRANCE:-}

prompt_inputs() {
    if [[ -z "$PANEL_PORT" ]]; then
        read -r -p "${TXT_SET_PANEL_PORT:-Set panel port}: " PANEL_PORT
    fi
    [[ -z "$PANEL_PORT" ]] && PANEL_PORT=$(shuf -i 10000-40000 -n 1 2>/dev/null || echo 10086)

    if [[ -z "$PANEL_USERNAME" ]]; then
        read -r -p "${TXT_SET_PANEL_USER:-Set panel username}: " PANEL_USERNAME
    fi
    if [[ -z "$PANEL_PASSWORD" ]]; then
        read -r -s -p "${TXT_SET_PANEL_PASSWORD:-Set panel password}: " PANEL_PASSWORD
        echo
        local confirm
        read -r -s -p "${TXT_SET_PANEL_PASSWORD:-Set panel password}: " confirm
        echo
        [[ "$PANEL_PASSWORD" != "$confirm" ]] && err "Passwords do not match"
    fi

    read -r -p "${TXT_SET_PANEL_ENTRANCE:-Set panel entrance (default /): }" PANEL_ENTRANCE
    PANEL_ENTRANCE=${PANEL_ENTRANCE:-/}
}

# ---------------------------------------------------------------------------
# Install steps
# ---------------------------------------------------------------------------
install_binaries() {
    log "Installing binaries to /usr/local/bin"
    cp -f "$CURRENT_DIR/$CORE_BIN_NAME" /usr/local/bin/ || err "copy $CORE_BIN_NAME failed"
    cp -f "$CURRENT_DIR/$AGENT_BIN_NAME" /usr/local/bin/ || err "copy $AGENT_BIN_NAME failed"
    cp -f "$CURRENT_DIR/$CTL_BIN_NAME" /usr/local/bin/ || err "copy $CTL_BIN_NAME failed"
    chmod +x "/usr/local/bin/$CORE_BIN_NAME" \
        "/usr/local/bin/$AGENT_BIN_NAME" \
        "/usr/local/bin/$CTL_BIN_NAME"
}

install_assets() {
    local run_base_dir="$1"
    if [ -d "$CURRENT_DIR/lang" ]; then
        cp -rf "$CURRENT_DIR/lang" /usr/local/bin || err "copy lang failed"
    fi
    if [ -f "$CURRENT_DIR/GeoIP.mmdb" ]; then
        mkdir -p "$run_base_dir/$PANEL_DIR_NAME/geo"
        cp -f "$CURRENT_DIR/GeoIP.mmdb" "$run_base_dir/$PANEL_DIR_NAME/geo/" || log "copy GeoIP.mmdb failed (non-fatal)"
    fi
    # Keep the initscript directory inside the install dir: the upgrade path
    # reads it from there as a fallback.
    mkdir -p "$run_base_dir/$PANEL_DIR_NAME"
    cp -rf "$CURRENT_DIR/initscript" "$run_base_dir/$PANEL_DIR_NAME" || log "copy initscript failed (non-fatal)"
}

configure_ctl() {
    local ctl="/usr/local/bin/$CTL_BIN_NAME"
    sed -i "s|^BASE_DIR=.*|BASE_DIR=$1|" "$ctl"
    sed -i "s|^ORIGINAL_PORT=.*|ORIGINAL_PORT=$PANEL_PORT|" "$ctl"
    sed -i "s|^ORIGINAL_VERSION=.*|ORIGINAL_VERSION=$2|" "$ctl"
    sed -i "s|^ORIGINAL_USERNAME=.*|ORIGINAL_USERNAME=$PANEL_USERNAME|" "$ctl"
    sed -i "s|^ORIGINAL_PASSWORD=.*|ORIGINAL_PASSWORD=$PANEL_PASSWORD|" "$ctl"
    sed -i "s|^ORIGINAL_ENTRANCE=.*|ORIGINAL_ENTRANCE=$PANEL_ENTRANCE|" "$ctl"
    sed -i "s|^LANGUAGE=.*|LANGUAGE=$selected_lang|" "$ctl"
}

install_service() {
    local init_dir="$CURRENT_DIR/initscript"
    if [ -d /run/systemd/system ] || command -v systemctl >/dev/null 2>&1; then
        log "Configuring systemd services"
        cp -f "$init_dir/$CORE_BIN_NAME.service" /etc/systemd/system/ || err "install core service failed"
        cp -f "$init_dir/$AGENT_BIN_NAME.service" /etc/systemd/system/ || err "install agent service failed"
        systemctl daemon-reload >>"$LOG_FILE" 2>&1
        systemctl enable "$CORE_BIN_NAME.service" >>"$LOG_FILE" 2>&1
        systemctl enable "$AGENT_BIN_NAME.service" >>"$LOG_FILE" 2>&1
        systemctl start "$AGENT_BIN_NAME.service" >>"$LOG_FILE" 2>&1
        systemctl start "$CORE_BIN_NAME.service" >>"$LOG_FILE" 2>&1
    elif [ -f /sbin/openrc-run ]; then
        log "Configuring openrc services"
        cp -f "$init_dir/$CORE_BIN_NAME.openrc" /etc/init.d/"${CORE_BIN_NAME}d" || err "install core service failed"
        chmod +x /etc/init.d/"${CORE_BIN_NAME}d"
        /etc/init.d/"${CORE_BIN_NAME}d" enable >>"$LOG_FILE" 2>&1
        /etc/init.d/"${CORE_BIN_NAME}d" start >>"$LOG_FILE" 2>&1
    else
        log "Configuring sysvinit services"
        cp -f "$init_dir/$CORE_BIN_NAME.init" /etc/init.d/"${CORE_BIN_NAME}d" || err "install core service failed"
        chmod +x /etc/init.d/"${CORE_BIN_NAME}d"
        /etc/init.d/"${CORE_BIN_NAME}d" enable >>"$LOG_FILE" 2>&1
        /etc/init.d/"${CORE_BIN_NAME}d" start >>"$LOG_FILE" 2>&1
    fi
}

open_firewall() {
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        firewall-cmd --zone=public --add-port="$PANEL_PORT"/tcp --permanent >>"$LOG_FILE" 2>&1
        firewall-cmd --reload >>"$LOG_FILE" 2>&1
        log "Opened firewall port $PANEL_PORT/tcp"
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "$PANEL_PORT"/tcp >>"$LOG_FILE" 2>&1
        log "Opened firewall port $PANEL_PORT/tcp"
    fi
}

print_access_info() {
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    [[ -z "$ip" ]] && ip="<server-ip>"
    local entrance="${PANEL_ENTRANCE#/}"
    local url="http://$ip:$PANEL_PORT/"
    [[ -n "$entrance" ]] && url="http://$ip:$PANEL_PORT/$entrance"
    echo
    echo -e "${GREEN}================= 3Panel installed =================${NC}"
    echo -e "  ${BLUE}Panel URL:${NC}   $url"
    echo -e "  ${BLUE}Username:${NC}    $PANEL_USERNAME"
    echo -e "  ${BLUE}Password:${NC}    $PANEL_PASSWORD"
    echo -e "  ${BLUE}Control:${NC}     ${CTL_BIN_NAME} {status|start|stop|restart|uninstall}"
    echo -e "${GREEN}====================================================${NC}"
}

main() {
    check_root
    check_tar
    select_language

    if [ -f "/usr/local/bin/$CTL_BIN_NAME" ]; then
        err "${TXT_PANEL_ALREADY_INSTALLED:-3Panel is already installed, please do not install again}"
    fi

    local version
    version=$(grep -m1 '^ORIGINAL_VERSION=' "$CURRENT_DIR/$CTL_BIN_NAME" | cut -d= -f2)
    version=${version:-unknown}

    prompt_inputs

    install_binaries
    configure_ctl "$PANEL_BASE_DIR" "$version"
    install_assets "$PANEL_BASE_DIR"
    install_service
    open_firewall
    print_access_info
}

main "$@"
