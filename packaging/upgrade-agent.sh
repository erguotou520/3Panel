#!/bin/bash
#
# 3Panel 节点 agent 一键升级（引导脚本）。
#
# 在节点机上执行：
#
#   bash -c "$(curl -sSL https://3panel.erguotou.me/package/upgrade-agent.sh)"
#
# 与 join.sh 的分工：
#   join.sh           给**没装过** agent 的机器用，要一次性 token、要换证书
#   upgrade-agent.sh  给**已经加入过**的节点用，不需要 token、不碰证书
#
# 为什么必须单独做：主控升级不会带动节点（core 不校验节点版本，只在节点列表里展示），
# 而 token 是一次性的、同名节点又不能重复创建（`ErrRecordExist`），所以「重跑一键加入
# 命令」这条升级路走不通。升级本质上只是换二进制 —— 证书与注册关系都在
# <base-dir>/3panel 下，原样保留即可。
#
# 流程：读现有配置 → 解析目标版本 → 选源 → 拉 agent 独立包（缺则回退整包）
#       → 校验 sha256 → 解压 → 交给包内 install-agent.sh --no-join
#
# 安装逻辑同样放在包里，让它跟二进制同版本一起演进；本脚本只做引导。
#
# 环境变量
#   PANEL3_CHANNEL                      发布频道，默认 stable
#   PANEL3_VERSION                      钉住版本；留空取该频道的 latest
#   PANEL3_ARCH                         覆盖架构探测（amd64|arm64）
#   PANEL3_ORIGIN                       发布源，默认 https://3panel.erguotou.me/package
#   PANEL3_MIRROR                       自建镜像，设了就只走它
#   PANEL3_RETRIES / PANEL3_PROBE_RETRIES  下载重试次数 / 版本探测重试次数
#   PANEL3_WORKDIR                      下载与解压目录，默认 /tmp/3panel-agent-upgrade
#   PANEL3_LANG                         zh|en，脚本自身提示语言
#   PANEL3_FORCE=1                      目标版本与当前一致时也重装一遍
#
set -uo pipefail

ORIGIN="${PANEL3_ORIGIN:-https://3panel.erguotou.me/package}"
MIRROR="${PANEL3_MIRROR:-}"
CHANNEL="${PANEL3_CHANNEL:-stable}"
RETRIES="${PANEL3_RETRIES:-5}"
PROBE_RETRIES="${PANEL3_PROBE_RETRIES:-6}"
WORKDIR="${PANEL3_WORKDIR:-/tmp/3panel-agent-upgrade}"
VERSION="${PANEL3_VERSION:-}"
FORCE="${PANEL3_FORCE:-0}"

AGENT_BIN_NAME="3panel-agent"
AGENT_PATH="/usr/local/bin/${AGENT_BIN_NAME}"
CTL_PATH="/usr/local/bin/3pctl"
SERVICE_NAME="3panel-agent"

# 脚本自身的提示语言：显式 PANEL3_LANG > 系统 locale。
LANG_CODE="${PANEL3_LANG:-}"
if [[ -z "$LANG_CODE" ]]; then
    case "${LC_ALL:-${LANG:-}}" in
        zh* | *zh_*) LANG_CODE=zh ;;
        "") LANG_CODE=zh ;;
        *) LANG_CODE=en ;;
    esac
fi

# ---------------------------------------------------------------------------
# 输出与工具
# ---------------------------------------------------------------------------
say() { # say <中文> <English>
    if [[ "$LANG_CODE" == "zh" ]]; then printf '%s\n' "$1"; else printf '%s\n' "$2"; fi
}
step() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }
info() { printf '    %s\n' "$1"; }
warn() { printf '\033[0;33m[warn] %s\033[0m\n' "$1"; }
err() {
    printf '\n\033[0;31m[error] %s\033[0m\n' "$1" >&2
    [[ $# -gt 1 ]] && printf '\033[0;31m        %s\033[0m\n' "$2" >&2
    exit 1
}

# sha256sum 是 Linux 的，shasum 是 macOS 的；目标平台是 Linux，这里兼容开发机。
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

trim_slash() { printf '%s' "${1%/}"; }

# ctl_get <KEY>   读节点上 3pctl 里记的值（BASE_DIR / ORIGINAL_VERSION / …）
ctl_get() {
    grep -m1 "^$1=" "$CTL_PATH" 2>/dev/null | cut -d= -f2- | tr -d '"'
}

usage() {
    cat <<'EOF'
Usage: bash -c "$(curl -sSL <upgrade-agent.sh url>)"

  PANEL3_VERSION='v2.0.4'                 可选，钉住版本（默认取频道 latest）
  PANEL3_CHANNEL=stable                   可选，发布频道（stable|dev|beta）
  PANEL3_MIRROR='https://mirror/package'  可选，自建镜像，设了就只走它
  PANEL3_FORCE=1                          可选，版本相同也重装

也可以把脚本存到本地再执行：
  ./upgrade-agent.sh --version v2.0.4
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --version) VERSION="${2:-}"; shift 2 ;;
            --channel) CHANNEL="${2:-}"; shift 2 ;;
            --mirror) MIRROR="${2:-}"; shift 2 ;;
            --lang) LANG_CODE="${2:-}"; shift 2 ;;
            --force) FORCE=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *) err "unknown argument: $1" ;;
        esac
    done
}

check_env() {
    [[ "$(id -u)" -eq 0 ]] || err "$(say "请用 root 执行这条命令" "run this command as root")" \
        "$(say "例如：sudo bash -c \"\$(curl -sSL ...)\"" "e.g. sudo bash -c \"\$(curl -sSL ...)\"")"
    [[ "$(uname -s)" == "Linux" ]] || err "$(say "只支持 Linux 主机" "only Linux hosts are supported")"
    command -v curl >/dev/null 2>&1 || err "curl is required"
    command -v tar >/dev/null 2>&1 || err "tar is required"
}

# 升级只对「已经加入过」的节点有意义：这两个文件是 join 装出来的。
check_installed() {
    if [[ ! -f "$CTL_PATH" || ! -f "$AGENT_PATH" ]]; then
        err "$(say "这台机器上没有 3Panel 节点 agent，没有什么可升级的" \
            "no 3Panel node agent found on this host")" \
            "$(say "新节点请用面板「多机管理」给出的加入命令（join.sh）" \
                "for a new node use the join command shown in the panel")"
    fi
}

detect_arch() {
    local raw="${PANEL3_ARCH:-$(uname -m)}"
    case "$raw" in
        x86_64 | amd64) ARCH=amd64 ;;
        aarch64 | arm64) ARCH=arm64 ;;
        *) err "$(say "不支持的架构：$raw" "unsupported architecture: $raw")" \
            "$(say "只提供 amd64 / arm64 两种包" "only amd64 / arm64 packages are published")" ;;
    esac
}

# ---------------------------------------------------------------------------
# 网络：探测 / 下载 / 校验
# ---------------------------------------------------------------------------
# 到 CDN 边缘的 TLS 握手偶发被重置（curl 35/28），单次请求不能当结论，所以探测
# 一律重试，而且每次都用新的 curl 进程（新连接），否则会一直复用坏连接。
CURL_TXT=(--connect-timeout 15 --max-time 30 -sS -L -f)
CURL_PKG=(--connect-timeout 20 --max-time 1800 -sS -L -f --speed-limit 1024 --speed-time 90)

# fetch_text <url> <outfile>
#   0 成功（输出非空）；2 目标不存在（HTTP 4xx）；1 探测失败（网络问题）
fetch_text() {
    local url="$1" out="$2" i rc
    for ((i = 1; i <= PROBE_RETRIES; i++)); do
        : >"$out"
        rc=0
        curl "${CURL_TXT[@]}" -o "$out" "$url" 2>/dev/null || rc=$?
        [[ -s "$out" ]] && return 0
        [[ $rc -eq 22 ]] && return 2
        sleep 1
    done
    return 1
}

# fetch_sha256 <url>   成功时把校验和打到 stdout
#   与 fetch_text 的区别：这里「文件不存在」是正常分支（用来判断某个版本有没有这个包），
#   所以不要用重试预算去磨 404。
fetch_sha256() {
    local url="$1" out i rc
    out="$(mktemp)"
    for ((i = 1; i <= 2; i++)); do
        rc=0
        curl "${CURL_TXT[@]}" -o "$out" "$url" 2>/dev/null || rc=$?
        if [[ -s "$out" ]]; then
            awk '{print $1}' "$out" | head -n1
            rm -f "$out"
            return 0
        fi
        [[ $rc -eq 22 ]] && break
        sleep 1
    done
    rm -f "$out"
    return 1
}

# download <url> <outfile>   断点续传 + 重试；镜像不支持 Range 时退回整包重下
#   0 成功；2 目标不存在；1 重试耗尽
download() {
    local url="$1" out="$2" i rc
    for ((i = 1; i <= RETRIES; i++)); do
        rc=0
        info "$(say "第 $i/$RETRIES 次传输" "transfer attempt $i/$RETRIES")"
        curl "${CURL_PKG[@]}" -C - -o "$out" "$url" || rc=$?

        if [[ $rc -eq 33 ]]; then
            # 服务端忽略 Range：带着 -C - 必然失败，去掉续传标志重来一次。
            warn "$(say "下载源不支持断点续传，改为整包重下" "the mirror ignores Range — restarting the whole download")"
            rm -f "$out"
            rc=0
            curl "${CURL_PKG[@]}" -o "$out" "$url" || rc=$?
        fi

        [[ $rc -eq 22 ]] && return 2
        if [[ $rc -ne 0 ]]; then
            warn "$(say "传输中断（curl ${rc}），保留已下载的部分重试" "transfer interrupted (curl ${rc}), keeping the partial file")"
            sleep 2
            continue
        fi
        return 0
    done
    return 1
}

# ---------------------------------------------------------------------------
# 定位包
# ---------------------------------------------------------------------------
# 下载源顺序：自建镜像 > 发布源。
build_bases() {
    BASES=()
    if [[ -n "$MIRROR" ]]; then
        BASES+=("$(trim_slash "$MIRROR")")
        return
    fi
    BASES+=("$(trim_slash "$ORIGIN")")
}

# 升级只认一个频道 —— 节点必须跟主控待在同一条通道上，所以不遍历 stable/dev/beta。
resolve_version() {
    local base tmp
    tmp="$(mktemp)"
    for base in "${BASES[@]}"; do
        if fetch_text "$base/$CHANNEL/latest" "$tmp"; then
            VERSION="$(head -n1 "$tmp" | tr -d '[:space:]')"
            if [[ -n "$VERSION" ]]; then
                info "$(say "取自 $base/$CHANNEL/latest" "resolved from $base/$CHANNEL/latest")"
                rm -f "$tmp"
                return 0
            fi
        fi
        warn "$(say "取不到版本号，换下一个下载源：$base" "unreachable, trying the next base: $base")"
    done
    rm -f "$tmp"
    return 1
}

PKG_KIND=""
PKG_BASE=""
PKG_SHA=""
PKG_URL=""

# 在某个 base 上找这个版本的包：先找 agent 独立包，找不到再退回整包。
locate_package() {
    local base="$1" sha url
    url="$base/$CHANNEL/$VERSION/release/3panel-agent-$VERSION-linux-$ARCH.tar.gz"
    if sha="$(fetch_sha256 "$url.sha256")" && [[ -n "$sha" ]]; then
        PKG_KIND="agent"
        PKG_BASE="$base"
        PKG_SHA="$sha"
        PKG_URL="$url"
        return 0
    fi
    # 整包回退：老版本（或忘了发独立包的版本）里 agent 在整包内
    url="$base/$CHANNEL/$VERSION/release/3panel-$VERSION-linux-$ARCH.tar.gz"
    if sha="$(fetch_sha256 "$url.sha256")" && [[ -n "$sha" ]]; then
        PKG_KIND="full"
        PKG_BASE="$base"
        PKG_SHA="$sha"
        PKG_URL="$url"
        return 0
    fi
    return 1
}

fetch_package() {
    local base
    step "$(say "选择下载源" "Choosing a download source")"
    for base in "${BASES[@]}"; do
        if locate_package "$base"; then
            if [[ "$PKG_KIND" == "agent" ]]; then
                info "$PKG_KIND: $PKG_URL"
            else
                warn "$(say "该版本没有 agent 独立包，回退到整包抽取 agent" \
                    "no standalone agent package for this version — falling back to the full package")"
                info "$PKG_KIND: $PKG_URL"
            fi
            return 0
        fi
        warn "$(say "这个源上没有 $VERSION 的包，换下一个：$base" \
            "no package for $VERSION on this base, trying the next one: $base")"
    done
    return 1
}

fetch_bootstrap_installer() {
    local url dest
    dest="$WORKDIR/install-agent.sh"
    # 整包回退时包里没有 install-agent.sh（老版本就打出去了），单独取一份。
    url="$PKG_BASE/install-agent.sh"
    if ! curl "${CURL_TXT[@]}" -o "$dest" "$url" 2>/dev/null || [[ ! -s "$dest" ]]; then
        return 1
    fi
    chmod 0755 "$dest"
    return 0
}

extract_package() {
    local archive="$1" pkgdir
    step "$(say "解压" "Extracting")"
    rm -rf "$WORKDIR/tree"
    mkdir -p "$WORKDIR/tree"
    tar -xzf "$archive" -C "$WORKDIR/tree" || return 1

    if [[ "$PKG_KIND" == "agent" ]]; then
        pkgdir="$WORKDIR/tree/3panel-agent-$VERSION-linux-$ARCH"
        [[ -d "$pkgdir" ]] || return 1
    else
        # 整包：只留下节点用得上的部分（agent 二进制、3pctl、语言包、服务定义）。
        pkgdir="$WORKDIR/tree/agent-only"
        mkdir -p "$pkgdir"
        tar -xzf "$archive" -C "$pkgdir" --strip-components=1 \
            "3panel-$VERSION-linux-$ARCH/3panel-agent" \
            "3panel-$VERSION-linux-$ARCH/3pctl" \
            "3panel-$VERSION-linux-$ARCH/lang" \
            "3panel-$VERSION-linux-$ARCH/initscript" || return 1
        # 整包里 agent 的服务定义和 core 混在一个 initscript/ 目录里，只留 agent 的。
        if [[ -d "$pkgdir/initscript" ]]; then
            find "$pkgdir/initscript" -type f ! -name "3panel-agent.*" -delete 2>/dev/null || true
        fi
        fetch_bootstrap_installer || return 1
        cp -f "$WORKDIR/install-agent.sh" "$pkgdir/install-agent.sh"
    fi

    EXTRACTED_DIR="$pkgdir"
    return 0
}

verify_archive() {
    local archive="$1" got
    step "$(say "校验 sha256" "Verifying sha256")"
    got="$(sha256_of "$archive")"
    if [[ "$got" != "$PKG_SHA" ]]; then
        warn "$(say "校验和不一致" "checksum mismatch")"
        warn "$(say "  期望 $PKG_SHA" "  expected $PKG_SHA")"
        warn "$(say "  实际 $got" "  got      $got")"
        return 1
    fi
    info "$(say "校验和一致" "checksum ok")  $got"
}

# ---------------------------------------------------------------------------
main() {
    parse_args "$@"
    check_env
    detect_arch
    check_installed

    local cur_ver cur_base cur_port cur_lang
    cur_ver="$(ctl_get ORIGINAL_VERSION)"
    cur_base="$(ctl_get BASE_DIR)"
    cur_port="$(ctl_get ORIGINAL_PORT)"
    cur_lang="$(ctl_get LANGUAGE)"
    cur_base="${cur_base:-/opt}"
    cur_port="${cur_port:-9999}"
    cur_lang="${cur_lang:-zh}"

    step "$(say "3Panel 节点 agent 升级" "3Panel node agent upgrade")"
    info "$(say "架构 $ARCH" "arch $ARCH")"
    info "$(say "当前版本 ${cur_ver:-unknown}" "current version ${cur_ver:-unknown}")"
    info "$(say "数据目录 ${cur_base}（证书与数据留在原地）" "data dir ${cur_base} (certificates stay put)")"

    mkdir -p "$WORKDIR"
    build_bases

    if [[ -z "$VERSION" ]]; then
        step "$(say "查询可用版本" "Resolving the version")"
        resolve_version || err "$(say "取不到版本号：下载源不可达，或频道 ${CHANNEL} 上没有 latest" \
            "could not resolve a version from channel ${CHANNEL}")" \
            "$(say "可以手工指定：PANEL3_VERSION=v2.0.4" "you can pin it: PANEL3_VERSION=v2.0.4")"
    fi
    info "$(say "目标版本" "target version")  $VERSION"

    if [[ "$VERSION" == "$cur_ver" && "$FORCE" != "1" ]]; then
        info "$(say "已经是最新版本，无需升级" "already up to date")"
        info "$(say "要强制重装一遍：PANEL3_FORCE=1" "to reinstall anyway: PANEL3_FORCE=1")"
        exit 0
    fi

    fetch_package || err "$(say "没找到 ${VERSION} 的发布包（${ARCH}）" \
        "no published package for ${VERSION} (${ARCH})")" \
        "$(say "确认频道 ${CHANNEL} 上有这个版本" "check that the version exists on channel ${CHANNEL}")"

    ARCHIVE="$WORKDIR/$(basename "$PKG_URL")"
    if [[ -f "$ARCHIVE" ]] && [[ "$(sha256_of "$ARCHIVE")" == "$PKG_SHA" ]]; then
        info "$(say "复用已下载并校验过的包" "reusing the already verified archive")"
    else
        download "$PKG_URL" "$ARCHIVE"
        case $? in
            0) ;;
            2) err "$(say "包在下载源上不存在了" "the package disappeared from the download source")" ;;
            *) err "$(say "下载失败（已尝试 $RETRIES 次）" "download failed after $RETRIES attempts")" ;;
        esac
        if ! verify_archive "$ARCHIVE"; then
            rm -f "$ARCHIVE"
            err "$(say "校验和不一致，已中止（不一致的包不执行）" "checksum mismatch, aborted")" \
                "$(say "期望 $PKG_SHA" "expected $PKG_SHA")"
        fi
    fi

    extract_package "$ARCHIVE" || err "$(say "解压失败" "extraction failed")"

    [[ -f "$EXTRACTED_DIR/install-agent.sh" ]] || err "$(say "包内缺少 install-agent.sh" \
        "install-agent.sh is missing inside the package")"
    chmod 0755 "$EXTRACTED_DIR/install-agent.sh"

    step "$(say "交给包内安装器（只换二进制，不重新加入）" "Handing over to the packaged installer (binaries only, no re-join)")"
    # --no-join：节点上已有证书；BASE_DIR / 端口 / 语言都沿用现有值，不改变节点布局。
    local args=(--no-join --version "$VERSION" --base-dir "$cur_base" --port "$cur_port" --lang "$cur_lang")
    "$EXTRACTED_DIR/install-agent.sh" "${args[@]}"
}

main "$@"
