#!/bin/bash
#
# 3Panel 一键加入节点（引导脚本）。
#
# 面板「多机管理」里创建节点后给出的是这条命令：
#
#   PANEL3_MASTER='https://<面板地址>' PANEL3_TOKEN='<一次性 token>' \
#     bash -c "$(curl -sSL https://3panel.erguotou.me/package/join.sh)"
#
# 这里只做引导，不写业务逻辑：
#
#   探测架构 → 取版本 → 选择一个可用下载源 → 拉 agent 独立包 → 校验 sha256
#   → 解压 → 交给包内的 install-agent.sh（安装 + 换证书 + 起服务）
#
# 安装逻辑放在包里、而不是放在这里，是为了让它跟二进制同版本一起演进。
#
# 为什么要有独立包：整包 54MB（含面板本体、前端产物、19MB GeoIP），节点只需要
# agent。agent 独立包约 26MB，少了一半；万一某个版本没发独立包，本脚本会自动
# 回退到整包里抽 agent（见 fetch_package）。
#
# 环境变量
#   PANEL3_MASTER / PANEL3_TOKEN        必填，也可用 --master/--token
#   PANEL3_ADDR / PANEL3_PORT           节点回连地址 / 端口（默认自动探测、9999）
#   PANEL3_BASE_DIR                     安装目录，默认 /opt
#   PANEL3_VERSION                      指定版本；留空取频道 latest
#   PANEL3_ARCH                         覆盖架构探测（amd64|arm64）
#   PANEL3_ORIGIN                       发布源，默认 https://3panel.erguotou.me/package
#   PANEL3_MIRROR                       自建镜像，设了就只走它
#   PANEL3_RETRIES / PANEL3_PROBE_RETRIES  下载重试次数 / 版本探测重试次数
#   PANEL3_WORKDIR                      下载与解压目录，默认 /tmp/3panel-agent-join
#   PANEL3_LANG                         zh|en，默认 zh
#
set -uo pipefail

ORIGIN="${PANEL3_ORIGIN:-https://3panel.erguotou.me/package}"
MIRROR="${PANEL3_MIRROR:-}"
RETRIES="${PANEL3_RETRIES:-5}"
PROBE_RETRIES="${PANEL3_PROBE_RETRIES:-6}"
WORKDIR="${PANEL3_WORKDIR:-/tmp/3panel-agent-join}"
VERSION="${PANEL3_VERSION:-}"
# 版本没指定时按这个顺序找 latest；发布的版本一定在 stable（非 beta）或 beta 里，
# dev 是同一个版本的副本，放在第二位只是为了让只发 dev 的镜像也能用。
CHANNELS="${PANEL3_CHANNELS:-stable dev beta}"

MASTER="${PANEL3_MASTER:-}"
TOKEN="${PANEL3_TOKEN:-}"
NODE_ADDR="${PANEL3_ADDR:-}"
NODE_PORT="${PANEL3_PORT:-9999}"
BASE_DIR="${PANEL3_BASE_DIR:-/opt}"
# 留空表示「自动」：detect_lang 会按终端字符集决定，避免 GBK 终端满屏乱码。
LANG_CODE="${PANEL3_LANG:-}"
NO_FIREWALL="${PANEL3_NO_FIREWALL:-0}"

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

# sha256sum 是 Linux 的，shasum 是 macOS 的；目标平台是 Linux，这里兼容开发机。
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

trim_slash() { printf '%s' "${1%/}"; }

usage() {
    cat <<'EOF'
Usage: bash -c "$(curl -sSL <join.sh url>)"      配合下面的环境变量使用

  PANEL3_MASTER='https://10.0.0.1:9999'   面板地址
  PANEL3_TOKEN='...'                      创建节点时生成的一次性 token
  PANEL3_ADDR='10.0.0.2'                  可选，面板回连本机的地址
  PANEL3_PORT=9999                        可选，本机 agent 监听端口
  PANEL3_VERSION='v2.0.2'                 可选，指定版本

也可以把脚本存到本地再执行：
  ./join.sh --master https://10.0.0.1:9999 --token 0f3d...
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --master) MASTER="${2:-}"; shift 2 ;;
            --token) TOKEN="${2:-}"; shift 2 ;;
            --addr) NODE_ADDR="${2:-}"; shift 2 ;;
            --port) NODE_PORT="${2:-}"; shift 2 ;;
            --base-dir) BASE_DIR="${2:-}"; shift 2 ;;
            --version) VERSION="${2:-}"; shift 2 ;;
            --lang) LANG_CODE="${2:-}"; shift 2 ;;
            --no-firewall) NO_FIREWALL=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *) err "unknown argument: $1" ;;
        esac
    done
    if [[ -z "$MASTER" || -z "$TOKEN" ]]; then
        usage
        err "$(say "缺少 --master / --token" "missing --master / --token")"
    fi
}

check_env() {
    [[ "$(id -u)" -eq 0 ]] || err "$(say "请用 root 执行这条命令" "run this command as root")" \
        "$(say "例如：sudo bash -c \"\$(curl -sSL ...)\"" "e.g. sudo bash -c \"\$(curl -sSL ...)\"")"
    [[ "$(uname -s)" == "Linux" ]] || err "$(say "只支持 Linux 主机" "only Linux hosts are supported")"
    command -v curl >/dev/null 2>&1 || err "curl is required"
    command -v tar >/dev/null 2>&1 || err "tar is required"
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
# 这台机器到 CDN 边缘的 TLS 握手偶发被重置（curl 35/28），单次请求不能当结论，
# 所以探测一律重试，而且每次都用新的 curl 进程（新连接），否则会一直复用坏连接。
CURL_TXT=(--connect-timeout 15 --max-time 30 -sS -L -f)
# 包体大（26~54MB），-sS 会让慢速下载看起来像卡死：终端上给进度条，管道里保持安静。
CURL_PKG=(--connect-timeout 20 --max-time 1800 -L -f --speed-limit 1024 --speed-time 90)

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
#   与 fetch_text 的区别：这里「文件不存在」是正常分支（用来判断某个版本/频道
#   有没有这个包），所以不要用重试预算去磨 404。
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
    local -a meter=(-sS)
    [[ -t 2 ]] && meter=(--progress-bar)
    for ((i = 1; i <= RETRIES; i++)); do
        rc=0
        info "$(say "第 ${i}/${RETRIES} 次传输" "transfer attempt ${i}/${RETRIES}")"
        curl "${CURL_PKG[@]}" "${meter[@]}" -C - -o "$out" "$url" || rc=$?

        if [[ $rc -eq 33 ]]; then
            # 服务端忽略 Range：带着 -C - 必然失败，去掉续传标志重来一次。
            warn "$(say "下载源不支持断点续传，改为整包重下" "the mirror ignores Range — restarting the whole download")"
            rm -f "$out"
            rc=0
            curl "${CURL_PKG[@]}" "${meter[@]}" -o "$out" "$url" || rc=$?
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
# 下载源顺序：自建镜像 > 发布源。第一个能取到版本的胜出。
build_bases() {
    BASES=()
    if [[ -n "$MIRROR" ]]; then
        BASES+=("$(trim_slash "$MIRROR")")
        return
    fi
    BASES+=("$(trim_slash "$ORIGIN")")
}

# 取版本：显式指定优先，否则依次问 stable/dev/beta 的 latest。
resolve_version() {
    local base ch tmp
    tmp="$(mktemp)"
    for base in "${BASES[@]}"; do
        for ch in $CHANNELS; do
            if fetch_text "$base/$ch/latest" "$tmp"; then
                VERSION="$(head -n1 "$tmp" | tr -d '[:space:]')"
                if [[ -n "$VERSION" ]]; then
                    info "$(say "取自 $base/$ch/latest" "resolved from $base/$ch/latest")"
                    rm -f "$tmp"
                    return 0
                fi
            fi
        done
        warn "$(say "取不到版本号，换下一个下载源：$base" "unreachable, trying the next base: $base")"
    done
    rm -f "$tmp"
    return 1
}

PKG_KIND=""
PKG_CHANNEL=""
PKG_BASE=""
PKG_SHA=""
PKG_URL=""

# 在某个 base 上找这个版本的包：先找 agent 独立包，找不到再退回整包。
locate_package() {
    local base="$1" ch candidate sha url
    for ch in $CHANNELS; do
        # agent 独立包
        url="$base/$ch/$VERSION/release/3panel-agent-$VERSION-linux-$ARCH.tar.gz"
        if sha="$(fetch_sha256 "$url.sha256")" && [[ -n "$sha" ]]; then
            PKG_KIND="agent"
            PKG_CHANNEL="$ch"
            PKG_BASE="$base"
            PKG_SHA="$sha"
            PKG_URL="$url"
            return 0
        fi
        # 整包回退：老版本（或忘了发独立包的版本）里 agent 在整包内
        url="$base/$ch/$VERSION/release/3panel-$VERSION-linux-$ARCH.tar.gz"
        if sha="$(fetch_sha256 "$url.sha256")" && [[ -n "$sha" ]]; then
            PKG_KIND="full"
            PKG_CHANNEL="$ch"
            PKG_BASE="$base"
            PKG_SHA="$sha"
            PKG_URL="$url"
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# 取包 → 校验 → 解压
# ---------------------------------------------------------------------------
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
            find "$pkgdir/initscript" -type f ! -name '3panel-agent.*' -delete
        fi
        fetch_bootstrap_installer || return 1
        cp -f "$WORKDIR/install-agent.sh" "$pkgdir/install-agent.sh"
    fi

    EXTRACTED_DIR="$pkgdir"
    return 0
}

# verify_archive <archive>   0 一致；1 不一致（清理交给调用方 —— 校验失败的包要删掉，
#                            否则下次运行会拿它当「已验证」直接跳过下载）
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
    detect_lang
    parse_args "$@"
    check_env
    detect_arch

    mkdir -p "$WORKDIR"
    build_bases

    step "$(say "3Panel 节点加入" "3Panel node join")"
    info "$MASTER"
    info "$(say "架构 $ARCH" "arch $ARCH")"

    if [[ -z "$VERSION" ]]; then
        step "$(say "查询可用版本" "Resolving the version")"
        resolve_version || err "$(say "取不到版本号：所有下载源都不可达，或版本路径不对" \
            "could not resolve a version — every download source failed")" \
            "$(say "可以手工指定：PANEL3_VERSION=v2.0.2" "you can pin it: PANEL3_VERSION=v2.0.2")"
    fi
    info "$(say "目标版本" "version")  $VERSION"

    fetch_package || err "$(say "没找到 ${VERSION} 的发布包（${ARCH}）" \
        "no published package for ${VERSION} (${ARCH})")" \
        "$(say "确认发布源里有这个版本，或换一个：PANEL3_VERSION=..." \
            "check that the version exists on the release host")"

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

    step "$(say "交给包内安装器" "Handing over to the packaged installer")"
    local args=(--master "$MASTER" --token "$TOKEN" --port "$NODE_PORT" --base-dir "$BASE_DIR" --lang "$LANG_CODE")
    args+=(--version "$VERSION")
    [[ -n "$NODE_ADDR" ]] && args+=(--addr "$NODE_ADDR")
    [[ "$NO_FIREWALL" == "1" ]] && args+=(--no-firewall)

    "$EXTRACTED_DIR/install-agent.sh" "${args[@]}"
}

main "$@"
