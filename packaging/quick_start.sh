#!/bin/bash
# ---------------------------------------------------------------------------
# 3Panel one-line installer — bootstrap only.
#
#   bash -c "$(curl -sSL https://3panel.erguotou.me/package/quick_start.sh)"
#
# What this does: resolve the newest release for this machine's architecture,
# download the package, verify its sha256 against the published value, extract
# it, then hand over to the `install.sh` that ships *inside* the package. Every
# real install step lives there — this file only bootstraps.
#
# The release host is served straight off object storage with a CDN in front,
# so no proxy prefix is needed or supported.
#
# Use the `bash -c "$(...)"` form, NOT `curl ... | bash`. install.sh prompts on
# stdin; a pipe would feed it the script text instead of your keyboard.
#
# Environment knobs (all optional)
#   PANEL3_MIRROR     use exactly this base URL and skip probing (local mirror)
#   PANEL3_ORIGIN     release-channel base, INCLUDING the /package segment
#                     (default https://3panel.erguotou.me/package)
#   PANEL3_WORKDIR    where the package is unpacked  (default ./3panel-install)
#   PANEL3_RETRIES    download attempts per URL      (default 5)
#   PANEL3_PROBE_RETRIES
#                     version-probe attempts per base (default 6)
#   PANEL3_LANG       zh | en                        (default: auto from $LANG)
#   INSTALL_MODE      stable | dev | beta            (default stable)
#   ARCH              force amd64 / arm64
#   PANEL_PORT / PANEL_USERNAME / PANEL_PASSWORD / PANEL_ENTRANCE / PANEL_BASE_DIR
#                     read by install.sh; set them for an unattended install.
#                     They must go in the ENVIRONMENT, not on the command line:
#
#   sudo PANEL_PORT=10086 PANEL_USERNAME=admin PANEL_PASSWORD='s3cret' \
#       bash -c "$(curl -sSL <this script url>)"
#
# NOTE: the prefix is PANEL3_, not 3PANEL_ — a shell variable name may not start
# with a digit.
# ---------------------------------------------------------------------------

set -o pipefail

ESC_RED=$'\033[0;31m'
ESC_GREEN=$'\033[0;32m'
ESC_YELLOW=$'\033[0;33m'
ESC_BLUE=$'\033[0;34m'
ESC_OFF=$'\033[0m'

# The release-channel BASE, not the site root: every lookup below appends
# /$MODE/latest, so this must already carry the "/package" segment. Getting this
# wrong produces a plain 404 on https://3panel.erguotou.me/stable/latest, which
# looks like a network problem rather than a wrong URL.
ORIGIN=${PANEL3_ORIGIN:-https://3panel.erguotou.me/package}
MODE=${INSTALL_MODE:-stable}
WORKDIR=${PANEL3_WORKDIR:-$PWD/3panel-install}
RETRIES=${PANEL3_RETRIES:-5}
# The version probe is a tiny request but the most failure-prone step, so it gets
# a larger budget than the multi-megabyte download.
PROBE_RETRIES=${PANEL3_PROBE_RETRIES:-6}
CTL_BIN_NAME="3pctl"

PASSTHRU=("$@")

# --------------------------------------------------------------------------- i18n
LANG_CODE=${PANEL3_LANG:-}
if [ -z "$LANG_CODE" ]; then
    case "${LC_ALL:-${LANG:-}}" in
        zh* | *zh_*) LANG_CODE=zh ;;
        "") LANG_CODE=zh ;; # unset locale: this project's primary audience
        *) LANG_CODE=en ;;
    esac
fi
case "$LANG_CODE" in
    zh | en) ;;
    *) LANG_CODE=en ;;
esac

if [ "$LANG_CODE" = "zh" ]; then
    M_TITLE='3Panel 一键安装'
    M_NEED_ROOT='需要 root 权限。请改用：sudo bash -c "$(curl -sSL <本脚本地址>)"'
    M_NEED_CMD='缺少必需命令：%s，请先安装它'
    M_BAD_ARCH='不支持的架构：%s（本版本只提供 amd64 / arm64）'
    M_BAD_MODE='INSTALL_MODE 无效：%s，仅支持 stable / dev / beta'
    M_ALREADY='检测到 3Panel 已安装。升级请在面板内操作，或先执行 3pctl uninstall 再重装'
    M_MKDIR='无法创建工作目录：%s'
    M_RESOLVING='正在解析 %s 通道的最新版本…'
    M_UNREACHABLE='以下地址都取不到版本信息，请检查网络或 DNS：%s'
    M_PROBE_FAIL='地址不可用，改试下一个：%s'
    M_RESOLVED='目标版本 %s（%s）'
    M_REUSE='本地已有安装包且校验通过，跳过下载'
    M_RESUME='检测到未完成的分片（%s / %s），从断点继续'
    M_DOWNLOAD='正在下载 %s（%s）'
    M_DL_FROM='来源：%s'
    M_DL_FAIL='下载失败（已尝试 %s 次）：%s'
    M_SHORT='传输不完整：%s / %s 字节'
    M_ATTEMPT='第 %s/%s 次传输失败'
    M_NO_RANGE='镜像站不支持断点续传，改为整包重下'
    M_NO_SHA='未找到 sha256 工具（sha256sum / shasum / openssl）'
    M_NO_HASH='未取到校验文件，跳过完整性校验（不影响安装，但不建议）'
    M_HASH_OK='校验和一致'
    M_HASH_BAD='安装包校验不通过（下载可能被截断或篡改），已中止。请重试'
    M_EXTRACT='正在解压…'
    M_EXTRACT_FAIL='解压失败，安装包可能不完整：%s'
    M_NO_INSTALLER='解压后未找到 install.sh，包结构异常：%s'
    M_HANDOVER='交给包内 install.sh 继续安装'
    M_NO_TTY='非交互环境且未提供账号密码，install.sh 会因读不到输入而创建空密码账号。请改用交互终端，或设置 PANEL_USERNAME 与 PANEL_PASSWORD'
    M_KEEP='安装包保留在：%s'
    M_DONE='安装流程结束'
else
    M_TITLE='3Panel one-line installer'
    M_NEED_ROOT='root is required. Re-run as: sudo bash -c "$(curl -sSL <this script url>)"'
    M_NEED_CMD='missing required command: %s'
    M_BAD_ARCH='unsupported architecture: %s (this release only ships amd64 / arm64)'
    M_BAD_MODE='invalid INSTALL_MODE: %s (expected stable / dev / beta)'
    M_ALREADY='3Panel is already installed. Upgrade from inside the panel, or run 3pctl uninstall first'
    M_MKDIR='cannot create work dir: %s'
    M_RESOLVING='Resolving the latest %s build…'
    M_UNREACHABLE='none of these bases could be reached: %s'
    M_PROBE_FAIL='unreachable, trying the next base: %s'
    M_RESOLVED='target version %s (%s)'
    M_REUSE='local package present and verified — skipping download'
    M_RESUME='incomplete partial found (%s of %s) — resuming'
    M_DOWNLOAD='Downloading %s (%s)'
    M_DL_FROM='from %s'
    M_DL_FAIL='download failed after %s attempts: %s'
    M_SHORT='short transfer: %s of %s bytes'
    M_ATTEMPT='transfer failed (attempt %s/%s)'
    M_NO_SHA='no sha256 tool found (sha256sum / shasum / openssl)'
    M_NO_RANGE='mirror does not support byte ranges — restarting the transfer'
    M_NO_HASH='no checksum file published — skipping integrity check'
    M_HASH_OK='checksum verified'
    M_HASH_BAD='package checksum mismatch (truncated or tampered download) — aborting'
    M_EXTRACT='Extracting…'
    M_EXTRACT_FAIL='extract failed, the package is probably incomplete: %s'
    M_NO_INSTALLER='install.sh not found after extracting — unexpected package layout: %s'
    M_HANDOVER='handing over to the package install.sh'
    M_NO_TTY='non-interactive shell without credentials: install.sh cannot prompt and would create an account with an empty password. Use a terminal, or set PANEL_USERNAME and PANEL_PASSWORD'
    M_KEEP='package kept at: %s'
    M_DONE='bootstrap finished'
fi

log() { printf '%s[3Panel]%s %s\n' "$ESC_BLUE" "$ESC_OFF" "$(printf "$@")"; }
warn() { printf '%s[3Panel]%s %s\n' "$ESC_YELLOW" "$ESC_OFF" "$(printf "$@")" >&2; }
die() {
    printf '%s[3Panel]%s %s\n' "$ESC_RED" "$ESC_OFF" "$(printf "$@")" >&2
    exit 1
}

usage() {
    cat <<'EOF'
3Panel one-line installer (bootstrap)

  bash -c "$(curl -sSL https://3panel.erguotou.me/package/quick_start.sh)"

Options:
  --help          show this help and exit
  any other word  forwarded to the package's install.sh (which ignores flags —
                  every option below is an environment variable)

Environment:
  INSTALL_MODE=stable|dev|beta     release channel            (default stable)
  ARCH=amd64|arm64                 override architecture detection
  PANEL3_MIRROR=<base url>         use one exact base, skip probing
  PANEL3_ORIGIN=<base url>         release-channel base, INCLUDING /package
                                   (default https://3panel.erguotou.me/package)
  PANEL3_WORKDIR=<dir>             unpack location   (default ./3panel-install)
  PANEL3_RETRIES=<n>               download attempts per URL (default 5)
  PANEL3_PROBE_RETRIES=<n>         version-probe attempts per base (default 6)
  PANEL3_LANG=zh|en                message language   (default: from $LANG)
  PANEL_PORT / PANEL_USERNAME / PANEL_PASSWORD / PANEL_ENTRANCE / PANEL_BASE_DIR
                                   read by install.sh; set them for an unattended install

Unattended install — the variables go in the ENVIRONMENT, not on the command
line (install.sh does not read flags):

  sudo PANEL_PORT=10086 PANEL_USERNAME=admin PANEL_PASSWORD='s3cret' \
    bash -c "$(curl -sSL <this script url>)"
EOF
}

# ------------------------------------------------------------------- utilities
size_of() { wc -c <"$1" | tr -d ' '; }

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    else
        return 1
    fi
}

# Shared transfer flags. $1 = resume (0/1); the rest is forwarded to curl.
# Quiet when stdout is a pipe, progress bar on a terminal.
curl_get() {
    local resume="$1"
    shift
    local -a opts=(-fL --connect-timeout 15 --max-time 0)
    [ "$resume" = "1" ] && opts+=(-C -)
    if [ -t 1 ]; then
        curl "${opts[@]}" --progress-bar "$@"
    else
        curl "${opts[@]}" -sS "$@"
    fi
}

remote_size() {
    # content-length of the final response; empty when the server is chunked
    curl -fsSIL --connect-timeout 15 --max-time 60 "$1" 2>/dev/null |
        tr -d '\r' | awk 'tolower($1) == "content-length:" { n = $2 } END { if (n != "") print n }'
}

# Small text resources (the version index) still need retries: both the origin
# and the proxy intermittently reset the TLS handshake — measured between ~1 in
# 15 and 2 in 5 requests depending on the moment — and without a retry a single
# reset aborts the whole install. Each attempt is a fresh curl process, i.e. a
# fresh connection, which is what actually clears the reset.
# Deliberately avoids --retry-all-errors: it needs curl >= 7.71, and this has to
# run on old distros too (CentOS 7 ships 7.29).
fetch_text() {
    local url="$1" attempt=0 out=''
    while :; do
        attempt=$((attempt + 1))
        out=$(curl -fsSL --connect-timeout 10 --max-time 45 "$url" 2>/dev/null | tr -d '[:space:]')
        [ -n "$out" ] && {
            printf '%s' "$out"
            return 0
        }
        [ "$attempt" -ge "$PROBE_RETRIES" ] && return 1
        warn "$M_ATTEMPT" "$attempt" "$PROBE_RETRIES"
        sleep 1
    done
}

# Returns 0 with the digest, or 2 when the file is definitively absent (HTTP
# error) — that is a real "not published", not a transient failure, so it must
# not burn the whole retry budget.
fetch_sha256() {
    local url="$1" attempt=0 body='' rc
    while :; do
        attempt=$((attempt + 1))
        body=$(curl -fsSL --connect-timeout 10 --max-time 60 "$url" 2>/dev/null)
        rc=$?
        if [ "$rc" -eq 0 ] && [ -n "$body" ]; then
            printf '%s' "$body" | tr -d '[:space:]'
            return 0
        fi
        [ "$rc" -eq 22 ] && return 2
        [ "$attempt" -ge "$RETRIES" ] && return 1
        sleep 2
    done
}

human_size() {
    awk -v n="${1:-0}" 'BEGIN {
        split("B KB MB GB", u, " "); i = 1
        while (n >= 1024 && i < 4) { n /= 1024; i++ }
        printf (i == 1 ? "%d %s" : "%.1f %s"), n, u[i]
    }'
}

detect_arch() {
    # An ARCH override is validated too: letting an unsupported value through
    # would only turn into a confusing 404 on the package itself.
    local arch="${ARCH:-}"
    if [ -z "$arch" ]; then
        case "$(uname -m)" in
            x86_64 | amd64) arch='amd64' ;;
            aarch64 | arm64) arch='arm64' ;;
            *) arch="$(uname -m)" ;;
        esac
    fi
    case "$arch" in
        amd64 | arm64) printf '%s' "$arch" ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------- checks
preflight() {
    local cmd
    for cmd in curl tar; do
        command -v "$cmd" >/dev/null 2>&1 || die "$M_NEED_CMD" "$cmd"
    done
    command -v sha256sum >/dev/null 2>&1 ||
        command -v shasum >/dev/null 2>&1 ||
        command -v openssl >/dev/null 2>&1 ||
        warn '%s' "$M_NO_SHA"

    [ "$(id -u)" -eq 0 ] || die '%s' "$M_NEED_ROOT"

    if [ -x "/usr/local/bin/$CTL_BIN_NAME" ]; then
        die '%s' "$M_ALREADY"
    fi

    case "$MODE" in
        stable | dev | beta) ;;
        *) die "$M_BAD_MODE" "$MODE" ;;
    esac

    # install.sh reads PORT/USERNAME/PASSWORD from stdin unless they are already
    # set. With no tty that read returns EOF and the panel would be created with
    # an empty username/password — fail loudly instead.
    if [ ! -t 0 ] && { [ -z "${PANEL_USERNAME:-}" ] || [ -z "${PANEL_PASSWORD:-}" ]; }; then
        die '%s' "$M_NO_TTY"
    fi
}

# --------------------------------------------------------------- base + version
# Candidate order: an explicit mirror wins; otherwise the origin itself. The
# first base that returns a non-empty version wins.
resolve_base() {
    local -a candidates=()
    if [ -n "${PANEL3_MIRROR:-}" ]; then
        candidates+=("${PANEL3_MIRROR%/}")
    else
        candidates+=("${ORIGIN%/}")
    fi

    local tried='' base ver
    for base in "${candidates[@]}"; do
        tried="$tried
  - $base"
        ver=$(fetch_text "$base/$MODE/latest") || ver=''
        if [ -n "$ver" ]; then
            BASE="$base"
            VERSION="$ver"
            log "$M_RESOLVED" "$VERSION" "$base"
            return 0
        fi
        warn "$M_PROBE_FAIL" "$base"
    done
    die "$M_UNREACHABLE" "$tried"
    return 1
}

# ------------------------------------------------------------------- download
# Retries with `-C -` (resume). A partial file that keeps failing is deleted and
# restarted, because a resume against an offset the server no longer honours
# produces a file that never reaches the expected size.
download() {
    local url="$1" out="$2" want="$3" attempt=0 resume=1 rc got
    while :; do
        attempt=$((attempt + 1))
        curl_get "$resume" -o "$out" "$url"
        rc=$?
        if [ "$rc" -eq 0 ]; then
            got=$(size_of "$out" 2>/dev/null || echo 0)
            if [ -z "$want" ] || [ "$got" = "$want" ]; then
                return 0
            fi
            # Completed, but short: the partial file is unusable, start clean.
            warn "$M_SHORT" "$got" "$want"
            rm -f "$out"
        elif [ "$rc" -eq 33 ]; then
            # 33 = the server ignored our Range header, so resuming is impossible.
            # Drop the flag and download the whole thing in one go.
            warn '%s' "$M_NO_RANGE"
            resume=0
            rm -f "$out"
        else
            # Keep the partial file: the next attempt resumes from where it stopped.
            warn "$M_ATTEMPT" "$attempt" "$RETRIES"
        fi
        [ "$attempt" -ge "$RETRIES" ] && return 1
        sleep 2
    done
}

# --------------------------------------------------------------------- install
main() {
    local arg
    for arg in "${PASSTHRU[@]}"; do
        case "$arg" in
            -h | --help)
                usage
                return 0
                ;;
        esac
    done

    printf '\n%s==================== %s ====================%s\n\n' \
        "$ESC_GREEN" "$M_TITLE" "$ESC_OFF"

    preflight

    local arch
    arch=$(detect_arch) || die "$M_BAD_ARCH" "${ARCH:-$(uname -m)}"

    mkdir -p "$WORKDIR" || die "$M_MKDIR" "$WORKDIR"

    log "$M_RESOLVING" "$MODE"
    BASE=''
    VERSION=''
    resolve_base

    local pkg="3panel-${VERSION}-linux-${arch}"
    local archive="$pkg.tar.gz"
    local file="$WORKDIR/$archive"
    local url="$BASE/$MODE/$VERSION/release/$archive"

    # ---------------------------------------------------------------- checksum
    # A missing .sha256 downgrades to a warning (a checksum outage should not
    # block installs); a published-but-different one is fatal, below.
    local expected=''
    if expected=$(fetch_sha256 "$url.sha256"); then
        :
    else
        expected=''
        warn '%s' "$M_NO_HASH"
    fi

    # ---------------------------------------------------------------- download
    if [ -f "$file" ] && [ -n "$expected" ] && [ "$(sha256_of "$file")" = "$expected" ]; then
        log '%s' "$M_REUSE"
    else
        local want label have
        want=$(remote_size "$url")
        if [ -f "$file" ]; then
            have=$(size_of "$file" 2>/dev/null || echo 0)
            # Keep a short partial file so `-C -` can pick up where it stopped: on
            # this link a 60 MB transfer stalls often, and discarding 40 MB of
            # progress on every re-run is worse than useless. Anything at or past
            # the expected size is unusable — that is exactly what just failed the
            # checksum — so it gets deleted.
            if [ -z "$want" ] || [ "$have" -ge "$want" ]; then
                rm -f "$file"
            else
                log "$M_RESUME" "$(human_size "$have")" "$(human_size "$want")"
            fi
        fi
        label='?'
        [ -n "$want" ] && label=$(human_size "$want")
        log "$M_DOWNLOAD" "$archive" "$label"
        log "$M_DL_FROM" "$url"
        download "$url" "$file" "$want" || die "$M_DL_FAIL" "$RETRIES" "$url"
    fi

    # ---------------------------------------------------------------- verify
    if [ -n "$expected" ]; then
        local actual
        actual=$(sha256_of "$file") || die '%s' "$M_NO_SHA"
        if [ "$actual" = "$expected" ]; then
            log '%s' "$M_HASH_OK"
        else
            rm -f "$file"
            die '%s' "$M_HASH_BAD"
        fi
    fi

    # ----------------------------------------------------------------- extract
    log '%s' "$M_EXTRACT"
    rm -rf "${WORKDIR:?}/$pkg"
    tar -xzf "$file" -C "$WORKDIR" || die "$M_EXTRACT_FAIL" "$archive"

    local top="$WORKDIR/$pkg"
    if [ ! -f "$top/install.sh" ]; then
        local cand
        for cand in "$WORKDIR"/*/install.sh; do
            [ -f "$cand" ] && top=$(dirname "$cand") && break
        done
    fi
    [ -f "$top/install.sh" ] || die "$M_NO_INSTALLER" "$WORKDIR"

    log '%s' "$M_HANDOVER"
    (cd "$top" && /bin/bash install.sh "${PASSTHRU[@]}")
    local rc=$?

    echo
    log '%s' "$M_DONE"
    log "$M_KEEP" "$file"
    return "$rc"
}

main
