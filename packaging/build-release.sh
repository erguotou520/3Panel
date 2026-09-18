#!/usr/bin/env bash
#
# Build a 3Panel release package that matches the layout the panel's upgrade
# path expects (core/app/service/upgrade.go):
#
#   3panel-<version>-linux-<arch>/
#   ├── 3panel-core                              -> /usr/local/bin/3panel-core
#   ├── 3panel-agent                             -> /usr/local/bin/3panel-agent
#   ├── 3pctl                                    -> /usr/local/bin/3pctl
#   ├── install.sh
#   ├── GeoIP.mmdb                               -> <install-dir>/3panel/geo/GeoIP.mmdb
#   ├── initscript/                              -> service definitions
#   └── lang/                                    -> /usr/local/bin/lang
#
# Usage:
#   ./packaging/build-release.sh <version> [arch...]
#
#   version   e.g. v1.0.0  (a "beta" substring routes the panel to the beta channel)
#   arch      one or more of amd64 arm64 (default: amd64 arm64)
#
# Environment:
#   RESOURCE_BASE   base URL that serves lang.tar.gz / GeoIP.mmdb
#                   (default: https://3panel.erguotou.me/resource)
#   GEOIP_FILE      local mmdb to embed verbatim instead of downloading one
#   GEOIP_FALLBACK  extra URL tried when <RESOURCE_BASE>/geo/GeoIP.mmdb is not
#                   available (default: the upstream 1Panel copy; "" disables)
#   OUT_DIR         where artifacts are written (default: ./dist)
#   SKIP_FRONTEND   set to 1 to reuse an existing frontend build
#
# The language catalog is read from packaging/lang/ in this repository, so a
# normal build never needs RESOURCE_BASE to be reachable. RESOURCE_BASE is only
# used as a fallback for lang and as the first source for GeoIP.
#
# GeoIP note — the schema is NOT stock MaxMind.
#   core/utils/geo/geo.go decodes a custom record shape: top-level `iso`,
#   `country.{en,zh}`, `latitude`, `longitude`, `province.{en,zh}`.
#   MaxMind's own GeoLite2-City instead nests `country.iso_code`,
#   `country.names.*`, `location.latitude/longitude` and `subdivisions[]`, so
#   dropping the official file in loads fine but resolves every lookup to an
#   empty string — a silent failure. Only the 1Panel-published mmdb matches.
#   Mirror that file to <RESOURCE_BASE>/geo/GeoIP.mmdb and the build uses yours.
#
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "usage: $0 <version> [arch...]" >&2
    exit 1
fi
shift || true

ARCHES=("$@")
if [[ ${#ARCHES[@]} -eq 0 ]]; then
    ARCHES=(amd64 arm64)
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGING_DIR="$ROOT_DIR/packaging"
RESOURCE_BASE="${RESOURCE_BASE:-https://3panel.erguotou.me/resource}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/dist}"
SKIP_FRONTEND="${SKIP_FRONTEND:-0}"
GEOIP_FILE="${GEOIP_FILE:-}"
# The upstream 1Panel copy is the only published mmdb with the record schema
# this panel decodes; it is a static data file, fetched read-only at build time.
GEOIP_FALLBACK="${GEOIP_FALLBACK-https://resource.fit2cloud.com/1panel/resource/geo/GeoIP.mmdb}"

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }
warn() { printf '\033[0;33m[warn] %s\033[0m\n' "$1"; }

# Portable sha256: sha256sum on Linux, shasum on macOS.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

step "3Panel release build: version=$VERSION arches=${ARCHES[*]}"

# ---------------------------------------------------------------------------
# 1. Frontend (must run first: core embeds core/cmd/server/web/assets)
# ---------------------------------------------------------------------------
if [[ "$SKIP_FRONTEND" != "1" ]]; then
    step "Building frontend"
    (cd "$ROOT_DIR/frontend" && npm install --no-audit --no-fund && npm run build:pro)
else
    warn "SKIP_FRONTEND=1: reusing existing frontend build"
fi

if [[ ! -d "$ROOT_DIR/core/cmd/server/web/assets" ]]; then
    echo "frontend assets missing at core/cmd/server/web/assets" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

# ---------------------------------------------------------------------------
# 2. Stamp the release version into the embedded config
# ---------------------------------------------------------------------------
# core/cmd/server/conf/app.yaml is `go:embed`-ed into the core binary, and
# core/init/hook/hook.go re-syncs the DB's SystemVersion to that value on EVERY
# start. If the embedded version does not match the release tag, an upgraded
# panel falls back to the old number on restart and keeps offering the same
# upgrade forever. So the tag has to be compiled in.
# The repo copy is restored afterwards so builds do not dirty the working tree.
step "Stamping version $VERSION into the embedded app.yaml"
STAMPED_FILES=()
restore_stamped() {
    for f in "${STAMPED_FILES[@]:-}"; do
        [[ -n "$f" && -f "$f.bak" ]] && mv -f "$f.bak" "$f"
    done
    # An EXIT trap that ends on a non-zero status can change the script's exit
    # code, which would turn a good build into a failed one.
    return 0
}
trap restore_stamped EXIT
for f in "$ROOT_DIR/core/cmd/server/conf/app.yaml" "$ROOT_DIR/agent/cmd/server/conf/app.yaml"; do
    [[ -f "$f" ]] || continue
    grep -qE '^[[:space:]]*version:' "$f" || continue
    sed -i.bak -E "s|^([[:space:]]*version:).*|\1 $VERSION|" "$f"
    STAMPED_FILES+=("$f")
    echo "  $f -> $VERSION (restored on exit)"
done

# ---------------------------------------------------------------------------
# 3. Per-architecture packages
# ---------------------------------------------------------------------------
for ARCH in "${ARCHES[@]}"; do
    step "Packaging linux/$ARCH"

    PKG_NAME="3panel-${VERSION}-linux-${ARCH}"
    STAGE_DIR="$OUT_DIR/stage/$PKG_NAME"
    rm -rf "$STAGE_DIR"
    mkdir -p "$STAGE_DIR"

    (cd "$ROOT_DIR/core" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
        go build -trimpath -ldflags '-s -w' -o "$STAGE_DIR/3panel-core" ./cmd/server)
    (cd "$ROOT_DIR/agent" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
        go build -trimpath -ldflags '-s -w' -o "$STAGE_DIR/3panel-agent" ./cmd/server)

    install -m 0755 "$PACKAGING_DIR/3pctl" "$STAGE_DIR/3pctl"
    install -m 0755 "$PACKAGING_DIR/install.sh" "$STAGE_DIR/install.sh"
    cp -r "$PACKAGING_DIR/initscript" "$STAGE_DIR/initscript"

    # ---- lang -----------------------------------------------------------------
    # The panel prefers the lang/ directory shipped inside the upgrade package
    # (see core/init/geo/lang.go: initLang copies tmpDir/lang instead of
    # downloading when it is present). The in-repo catalog is used first so
    # builds are reproducible and don't depend on an external host being warm.
    step "Assembling language pack"
    if compgen -G "$PACKAGING_DIR/lang/*.sh" >/dev/null; then
        mkdir -p "$STAGE_DIR/lang"
        cp -f "$PACKAGING_DIR/lang/"*.sh "$STAGE_DIR/lang/"
        echo "lang (from repo): $(ls "$STAGE_DIR/lang" | tr '\n' ' ')"
    else
        LANG_TMP="$(mktemp -d)"
        if curl -fsSL --max-time 60 -o "$LANG_TMP/lang.tar.gz" "$RESOURCE_BASE/language/lang.tar.gz"; then
            tar -xzf "$LANG_TMP/lang.tar.gz" -C "$STAGE_DIR"
            # Accept both "lang/" inside the archive and flat "*.sh" entries.
            if [[ ! -d "$STAGE_DIR/lang" ]]; then
                mkdir -p "$STAGE_DIR/lang"
                find "$STAGE_DIR" -maxdepth 1 -name '*.sh' -exec mv {} "$STAGE_DIR/lang/" \;
            fi
            echo "lang (from $RESOURCE_BASE): $(ls "$STAGE_DIR/lang" | tr '\n' ' ')"
        else
            warn "no repo lang catalog and could not fetch $RESOURCE_BASE/language/lang.tar.gz"
            warn "the panel downloads the language pack from ResourceURL at startup, so this is not fatal"
        fi
        rm -rf "$LANG_TMP"
    fi

    # initLang() uses lang/zh.sh as its "language pack installed" sentinel; when
    # it is missing the panel re-downloads the pack on every single startup.
    if [[ -f "$STAGE_DIR/lang/zh.sh" ]]; then
        : # good
    elif [[ -d "$STAGE_DIR/lang" ]]; then
        warn "lang/zh.sh missing — the panel treats the pack as absent and will re-download on every start"
    fi

    # ---- resource: language pack ----------------------------------------------
    # Separate from the upgrade package: the panel fetches
    # {ResourceURL}/language/lang.tar.gz whenever /usr/local/bin/lang is missing,
    # and both 3pctl and install.sh source /usr/local/bin/lang/<lang>.sh.
    # The archive must therefore carry a top-level lang/ directory (the panel
    # extracts it as `tar zxvfC lang.tar.gz /usr/local/bin/`).
    if [[ -d "$STAGE_DIR/lang" ]]; then
        # COPYFILE_DISABLE keeps macOS bsdtar from adding ._* AppleDouble entries.
        COPYFILE_DISABLE=1 tar -czf "$OUT_DIR/lang.tar.gz" -C "$STAGE_DIR" lang
        echo "lang.tar.gz: $(du -h "$OUT_DIR/lang.tar.gz" | cut -f1)  -> /resource/language/lang.tar.gz"
    fi

    # ---- one-line installer ----------------------------------------------------
    # Read by end users as `bash -c "$(curl -sSL <url>)"`, so it must stay
    # reachable without a version in the path. publish-bootstrap.yml uploads it on
    # every change to this file; this copy keeps a release self-contained.
    if [[ -f "$PACKAGING_DIR/quick_start.sh" ]]; then
        cp -f "$PACKAGING_DIR/quick_start.sh" "$OUT_DIR/quick_start.sh"
        chmod 0644 "$OUT_DIR/quick_start.sh"
        echo "quick_start.sh: $(du -h "$OUT_DIR/quick_start.sh" | cut -f1)  -> /package/quick_start.sh"
    else
        warn "packaging/quick_start.sh missing — /package/quick_start.sh not published"
    fi

    # ---- GeoIP -----------------------------------------------------------------
    step "Fetching GeoIP database"
    geoip_ok=0
    if [[ -n "$GEOIP_FILE" ]]; then
        if [[ -f "$GEOIP_FILE" ]]; then
            cp "$GEOIP_FILE" "$STAGE_DIR/GeoIP.mmdb"
            geoip_ok=1
            echo "GeoIP.mmdb: $(du -h "$STAGE_DIR/GeoIP.mmdb" | cut -f1)  <- local $GEOIP_FILE"
        else
            warn "GEOIP_FILE=$GEOIP_FILE not found, falling back to download"
        fi
    fi
    if [[ $geoip_ok -eq 0 ]]; then
        GEOIP_SOURCES=("$RESOURCE_BASE/geo/GeoIP.mmdb")
        if [[ -n "$GEOIP_FALLBACK" ]]; then
            GEOIP_SOURCES+=("$GEOIP_FALLBACK")
        fi
        for src in "${GEOIP_SOURCES[@]}"; do
            if curl -fsSL --max-time 180 -o "$STAGE_DIR/GeoIP.mmdb" "$src"; then
                echo "GeoIP.mmdb: $(du -h "$STAGE_DIR/GeoIP.mmdb" | cut -f1)  <- $src"
                if [[ "$src" != "$RESOURCE_BASE/geo/GeoIP.mmdb" ]]; then
                    warn "came from the upstream fallback — mirror it to $RESOURCE_BASE/geo/GeoIP.mmdb"
                fi
                geoip_ok=1
                break
            fi
            rm -f "$STAGE_DIR/GeoIP.mmdb"
        done
    fi
    if [[ $geoip_ok -eq 0 ]]; then
        rm -f "$STAGE_DIR/GeoIP.mmdb"
        warn "no GeoIP database available — the package will ship without it"
        warn "not fatal: the panel downloads it at startup into <install-dir>/3panel/geo/"
        warn "see docs/UPGRADE-升级通道部署.md § GeoIP for the schema caveat"
    fi

    # ---- archive ---------------------------------------------------------------
    step "Creating archive"
    ARCHIVE="$OUT_DIR/${PKG_NAME}.tar.gz"
    rm -f "$ARCHIVE"
    tar -czf "$ARCHIVE" -C "$OUT_DIR/stage" "$PKG_NAME"
    # The panel verifies <package-url>.sha256 when it is published; publish it.
    (cd "$OUT_DIR" && sha256_of "${PKG_NAME}.tar.gz" > "${PKG_NAME}.tar.gz.sha256")

    echo "built $(du -h "$ARCHIVE" | cut -f1)  $ARCHIVE"
    echo "sha256 $(cat "$ARCHIVE.sha256")"
done

# ---------------------------------------------------------------------------
# 4. Channel indexes
# ---------------------------------------------------------------------------
# "beta" anywhere in the version routes the panel to the beta channel,
# mirroring core/app/service/upgrade.go.
CHANNEL="stable"
if [[ "$VERSION" == *beta* ]]; then
    CHANNEL="beta"
fi

step "Writing channel index for '$CHANNEL'"
INDEX_DIR="$OUT_DIR/package/$CHANNEL"
mkdir -p "$INDEX_DIR"
# IMPORTANT: no trailing newline — the panel does not TrimSpace this value.
printf '%s' "$VERSION" > "$INDEX_DIR/latest"
echo "package/$CHANNEL/latest -> $VERSION"

step "Done. Upload these to ${RESOURCE_BASE%/resource}"
cat <<EOF
  dist/package/$CHANNEL/latest                                -> /package/$CHANNEL/latest
  dist/<package>.tar.gz                                       -> /package/$CHANNEL/$VERSION/release/
  dist/<package>.tar.gz.sha256                                -> /package/$CHANNEL/$VERSION/release/
  <release notes>                                             -> /package/$CHANNEL/$VERSION/release/3panel-$VERSION-release-notes
  dist/lang.tar.gz                                            -> /resource/language/lang.tar.gz
  dist/quick_start.sh                                         -> /package/quick_start.sh
EOF
