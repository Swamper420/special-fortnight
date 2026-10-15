#!/bin/sh
# Build local release artifacts: Windows .exe + Linux AppImage.
# Needs: cargo (i686 musl + windows-gnu targets), python3 + Pillow,
# network once for appimagetool (cached under pack/cache).
# The original dsj3v171.exe is read, never bundled (not redistributable).
#
#   sh pack/build.sh            # both artifacts -> dist/
#   sh pack/build.sh --exe-only # skip AppImage
#   sh pack/build.sh --img-only # skip .exe
#   APPIMAGETOOL=/path/to/appimagetool sh pack/build.sh  # offline reuse
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DIST=$ROOT/dist
CACHE=$ROOT/pack/cache
APPIMAGETOOL_URL=${APPIMAGETOOL_URL:-https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage}
EXE_ONLY=0; IMG_ONLY=0
for a in "$@"; do
    case $a in
        --exe-only) EXE_ONLY=1;;
        --img-only) IMG_ONLY=1;;
        -h|--help) sed -n '2,12p' "$0"; exit 0;;
        *) echo "unknown flag: $a" >&2; exit 1;;
    esac
done
need() { command -v "$1" >/dev/null 2>&1 || { echo "need $1" >&2; exit 1; }; }
export PATH="$HOME/.cargo/bin:$PATH"
need cargo; need python3

if [ "$IMG_ONLY" -eq 0 ]; then
    echo "== windows .exe"
    cargo build --release --target i686-pc-windows-gnu --manifest-path "$ROOT/Cargo.toml"
    mkdir -p "$DIST"
    cp "$ROOT/target/i686-pc-windows-gnu/release/dsj3.exe" "$DIST/dsj3-windows-i686.exe"
fi

if [ "$EXE_ONLY" -eq 0 ]; then
    echo "== linux binary"
    cargo build --release --target i686-unknown-linux-musl --manifest-path "$ROOT/Cargo.toml"
    echo "== icon"
    python3 "$ROOT/pack/icon.py" "$ROOT/dsj3v171.exe" "$DIST/icon"
    echo "== AppDir"
    APPDIR=$DIST/AppDir
    rm -rf "$APPDIR"
    mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/icons/hicolor/32x32/apps" "$APPDIR/usr/share/applications"
    cp "$ROOT/target/i686-unknown-linux-musl/release/dsj3" "$APPDIR/usr/bin/dsj3"
    ln -sf usr/bin/dsj3 "$APPDIR/dsj3"
    cp "$ROOT/pack/AppRun.sh" "$APPDIR/AppRun"
    chmod +x "$APPDIR/AppRun"
    cp "$ROOT/pack/dsj3.desktop" "$APPDIR/dsj3.desktop"
    cp "$ROOT/pack/dsj3.desktop" "$APPDIR/usr/share/applications/dsj3.desktop"
    cp "$DIST/icon/dsj3-32.png" "$APPDIR/dsj3.png"
    cp "$DIST/icon/dsj3-32.png" "$APPDIR/usr/share/icons/hicolor/32x32/apps/dsj3.png"
    echo "== appimagetool"
    mkdir -p "$CACHE"
    AIT=${APPIMAGETOOL:-$CACHE/appimagetool.AppImage}
    if [ ! -x "$AIT" ]; then
        echo "fetch $APPIMAGETOOL_URL"
        curl -L -o "$AIT" "$APPIMAGETOOL_URL"
        chmod +x "$AIT"
    fi
    # Needs FUSE to self-mount; without it, run the extracted copy.
    if ! "$AIT" --version >/dev/null 2>&1; then
        if [ ! -x "$CACHE/appimagetool/AppRun" ]; then
            (cd "$CACHE" && "$AIT" --appimage-extract >/dev/null && mv squashfs-root appimagetool)
        fi
        AIT=$CACHE/appimagetool/AppRun
    fi
    "$AIT" --version | tee "$DIST/BUILD_INFO"
    (cd "$DIST" && ARCH=i686 "$AIT" AppDir DSJ3-Linux-i686.AppImage)
fi

echo "== sums"
(cd "$DIST" && sha256sum dsj3-windows-i686.exe DSJ3-Linux-i686.AppImage > SHA256SUMS 2>/dev/null || true)
ls -la "$DIST"
