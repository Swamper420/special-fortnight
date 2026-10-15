#!/bin/sh
# AppRun: the image (dsj3v171.exe) lives beside the AppImage file, not in
# the read-only mount; the binary resolves it via $APPIMAGE (see
# install.rs locate_image). Args pass straight through.
exec "$APPDIR/dsj3" "$@"
