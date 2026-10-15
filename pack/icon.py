#!/usr/bin/env python3
"""Extract the original app icon (RT_GROUP_ICON) from dsj3v171.exe.

Writes <outdir>/dsj3.ico (all 4 images) and <outdir>/dsj3-32.png
(largest: 32x32 8bpp — small but authentic; see ceiling below).
Stdlib PE parsing + Pillow for ICO/PNG. Scratch knowledge lives in
analysis/; this ships because `pack/build.sh` needs it offline.

Ceiling: the original icon tops out at 32x32. Upscaling would blur,
so the AppImage icon stays 32px.
"""
import struct
import sys
from pathlib import Path


def parse_pe_rsrc(img):
    pe = struct.unpack_from("<I", img, 0x3C)[0]
    nsec = struct.unpack_from("<H", img, pe + 6)[0]
    opt = pe + 24
    optsz = struct.unpack_from("<H", img, pe + 20)[0]
    stab = opt + optsz
    for i in range(nsec):
        s = stab + i * 40
        if img[s:s + 8].startswith(b".rsrc"):
            raw = struct.unpack_from("<I", img, s + 20)[0]
            rva = struct.unpack_from("<I", img, s + 12)[0]
            return raw, rva
    raise SystemExit("no .rsrc section")


def main():
    exe = Path(sys.argv[1] if len(sys.argv) > 1 else "dsj3v171.exe")
    out = Path(sys.argv[2] if len(sys.argv) > 2 else "dist/icon")
    img = exe.read_bytes()
    roff, srva = parse_pe_rsrc(img)

    def u32(o):
        return struct.unpack_from("<I", img, roff + o)[0]

    def u16(o):
        return struct.unpack_from("<H", img, roff + o)[0]

    def entries(d):
        n = u16(d + 12) + u16(d + 14)
        return [(u32(d + 16 + i * 8), u32(d + 16 + i * 8 + 4)) for i in range(n)]

    def data(o):
        rva, size = u32(o), u32(o + 4)
        fo = rva - srva + roff
        return img[fo:fo + size]

    groups = []
    for name, off in entries(0):
        if name == 14:  # RT_GROUP_ICON
            for nid, o2 in entries(off & 0x7FFFFFFF):
                for _lang, o3 in entries(o2 & 0x7FFFFFFF):
                    groups.append(data(o3 & 0x7FFFFFFF))
    if not groups:
        raise SystemExit("no icon group found")
    grp = max(groups, key=len)
    rsv, typ, count = struct.unpack_from("<HHH", grp, 0)
    assert (rsv, typ) == (0, 1), (rsv, typ)
    metas = []
    for k in range(count):
        w, h, c, _rs, _pl, bp, size, iid = struct.unpack_from("<BBBBHHIH", grp, 6 + k * 14)
        metas.append((w or 256, h or 256, bp, size, iid))

    # Raw icon images live under RT_ICON (type 3) by id.
    icons = {}
    for name, off in entries(0):
        if name == 3:
            for iid, o2 in entries(off & 0x7FFFFFFF):
                for _lang, o3 in entries(o2 & 0x7FFFFFFF):
                    icons[iid] = data(o3 & 0x7FFFFFFF)

    # Assemble a real .ico: header + dir + image blobs.
    ico = struct.pack("<HHH", 0, 1, len(metas))
    blob_off = 6 + 16 * len(metas)
    blobs = []
    for w, h, bp, _size, iid in [(m[0], m[1], m[2], m[3], m[4]) for m in metas]:
        raw = icons[iid]
        ico += struct.pack("<BBBBHHII", w if w < 256 else 0, h if h < 256 else 0,
                           0, 0, 1, bp, len(raw), blob_off)
        blob_off += len(raw)
        blobs.append(raw)
    ico = ico + b"".join(blobs)

    out.mkdir(parents=True, exist_ok=True)
    (out / "dsj3.ico").write_bytes(ico)
    try:
        from PIL import Image
    except ImportError:
        print("no Pillow: wrote dsj3.ico only (convert it to PNG yourself)")
        return
    import io
    im = Image.open(io.BytesIO(ico))
    im.save(out / "dsj3-32.png")
    print(f"wrote {out/'dsj3.ico'} ({len(metas)} images) and {out/'dsj3-32.png'} {im.size}")


if __name__ == "__main__":
    main()
