//! Original procedure `0x00402be0` (293 bytes, `0x402be0–0x402d04`).
//! Evidence: `evidence/00402be0_fn_00402be0.md`.

use crate::fn_00402b9c::fn_00402b9c;

/// Record window `[0x41205c, 0x4124bc)`: 55 records, stride `0x20`.
/// Per record (rel base `B`): `+0x1c` u32 slot, `+0x14`/`+0x04` base-link,
/// `+0x0c` zero, `+0x08` one, `+0x01` mask byte, `+0x18`/`+0x1a` derived
/// words, `+0x02` source word.
///
/// ponytail: overlaps sibling `crate::fn_00402b9c::RAW_0041205e` at +2;
/// local window keeps 1:1 offsets, see evidence (init never writes the
/// lane-base words the sibling reads).
pub static mut TABLE_0041205c: [u8; 55 * 0x20] = [0; 55 * 0x20];

/// Self-pointer heads observed at `0x00413a24` / `0x00413a28` (u32 image
/// addresses).
///
/// ponytail: absolute-address cells modeled as mutable statics, upgrade to
/// real image-relative imports once data layout proven.
pub static mut HEAD_00413a24: u32 = 0;
pub static mut HEAD_00413a28: u32 = 0;

/// Pair table observed at `0x00413ac4`: `0x400` self-linked 8-byte pairs,
/// stored as `0x800` u32 image addresses.
///
/// ponytail: absolute-address cells modeled as mutable statics, upgrade to
/// real image-relative imports once data layout proven.
pub static mut TABLE_00413ac4: [u32; 0x800] = [0; 0x800];

/// Self-pointer heads observed at `0x00415ac8` / `0x00415acc`.
///
/// ponytail: absolute-address cells modeled as mutable statics, upgrade to
/// real image-relative imports once data layout proven.
pub static mut HEAD_00415ac8: u32 = 0;
pub static mut HEAD_00415acc: u32 = 0;

unsafe fn read_u16(base: usize, off: usize) -> u16 {
    let p = core::ptr::addr_of!(TABLE_0041205c[base + off]) as *const u16;
    core::ptr::read_unaligned(p)
}

unsafe fn write_u16(base: usize, off: usize, v: u16) {
    let p = core::ptr::addr_of_mut!(TABLE_0041205c[base + off]) as *mut u16;
    core::ptr::write_unaligned(p, v);
}

unsafe fn read_u32(base: usize, off: usize) -> u32 {
    let p = core::ptr::addr_of!(TABLE_0041205c[base + off]) as *const u32;
    core::ptr::read_unaligned(p)
}

unsafe fn write_u32(base: usize, off: usize, v: u32) {
    let p = core::ptr::addr_of_mut!(TABLE_0041205c[base + off]) as *mut u32;
    core::ptr::write_unaligned(p, v);
}

/// Init 55 stride-`0x20` records from lane source words, then
/// `fn_00402b9c()`, then self-linked list heads/tables.
///
/// ponytail: direct call to done `fn_00402b9c` (no hook).
pub unsafe fn fn_00402be0() {
    let mut base: usize = 0;
    let mut remaining: u32 = 0x37;
    loop {
        if read_u32(base, 0x1c) == 0 {
            write_u32(base, 0x1c, 0x40148c);
        }
        let link = (0x0041205c as u32).wrapping_add(base as u32);
        write_u32(base, 0x14, link);
        write_u32(base, 0x04, link);
        write_u32(base, 0x0c, 0);
        write_u32(base, 0x08, 1);
        let word = read_u16(base, 0x02) as u32;
        let mut u = (((word.wrapping_mul(0xc)).wrapping_add(0xef)) & 0xffffff00)
            .wrapping_add(0x30);
        if u < 0xb30 {
            u = 0xb30;
        }
        u = u.wrapping_add(0x4d0) >> 0xd;
        if u > 7 {
            u = 7;
        }
        TABLE_0041205c[base + 0x01] = 0xffu8.wrapping_shl(u);
        write_u16(
            base,
            0x18,
            ((u << 0xd) as u16).wrapping_add(0xb30),
        );
        let mut t = (((word.wrapping_mul(0x30)).wrapping_add(0xef)) & 0xffffff00)
            .wrapping_add(0x30);
        if t < 0x7330 {
            t = 0x7330;
        }
        if t > 0xff30 {
            t = 0xff30;
        }
        let q = t.wrapping_sub(0x20) / word;
        let p = (q as u16).wrapping_mul(word as u16);
        write_u16(
            base,
            0x1a,
            (p.wrapping_add(0xef) & 0xff00).wrapping_add(0x30),
        );
        base = base.wrapping_add(0x20);
        remaining = remaining.wrapping_sub(1);
        if remaining == 0 {
            break;
        }
    }
    fn_00402b9c();
    HEAD_00413a24 = 0x413a24;
    HEAD_00413a28 = 0x413a24;
    let mut i: usize = 0;
    while i < 0x800 {
        TABLE_00413ac4[i] = (0x00413ac4 as u32).wrapping_add((i as u32).wrapping_mul(4));
        i = i.wrapping_add(1);
    }
    HEAD_00415ac8 = 0x415ac8;
    HEAD_00415acc = 0x415ac8;
}

#[cfg(test)]
mod tests {
    use super::{
        HEAD_00413a24, HEAD_00413a28, HEAD_00415ac8, HEAD_00415acc, TABLE_0041205c,
        TABLE_00413ac4, fn_00402be0,
    };

    unsafe fn set_word(lane: usize, w: u16) {
        TABLE_0041205c[lane * 0x20 + 0x02] = w as u8;
        TABLE_0041205c[lane * 0x20 + 0x03] = (w >> 8) as u8;
    }

    unsafe fn get_word(lane: usize, off: usize) -> u16 {
        (TABLE_0041205c[lane * 0x20 + off] as u16)
            | ((TABLE_0041205c[lane * 0x20 + off + 1] as u16) << 8)
    }

    unsafe fn get_u32(lane: usize, off: usize) -> u32 {
        (TABLE_0041205c[lane * 0x20 + off] as u32)
            | ((TABLE_0041205c[lane * 0x20 + off + 1] as u32) << 8)
            | ((TABLE_0041205c[lane * 0x20 + off + 2] as u32) << 16)
            | ((TABLE_0041205c[lane * 0x20 + off + 3] as u32) << 24)
    }

    #[test]
    fn init_records_and_lists() {
        // fn_00402be0 calls done fn_00402b9c, which fills its own DEST
        // global: hold the owner lock and restore DEST after.
        let _owner = crate::fn_00402b9c::TEST_LOCK.lock().unwrap();
        let saved_dest = unsafe { crate::fn_00402b9c::DEST_004138dc };
        unsafe {
            TABLE_0041205c = [0; 55 * 0x20];
            TABLE_00413ac4 = [0; 0x800];
            // Slot lanes: record 0 defaults, record 1 preserves.
            set_word(0, 0x100);
            set_word(1, 0xffff);
            for lane in 2..55 {
                set_word(lane, 0x100);
            }
            // Slot cells at +0x1c: record 1 preset nonzero.
            TABLE_0041205c[1 * 0x20 + 0x1c] = 0x78;
            TABLE_0041205c[1 * 0x20 + 0x1d] = 0x56;
            TABLE_0041205c[1 * 0x20 + 0x1e] = 0x34;
            TABLE_0041205c[1 * 0x20 + 0x1f] = 0x12;
            fn_00402be0();

            // word=0x100: u=0xc30, n=0, mask=0xff, w1=0xb30, w2=0x7330.
            assert_eq!(get_u32(0, 0x1c), 0x40148c);
            assert_eq!(get_u32(0, 0x14), 0x41205c);
            assert_eq!(get_u32(0, 0x04), 0x41205c);
            assert_eq!(get_u32(0, 0x0c), 0);
            assert_eq!(get_u32(0, 0x08), 1);
            assert_eq!(TABLE_0041205c[0x01], 0xff);
            assert_eq!(get_word(0, 0x18), 0xb30);
            assert_eq!(get_word(0, 0x1a), 0x7330);
            // word=0xffff: top clamps, mask=0x80, w1=0xeb30, w2=0x30.
            assert_eq!(get_u32(1, 0x1c), 0x12345678);
            assert_eq!(TABLE_0041205c[1 * 0x20 + 0x01], 0x80);
            assert_eq!(get_word(1, 0x18), 0xeb30);
            assert_eq!(get_word(1, 0x1a), 0x30);
            assert_eq!(get_u32(1, 0x14), 0x41207c);
            // Last record base linkage.
            assert_eq!(get_u32(54, 0x14), 0x41205c + 54 * 0x20);
            assert_eq!(get_u32(54, 0x1c), 0x40148c);

            // List heads and pair table.
            assert_eq!(HEAD_00413a24, 0x413a24);
            assert_eq!(HEAD_00413a28, 0x413a24);
            assert_eq!(TABLE_00413ac4[0], 0x413ac4);
            assert_eq!(TABLE_00413ac4[1], 0x413ac8);
            assert_eq!(TABLE_00413ac4[0x7ff], 0x413ac4 + 0x1ffc);
            assert_eq!(HEAD_00415ac8, 0x415ac8);
            assert_eq!(HEAD_00415acc, 0x415ac8);

            crate::fn_00402b9c::DEST_004138dc = saved_dest;
        }
    }
}
