//! Original procedure `0x00402b9c` (66 bytes, `0x00402b9c–0x00402bdd`).
//! Evidence: `evidence/00402b9c_fn_00402b9c.md`.

/// Flag byte observed at `0x00413a22`: zero forces the fill lane, nonzero
/// fills only when the lane word low nibble is zero.
///
/// ponytail: absolute-address cell modeled as mutable static, upgrade to real
/// image-relative import once data layout proven.
pub static mut FLAG_00413a22: u8 = 0;

/// Source lanes observed at `0x0041205e`: 55 `u16` words at stride `0x20`.
///
/// ponytail: stride-32 multi-lane array not host-representable as `[u16; 55]`;
/// flat byte window keeps 1:1 layout, word read at `lane * 0x20`.
pub static mut RAW_0041205e: [u8; 55 * 0x20] = [0; 55 * 0x20];

/// Dest bytes observed at `0x004138dc`, filled over `[cursor, word >> 3)`.
///
/// ponytail: 8192-entry ceiling from `u16 >> 3` max, shrink once dest extent
/// proven.
pub static mut DEST_004138dc: [u8; 8192] = [0; 8192];

/// Fill `DEST_004138dc` from the stride-`0x20` word lanes at `0x0041205e`.
///
/// 55 lanes; lane `i` fills `[cursor, word >> 3)` with `(i * 4) as u8` and
/// sets cursor to `word >> 3` (cursor can retreat). Lanes with nonzero low
/// nibble are skipped unless the flag is zero.
pub unsafe fn fn_00402b9c() {
    let mut eax: u32 = 0;
    let mut esi: u32 = 0;
    let mut edx: usize = 0;
    loop {
        if FLAG_00413a22 == 0 || (RAW_0041205e[edx] & 0xf) == 0 {
            let word = (RAW_0041205e[edx] as u32) | ((RAW_0041205e[edx + 1] as u32) << 8);
            let edi = word >> 3;
            let mut ecx = esi;
            ecx = ecx.wrapping_add(ecx);
            ecx = ecx.wrapping_add(ecx);
            let cl = ecx as u8;
            while eax < edi {
                DEST_004138dc[eax as usize] = cl;
                eax = eax.wrapping_add(1);
            }
            eax = edi;
        }
        esi = esi.wrapping_add(1);
        edx = edx.wrapping_add(0x20);
        if esi == 0x37 {
            break;
        }
    }
}

/// Test-only serialization for tests sharing FLAG/RAW/DEST globals.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::{DEST_004138dc, FLAG_00413a22, RAW_0041205e, fn_00402b9c};

    unsafe fn set_lane(lane: usize, word: u16) {
        RAW_0041205e[lane * 0x20] = word as u8;
        RAW_0041205e[lane * 0x20 + 1] = (word >> 8) as u8;
    }

    #[test]
    fn fill_skip_and_cursor_retreat() {
        let _guard = super::TEST_LOCK.lock().unwrap();
        unsafe {
            RAW_0041205e = [0; 55 * 0x20];
            DEST_004138dc = [0xFF; 8192];
            FLAG_00413a22 = 0;
            set_lane(0, 0x28); // target 5, DEST[0..5] = 0*4 = 0
            set_lane(1, 0x10); // target 2 < cursor 5: retreat, no writes
            set_lane(2, 0x20); // target 4, DEST[2..4] = 2*4 = 8
            for lane in 3..55 {
                set_lane(lane, 0x20); // target 4 == cursor: no writes
            }
            fn_00402b9c();
            assert_eq!(&DEST_004138dc[0..2], &[0, 0]);
            assert_eq!(&DEST_004138dc[2..4], &[8, 8]);
            assert_eq!(DEST_004138dc[4], 0);
            assert_eq!(DEST_004138dc[5], 0xFF);
            // Flag-gated lane: low nibble set skips, zero fills.
            DEST_004138dc = [0xFF; 8192];
            RAW_0041205e = [0; 55 * 0x20];
            FLAG_00413a22 = 1;
            set_lane(0, 0x21); // nibble 1: skip
            set_lane(1, 0x20); // nibble 0: DEST[0..4] = 1*4 = 4
            for lane in 2..55 {
                set_lane(lane, 0x20);
            }
            fn_00402b9c();
            assert_eq!(&DEST_004138dc[0..4], &[4, 4, 4, 4]);
            assert_eq!(DEST_004138dc[4], 0xFF);
        }
    }
}
