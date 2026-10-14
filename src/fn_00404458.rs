//! Original procedure `0x00404458` (105 bytes, `0x00404458–0x004044c1`).
//! Evidence: `evidence/00404458_fn_00404458.md`.

/// Cell observed as `dword ptr [0x00412000]` (signed decimal input).
///
/// ponytail: absolute-address cell as hermetic own-module static, unify
/// with writer modules in `data.rs` once data layout proven.
pub static mut CELL_00412000: i32 = 0;

/// Cell observed as `dword ptr [0x00412004]` (unsigned hex input).
///
/// ponytail: absolute-address cell as hermetic own-module static, unify
/// with writer modules in `data.rs` once data layout proven.
pub static mut CELL_00412004: u32 = 0;

/// Buffer observed at `0x00412778` (`Runtime error     at 00000000`).
///
/// ponytail: absolute-address bytes as hermetic own-module static, unify
/// in `data.rs` once data layout proven.
pub static mut BUF_00412778: [u8; 29] = *b"Runtime error     at 00000000";

/// Nibble table bytes observed at `0x00404443` (`0123456789ABCDEF`).
///
/// ponytail: code-range bytes as hermetic own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut TABLE_00404443: [u8; 16] = *b"0123456789ABCDEF";

/// Pointer cell observed as `dword ptr [0x00412798]`, points at the nibble
/// table. Provision before calling (tests set it to `TABLE_00404443`).
///
/// ponytail: absolute-address cell as hermetic own-module static (null
/// until provisioned), upgrade to real image-relative import once data
/// layout proven.
pub static mut PTR_00412798: *const u8 = core::ptr::null();

/// Format `CELL_00412000` signed-decimal into `BUF[0x10]` descending,
/// then `CELL_00412004` unsigned-hex into `BUF[0x1c]` descending.
/// Both loops are bottom-tested (≥1 digit). No register lanes.
pub unsafe fn fn_00404458() {
    // Loop 1: CDQ+IDIV (signed). Remainder takes the dividend's sign;
    // ADD DL,0x30 is an 8-bit wrap.
    let mut idx: u8 = 0x10;
    let mut v: i32 = CELL_00412000;
    loop {
        let digit = (v % 10) as u8;
        BUF_00412778[idx as usize] = digit.wrapping_add(b'0');
        v /= 10;
        idx = idx.wrapping_sub(1);
        if v == 0 {
            break;
        }
    }
    // Loop 2: AND-nibble table fetch through [0x00412798] (double deref),
    // XOR EDX,EDX+DIV (unsigned). INC/[-1] cancel: table[(v>>s)&0xf].
    let mut idx: u8 = 0x1c;
    let mut v: u32 = CELL_00412004;
    loop {
        let table: *const u8 = PTR_00412798;
        let ch: u8 = *table.wrapping_add((v & 0xf) as usize);
        BUF_00412778[idx as usize] = ch;
        v /= 0x10;
        idx = idx.wrapping_sub(1);
        if v == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BUF_00412778, CELL_00412000, CELL_00412004, PTR_00412798, TABLE_00404443, fn_00404458};

    fn reset() {
        unsafe {
            BUF_00412778 = *b"Runtime error     at 00000000";
            PTR_00412798 = TABLE_00404443.as_ptr();
        }
    }

    #[test]
    fn decimal_and_hex_placement() {
        reset();
        unsafe {
            // 4-digit value: fills 13..17, leaves "Runtime error" intact
            // (a 5-digit value would faithfully clobber [12], as the
            // original's downward store from 0x10 does).
            CELL_00412000 = 1234;
            CELL_00412004 = 0x1a2b3c;
            fn_00404458();
            assert_eq!(&BUF_00412778[0..13], b"Runtime error");
            assert_eq!(&BUF_00412778[13..17], b"1234");
            assert_eq!(&BUF_00412778[18..20], b"at");
            assert_eq!(&BUF_00412778[23..29], b"1A2B3C");
        }

        // Zero inputs still emit one digit each (do-while).
        reset();
        unsafe {
            CELL_00412000 = 0;
            CELL_00412004 = 0;
            fn_00404458();
            assert_eq!(BUF_00412778[16], b'0');
            assert_eq!(BUF_00412778[28], b'0');
            assert_eq!(&BUF_00412778[0..13], b"Runtime error");
        }
    }
}
