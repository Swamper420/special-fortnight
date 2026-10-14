//! Original procedure `0x0040d034` (96 bytes, `0x0040d034–0x0040d093`).
//! Evidence: `evidence/0040d034_fn_0040d034.md`.

/// Range-decode `param_2` bits; `extraout_ECX` dead (dropped).
/// All math `wrapping_*` like x86.
pub unsafe fn fn_0040d034(param_1: *mut u8, param_2: u32, param_3: i32) -> u32 {
    let mut out: u32 = 0;
    let mut range: u32 =
        core::ptr::read_unaligned(param_1.wrapping_byte_add(8) as *const u32);
    let mut code: u32 =
        core::ptr::read_unaligned(param_1.wrapping_byte_add(0xc) as *const u32);
    let mut carry: u32 = param_2;
    let mut n: u32 = param_2;
    while n != 0 {
        range = range.wrapping_shr(1);
        out = out.wrapping_add(out);
        if range <= code {
            code = code.wrapping_sub(range);
            out |= 1;
        }
        if range < 0x1000000 {
            range = range.wrapping_shl(8);
            let b = crate::fn_0040cfb4::fn_0040cfb4(param_1, carry, param_3);
            carry = ((code.wrapping_shl(8)) | (b as u32)) ;
            code = carry;
        }
        n = n.wrapping_sub(1);
    }
    core::ptr::write_unaligned(param_1.wrapping_byte_add(8) as *mut u32, range);
    core::ptr::write_unaligned(param_1.wrapping_byte_add(0xc) as *mut u32, code);
    out
}

#[cfg(test)]
mod tests {
    use super::fn_0040d034;

    static FEED: [u8; 1] = [0x00];

    // Renormalize byte served through the real `fn_0040cfb4`'s buffered
    // lane (`cur != end`, no refill). `cur` is one `usize` at `+0`; the
    // `+4` lane is left alone (on 64-bit host an 8 B write there would
    // clobber `cur`'s high half — overlap parity holds on i686 only).
    // `end` (`+4`, 8 B host read) = `feed_hi ++ range` differs from `cur`.
    fn state_with_byte(range: u32, code: u32) -> ([u8; 0x20], *const u8) {
        let mut rec = [0u8; 0x20];
        let base = rec.as_mut_ptr();
        unsafe {
            core::ptr::write_unaligned(base as *mut usize, FEED.as_ptr() as usize);
            core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, range);
            core::ptr::write_unaligned(base.wrapping_byte_add(0xc) as *mut u32, code);
        }
        (rec, FEED.as_ptr())
    }

    #[test]
    fn zero_and_renorm_lanes() {
        // Zero-count: stores through, no call.
        let (mut rec, _) = state_with_byte(0x77, 0x88);
        unsafe {
            assert_eq!(fn_0040d034(rec.as_mut_ptr(), 0, 0), 0);
            assert_eq!(
                core::ptr::read_unaligned(rec.as_mut_ptr().wrapping_byte_add(8) as *const u32),
                0x77
            );
            assert_eq!(
                core::ptr::read_unaligned(rec.as_mut_ptr().wrapping_byte_add(0xc) as *const u32),
                0x88
            );
        }
        // One bit with tiny range: range>>=1, 0<=code sets bit, renorm
        // pulls `0x00` through the real `cfb4` → code `0x400`.
        let (mut rec, _) = state_with_byte(2, 5);
        unsafe {
            let r = fn_0040d034(rec.as_mut_ptr(), 1, 0);
            assert_eq!(r, 1);
            assert_eq!(
                core::ptr::read_unaligned(rec.as_mut_ptr().wrapping_byte_add(8) as *const u32),
                0x100
            );
            assert_eq!(
                core::ptr::read_unaligned(rec.as_mut_ptr().wrapping_byte_add(0xc) as *const u32),
                0x400
            );
        }
    }
}
