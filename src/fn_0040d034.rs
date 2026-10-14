//! Original procedure `0x0040d034` (96 bytes, `0x40d034–0x40d093`).
//! Evidence: `evidence/0040d034_fn_0040d034.md`.

unsafe extern "C" fn default_next(_b: *mut u8, _p2: u32, _p3: i32) -> u8 {
    0
}

/// Target `0x40cfb4` (`FUN_0040cfb4`), renormalize lane.
///
/// ponytail: hook standing in for same-batch `fn_0040cfb4`.
pub static mut HOOK_0040CFB4: unsafe extern "C" fn(*mut u8, u32, i32) -> u8 = default_next;

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
            let b = HOOK_0040CFB4(param_1, carry, param_3);
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
    use super::{HOOK_0040CFB4, fn_0040d034};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn next(_b: *mut u8, _p2: u32, _p3: i32) -> u8 {
        HITS.fetch_add(1, Ordering::SeqCst);
        0x00
    }

    #[test]
    fn zero_and_renorm_lanes() {
        unsafe { HOOK_0040CFB4 = next };
        // Zero-count: stores through, no call.
        HITS.store(0, Ordering::SeqCst);
        let mut rec = [0u8; 0x10];
        unsafe {
            core::ptr::write_unaligned(rec.as_mut_ptr().wrapping_byte_add(8) as *mut u32, 0x77);
            core::ptr::write_unaligned(rec.as_mut_ptr().wrapping_byte_add(0xc) as *mut u32, 0x88);
            assert_eq!(fn_0040d034(rec.as_mut_ptr(), 0, 0), 0);
        }
        assert_eq!(HITS.load(Ordering::SeqCst), 0);
        // One bit with tiny range: range>>=1, 0<=code sets bit, renorm calls once.
        HITS.store(0, Ordering::SeqCst);
        unsafe {
            core::ptr::write_unaligned(rec.as_mut_ptr().wrapping_byte_add(8) as *mut u32, 2);
            core::ptr::write_unaligned(rec.as_mut_ptr().wrapping_byte_add(0xc) as *mut u32, 5);
            let r = fn_0040d034(rec.as_mut_ptr(), 1, 0);
            assert_eq!(r, 1);
            assert_eq!(HITS.load(Ordering::SeqCst), 1);
        }
    }
}
