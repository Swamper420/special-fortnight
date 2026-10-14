//! Original procedure `0x0040cff4` (61 bytes, `0x0040cff4–0x0040d030`).
//! Evidence: `evidence/0040cff4_fn_0040cff4.md`.

unsafe extern "C" fn default_next(_b: *mut u8, _p2: u32, _p3: i32) -> u8 {
    0
}

/// Target `0x0040cfb4` (`FUN_0040cfb4`), exactly 5 folds.
///
/// ponytail: hook standing in for same-batch `fn_0040cfb4`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_0040CFB4: unsafe extern "C" fn(*mut u8, u32, i32) -> u8 = default_next;

/// Zero cells, `[+8]=-1`, then 5× `cfb4→([+0xc]<<8)|byte→[+0xc]`.
pub unsafe fn fn_0040cff4(param_1: *mut u8) {
    core::ptr::write_unaligned(param_1.wrapping_byte_add(4) as *mut u32, 0);
    core::ptr::write_unaligned(param_1 as *mut u32, 0);
    core::ptr::write_unaligned(param_1.wrapping_byte_add(0x18) as *mut u32, 0);
    core::ptr::write_unaligned(param_1.wrapping_byte_add(0xc) as *mut u32, 0);
    core::ptr::write_unaligned(param_1.wrapping_byte_add(8) as *mut u32, 0xffffffff);
    // ponytail: EDX/ECX lanes carried explicitly; ECX for call N+1 is the
    // shifted stored code from iteration N (recomputed from `[+0xc]`).
    let mut edx: u32 = 0;
    let mut ecx: u32 = 0;
    let mut i: i32 = 0;
    loop {
        let b = HOOK_0040CFB4(param_1, edx, ecx as i32);
        let shifted: u32 = core::ptr::read_unaligned(
            param_1.wrapping_byte_add(0xc) as *const u32,
        )
        .wrapping_shl(8);
        edx = (b as u32) | shifted;
        ecx = shifted;
        i += 1;
        core::ptr::write_unaligned(param_1.wrapping_byte_add(0xc) as *mut u32, edx);
        if i >= 5 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040CFB4, fn_0040cff4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);
    static FEED: [u8; 5] = [0x01, 0x02, 0x03, 0x04, 0x05];

    unsafe extern "C" fn next(_b: *mut u8, _p2: u32, _p3: i32) -> u8 {
        let i = N.fetch_add(1, Ordering::SeqCst);
        FEED[i]
    }

    #[test]
    fn folds_five_bytes() {
        unsafe { HOOK_0040CFB4 = next };
        N.store(0, Ordering::SeqCst);
        let mut rec = [0u8; 0x20];
        unsafe { fn_0040cff4(rec.as_mut_ptr()) };
        unsafe {
            assert_eq!(
                core::ptr::read_unaligned(rec.as_mut_ptr().wrapping_byte_add(8) as *const u32),
                0xffffffff
            );
            assert_eq!(
                core::ptr::read_unaligned(rec.as_mut_ptr().wrapping_byte_add(0xc) as *const u32),
                0x0102_0304u32.wrapping_shl(8) | 0x05
            );
        }
        assert_eq!(N.load(Ordering::SeqCst), 5);
    }
}
