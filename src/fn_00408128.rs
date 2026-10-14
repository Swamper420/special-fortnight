//! Original procedure `0x00408128` (57 bytes, `0x00408128–0x00408160`).
//! Evidence: `evidence/00408128_fn_00408128.md`.

use crate::fn_00402fbc::fn_00402fbc;

unsafe extern "C" fn default_len(_s: *mut u16) -> u32 {
    0
}

/// Length callee `0x004080dc` (`FUN_004080dc`), observed `(short *) -> uint`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_004080dc` once it exists.
pub static mut HOOK_004080DC: unsafe extern "C" fn(*mut u16) -> u32 = default_len;

/// `n=min(len(src),max); copy(src,dst,n*2); dst[n]=0; return dst`.
/// `param_1` (dst) arrives in EAX, `param_2` (src) in EDX, `param_3` (max)
/// in ECX per Ghidra `__register` observation.
pub unsafe fn fn_00408128(param_1: *mut u16, param_2: *mut u16, param_3: u32) -> *mut u16 {
    let len = HOOK_004080DC(param_2);
    let mut n = len;
    if param_3 < n {
        n = param_3;
    }
    fn_00402fbc(param_2 as *mut u8, param_1 as *mut u8, n.wrapping_mul(2));
    core::ptr::write_unaligned(param_1.wrapping_add(n as usize), 0);
    param_1
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004080DC, fn_00408128};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LEN_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn scan_len(s: *mut u16) -> u32 {
        LEN_CALLS.fetch_add(1, Ordering::SeqCst);
        let mut n: u32 = 0;
        while core::ptr::read_unaligned(s.wrapping_add(n as usize)) != 0 {
            n = n.wrapping_add(1);
        }
        n
    }

    #[test]
    fn copy_min_len_then_nul() {
        unsafe {
            HOOK_004080DC = scan_len;
        }
        LEN_CALLS.store(0, Ordering::SeqCst);
        // Full copy: src len 3 < max 8.
        let mut src = [0x41u16, 0x42, 0x43, 0];
        let mut dst = [0x5Au16; 8];
        let r = unsafe { fn_00408128(dst.as_mut_ptr(), src.as_mut_ptr(), 8) };
        assert_eq!(r, dst.as_mut_ptr());
        assert_eq!(&dst[..5], &[0x41, 0x42, 0x43, 0, 0x5A]);
        // Truncation: max 2 < len 3.
        let mut dst2 = [0x5Au16; 8];
        unsafe { fn_00408128(dst2.as_mut_ptr(), src.as_mut_ptr(), 2) };
        assert_eq!(&dst2[..4], &[0x41, 0x42, 0, 0x5A]);
        // max 0: no copy, dst[0] still NUL-stored.
        let mut dst3 = [0x5Au16; 8];
        unsafe { fn_00408128(dst3.as_mut_ptr(), src.as_mut_ptr(), 0) };
        assert_eq!(&dst3[..2], &[0, 0x5A]);
        assert_eq!(LEN_CALLS.load(Ordering::SeqCst), 3);
    }
}
