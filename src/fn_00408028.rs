//! Original procedure `0x00408028` (41 bytes, `0x00408028–0x00408050`).
//! Evidence: `evidence/00408028_fn_00408028.md`.

unsafe extern "C" fn default_scan(_base: *mut u8, _s: *mut u8) -> i32 {
    0
}

/// Scanner `0x00407f4c` (`FUN_00407f4c`), called with `(&DAT_00408060,
/// param_1)`; its EAX residue is taken as `i32` per this caller's
/// observation (the callee's own dossier reports `void`; see evidence).
///
/// ponytail: hook standing in for batch-mate `fn_00407f4c`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_00407F4C: unsafe extern "C" fn(*mut u8, *mut u8) -> i32 =
    default_scan;

/// Emitter `0x0040525c` (`FUN_0040525c`), called with
/// `(param_1, res+1, 0x7fffffff, param_2)`: direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, i32, i32, *mut u8)`).

/// Cell observed as `DAT_00408060`, address-taken as the scanner base arg.
///
/// ponytail: absolute-address cell as mutable static, upgrade to real
/// image-relative import once data layout proven. Size unobserved
/// (address load, no deref); single byte ceiling, widen once a deref
/// width is proven.
pub static mut DAT_00408060: u8 = 0;

/// `emit(param_1, scan(&DAT, param_1)+1, 0x7fffffff, param_2)`.
/// `param_1` arrives in EAX, `param_2` in EDX per `__register`; the
/// `+1` wraps like the original `LEA`.
pub unsafe fn fn_00408028(param_1: *mut u8, param_2: *mut u8) {
    let r = HOOK_00407F4C(
        core::ptr::addr_of_mut!(DAT_00408060) as *mut u8,
        param_1,
    );
    crate::fn_0040525c::fn_0040525c(param_1, r.wrapping_add(1), 0x7fffffff, param_2);
}

#[cfg(test)]
mod tests {
    use super::{DAT_00408060, HOOK_00407F4C, fn_00408028};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SCAN_RET: AtomicUsize = AtomicUsize::new(0);
    static SCAN_BASE: AtomicUsize = AtomicUsize::new(0);
    static SCAN_S: AtomicUsize = AtomicUsize::new(0);
    static WIDE_D: AtomicUsize = AtomicUsize::new(0);
    static WIDE_S: AtomicUsize = AtomicUsize::new(0);
    static WIDE_N: AtomicUsize = AtomicUsize::new(0);

    /// Headed emit source for the real `fn_0040525c`: tag 2,
    /// length 8, payload `0xC0..`.
    static mut SRC_ARENA: [u8; 64] = [0; 64];

    unsafe extern "C" fn scan(base: *mut u8, s: *mut u8) -> i32 {
        SCAN_BASE.store(base as usize, Ordering::SeqCst);
        SCAN_S.store(s as usize, Ordering::SeqCst);
        SCAN_RET.load(Ordering::SeqCst) as i32
    }

    /// Real `fn_0040525c` wide-copy lane hook: copies and records.
    unsafe extern "C" fn wide(d: *mut u8, x: *mut u8, n: u32) {
        WIDE_D.store(d as usize, Ordering::SeqCst);
        WIDE_S.store(x as usize, Ordering::SeqCst);
        WIDE_N.store(n as usize, Ordering::SeqCst);
        core::ptr::copy_nonoverlapping(x, d, n as usize);
    }

    unsafe fn headed() -> *mut u8 {
        let base = core::ptr::addr_of_mut!(SRC_ARENA) as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 1);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, 8);
        for i in 0..16 {
            core::ptr::write_unaligned(base.wrapping_byte_add(12 + i), (0xC0 + i) as u8);
        }
        base.wrapping_byte_add(12)
    }

    #[test]
    fn scan_then_emit_lanes() {
        // Real `fn_0040525c` behind the emit (its hooks shared):
        // hold its lock, pin the wide copy.
        let _slice = crate::fn_0040525c::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_00407F4C = scan;
            crate::fn_0040525c::HOOK_00404dd4 = wide;
        }
        let p1 = unsafe { headed() };
        let mut dst = [0u8; 8];
        let p2 = dst.as_mut_ptr();
        let dat = core::ptr::addr_of!(DAT_00408060) as usize;

        // Mid-range: scan 5 → start 6-1 = 5, n =
        // min(0x7fffffff, 8-5) = 3 → wide(dst, p1+2*5, 3).
        SCAN_RET.store(5, Ordering::SeqCst);
        unsafe { fn_00408028(p1, p2) };
        assert_eq!(SCAN_BASE.load(Ordering::SeqCst), dat);
        assert_eq!(SCAN_S.load(Ordering::SeqCst), p1 as usize);
        assert_eq!(WIDE_D.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(WIDE_S.load(Ordering::SeqCst), (p1 as usize).wrapping_add(10));
        assert_eq!(WIDE_N.load(Ordering::SeqCst), 3);
        assert_eq!(&dst[..3], &[0xCA, 0xCB, 0xCC]);

        // LEA wrap edge: scan -1 → start 0, n = min(0x7fffffff, 8)
        // = 8 → wide(dst, p1, 8).
        SCAN_RET.store(0xffff_ffff, Ordering::SeqCst);
        unsafe { fn_00408028(p1, p2) };
        assert_eq!(WIDE_S.load(Ordering::SeqCst), p1 as usize);
        assert_eq!(WIDE_N.load(Ordering::SeqCst), 8);
        assert_eq!(&dst, &[0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7]);
    }
}
