//! Original procedure `0x00408028` (41 bytes, `0x00408028–0x00408050`).
//! Evidence: `evidence/00408028_fn_00408028.md`.

unsafe extern "C" fn default_scan(_base: *mut u8, _s: *mut u8) -> i32 {
    0
}

unsafe extern "C" fn default_emit(_d: *mut u8, _start: i32, _n: i32, _dst: *mut u8) {}

/// Scanner `0x00407f4c` (`FUN_00407f4c`), called with `(&DAT_00408060,
/// param_1)`; its EAX residue is taken as `i32` per this caller's
/// observation (the callee's own dossier reports `void`; see evidence).
///
/// ponytail: hook standing in for batch-mate `fn_00407f4c`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_00407F4C: unsafe extern "C" fn(*mut u8, *mut u8) -> i32 =
    default_scan;

/// Emitter `0x0040525c` (`FUN_0040525c`), called with
/// `(param_1, res+1, 0x7fffffff, param_2)`.
///
/// ponytail: hook mirroring done `fn_0040525c`'s shape, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_0040525C: unsafe extern "C" fn(*mut u8, i32, i32, *mut u8) =
    default_emit;

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
    HOOK_0040525C(param_1, r.wrapping_add(1), 0x7fffffff, param_2);
}

#[cfg(test)]
mod tests {
    use super::{DAT_00408060, HOOK_0040525C, HOOK_00407F4C, fn_00408028};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SCAN_RET: AtomicUsize = AtomicUsize::new(0);
    static SCAN_BASE: AtomicUsize = AtomicUsize::new(0);
    static SCAN_S: AtomicUsize = AtomicUsize::new(0);
    static EMIT_D: AtomicUsize = AtomicUsize::new(0);
    static EMIT_START: AtomicUsize = AtomicUsize::new(0);
    static EMIT_N: AtomicUsize = AtomicUsize::new(0);
    static EMIT_DST: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn scan(base: *mut u8, s: *mut u8) -> i32 {
        SCAN_BASE.store(base as usize, Ordering::SeqCst);
        SCAN_S.store(s as usize, Ordering::SeqCst);
        SCAN_RET.load(Ordering::SeqCst) as i32
    }

    unsafe extern "C" fn emit(d: *mut u8, start: i32, n: i32, dst: *mut u8) {
        EMIT_D.store(d as usize, Ordering::SeqCst);
        EMIT_START.store(start as usize, Ordering::SeqCst);
        EMIT_N.store(n as usize, Ordering::SeqCst);
        EMIT_DST.store(dst as usize, Ordering::SeqCst);
    }

    #[test]
    fn scan_then_emit_lanes() {
        // Own hooks/cell only: no foreign globals, no TEST_LOCK.
        unsafe {
            HOOK_00407F4C = scan;
            HOOK_0040525C = emit;
        }
        let mut a = 0u8;
        let mut b = 0u8;
        let p1 = &mut a as *mut u8;
        let p2 = &mut b as *mut u8;
        let dat = core::ptr::addr_of!(DAT_00408060) as usize;

        // Mid-range: scan 5 → start 6, max 0x7fffffff.
        SCAN_RET.store(5, Ordering::SeqCst);
        unsafe { fn_00408028(p1, p2) };
        assert_eq!(SCAN_BASE.load(Ordering::SeqCst), dat);
        assert_eq!(SCAN_S.load(Ordering::SeqCst), p1 as usize);
        assert_eq!(EMIT_D.load(Ordering::SeqCst), p1 as usize);
        assert_eq!(EMIT_START.load(Ordering::SeqCst), 6);
        assert_eq!(EMIT_N.load(Ordering::SeqCst), 0x7fffffff);
        assert_eq!(EMIT_DST.load(Ordering::SeqCst), p2 as usize);

        // LEA wrap edge: scan -1 → start 0.
        SCAN_RET.store(0xffff_ffff, Ordering::SeqCst);
        unsafe { fn_00408028(p1, p2) };
        assert_eq!(EMIT_START.load(Ordering::SeqCst), 0);
        assert_eq!(EMIT_N.load(Ordering::SeqCst), 0x7fffffff);
        assert_eq!(EMIT_DST.load(Ordering::SeqCst), p2 as usize);
    }
}
