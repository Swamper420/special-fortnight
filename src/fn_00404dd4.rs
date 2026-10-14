//! Original procedure `0x00404dd4` (48 bytes, `0x404dd4–0x404e03`).
//! Evidence: `evidence/00404dd4_fn_00404dd4.md`.

use crate::fn_004046c4::fn_004046c4;

unsafe extern "C" fn default_alloc(_n: u32) -> u32 {
    0
}

unsafe extern "C" fn default_fill(_a: *mut u8, _b: u32, _c: u32) {}

/// Target `0x4054b4` (`FUN_004054b4`), called with `param_3`, result
/// forwarded to fill and stored to `*param_1`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_004054b4` once it exists.
pub static mut HOOK_004054b4: unsafe extern "C" fn(u32) -> u32 = default_alloc;

/// Target `0x402fbc` (`FUN_00402fbc`), called with
/// `(param_2, result, param_3<<1)` on the non-null lane.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00402fbc` once it exists.
pub static mut HOOK_00402fbc: unsafe extern "C" fn(*mut u8, u32, u32) = default_fill;

/// `r=54b4(p3); if p2!=0 { 02fbc(p2,r,p3<<1) }; 446c4(p1); *p1=r`.
/// Params arrive in EAX/EDX/ECX per Ghidra `__register` observation.
///
/// ponytail: direct call to done `fn_004046c4` (no hook); hooks for
/// the two unreconstructed callees.
pub unsafe fn fn_00404dd4(param_1: *mut u8, param_2: *mut u8, param_3: u32) {
    let r = HOOK_004054b4(param_3);
    if !param_2.is_null() {
        HOOK_00402fbc(param_2, r, param_3.wrapping_shl(1));
    }
    fn_004046c4(param_1);
    core::ptr::write_unaligned(param_1 as *mut u32, r);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00402fbc, HOOK_004054b4, fn_00404dd4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_A: AtomicUsize = AtomicUsize::new(0);
    static FILL_B: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);

    const CANNED: u32 = 0x1122_3344;

    unsafe extern "C" fn alloc(n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        CANNED
    }

    unsafe extern "C" fn fill(a: *mut u8, b: u32, c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
        FILL_A.store(a as usize, Ordering::SeqCst);
        FILL_B.store(b as usize, Ordering::SeqCst);
        FILL_C.store(c as usize, Ordering::SeqCst);
    }

    #[test]
    fn alloc_fill_release_store_lanes() {
        // fn_00404dd4 calls done fn_004046c4, which reads its hook
        // global: hold the owner lock so its writer test can't race us.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_004054b4 = alloc;
            HOOK_00402fbc = fill;
        }
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);

        // Arena mirroring fn_004046c4's own test: obj = base+12,
        // count cell = base+4 (`obj-8`); slot cell holds obj.
        let mut arena = [0u32; 4];
        let base = arena.as_mut_ptr() as *mut u8;
        let obj = unsafe { base.wrapping_byte_add(12) };
        let mut slot: *mut u8 = obj;
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;
        let mut dst = [0u8; 8];
        let p2 = dst.as_mut_ptr();

        // Null lane: no fill call, result still stored.
        unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
        unsafe { fn_00404dd4(slot_ptr, core::ptr::null_mut(), 0x10) };
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 0x10);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { core::ptr::read_unaligned(slot_ptr as *const u32) }, CANNED);
        assert_eq!(unsafe { *arena.as_mut_ptr().wrapping_add(1) }, 0);

        // Non-null lane: one fill call carrying (p2, canned, p3<<1).
        unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
        slot = obj;
        unsafe { fn_00404dd4(slot_ptr, p2, 0x10) };
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_A.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(FILL_B.load(Ordering::SeqCst), CANNED as usize);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 0x20);
        assert_eq!(unsafe { core::ptr::read_unaligned(slot_ptr as *const u32) }, CANNED);
    }
}
