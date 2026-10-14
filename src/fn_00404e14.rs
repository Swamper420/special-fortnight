//! Original procedure `0x00404e14` (56 bytes, `0x00404e14–0x00404e4b`).
//! Evidence: `evidence/00404e14_fn_00404e14.md`.

use crate::fn_00404dd4::fn_00404dd4;

/// Wide-char length then forward: `len=wcslen(param_2 or 0);
/// 404dd4(param_1, param_2, len)`. `param_1` arrives in EAX
/// (untouched), `param_2` in EDX (null-tested, scanned as
/// `u16` lanes 0/2/4/6 with `+8` step, then
/// `(end-start)>>1`). Final `JMP 404dd4` is a tail call.
///
/// ponytail: direct call to done `fn_00404dd4` (no hook); no
/// new hook — single thin wrapper.
pub unsafe fn fn_00404e14(param_1: *mut u8, param_2: *mut u16) {
    let mut len: u32 = 0;
    if !param_2.is_null() {
        let mut p = param_2;
        loop {
            if core::ptr::read_unaligned(p) == 0 {
                break;
            }
            if core::ptr::read_unaligned(p.wrapping_add(1)) == 0 {
                p = p.wrapping_add(1);
                break;
            }
            if core::ptr::read_unaligned(p.wrapping_add(2)) == 0 {
                p = p.wrapping_add(2);
                break;
            }
            if core::ptr::read_unaligned(p.wrapping_add(3)) == 0 {
                p = p.wrapping_add(3);
                break;
            }
            p = p.wrapping_add(4);
        }
        len = (p as u32).wrapping_sub(param_2 as u32) >> 1;
    }
    fn_00404dd4(param_1, param_2 as *mut u8, len);
}

#[cfg(test)]
mod tests {
    use super::fn_00404e14;
    use crate::fn_00404dd4::{HOOK_00402fbc, HOOK_004054b4};
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
    fn wcslen_then_forward_lanes() {
        // fn_00404e14 → done fn_00404dd4 → done fn_004046c4, which
        // reads its hook global: hold the owner lock so its writer
        // test can't race us (same lock fn_00404dd4's test holds).
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_004054b4 = alloc;
            HOOK_00402fbc = fill;
        }

        // Arena mirroring fn_004046c4's own test: obj = base+12,
        // count cell = base+4 (`obj-8`); slot cell holds obj.
        let mut arena = [0u32; 4];
        unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
        let base = arena.as_mut_ptr() as *mut u8;
        let obj = unsafe { base.wrapping_byte_add(12) };
        let mut slot: *mut u8 = obj;
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;

        // Null lane: len=0, no fill call.
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404e14(slot_ptr, core::ptr::null_mut()) };
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 0);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { core::ptr::read_unaligned(slot_ptr as *const u32) }, CANNED);

        // Wide-string lanes: each cascade arm + the +8 step.
        let cases: &[&[u16]] = &[&[0], &[0x41, 0], &[0x41, 0x42, 0], &[0x41, 0x42, 0x43, 0], &[0x41, 0x42, 0x43, 0x44, 0], &[0x41, 0x42, 0x43, 0x44, 0x45, 0]];
        for (i, s) in cases.iter().enumerate() {
            let expect = s.len() as u32 - 1;
            unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
            slot = obj;
            ALLOC_HITS.store(0, Ordering::SeqCst);
            FILL_HITS.store(0, Ordering::SeqCst);
            unsafe { fn_00404e14(slot_ptr, s.as_ptr() as *mut u16) };
            assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), expect as usize, "case {i}");
            assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1, "case {i}");
            assert_eq!(FILL_A.load(Ordering::SeqCst), s.as_ptr() as usize, "case {i}");
            assert_eq!(FILL_B.load(Ordering::SeqCst), CANNED as usize, "case {i}");
            assert_eq!(FILL_C.load(Ordering::SeqCst), (expect * 2) as usize, "case {i}");
            assert_eq!(unsafe { core::ptr::read_unaligned(slot_ptr as *const u32) }, CANNED, "case {i}");
        }
    }
}
