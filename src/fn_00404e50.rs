//! Original procedure `0x00404e50` (24 bytes, `0x00404e50–0x00404e67`).
//! Evidence: `evidence/00404e50_fn_00404e50.md`.

use crate::fn_00404dd4::fn_00404dd4;

/// Bounded wide-char length then forward: `len=wcsnlen(param_2,
/// param_3); 404dd4(param_1, param_2, len)`. `param_1` arrives in
/// EAX (saved/restored, untouched), `param_2` in EDX (scanner
/// input, untouched), `param_3` in ECX (`REPNE SCASW` bound).
/// Found lane: `NOT ECX` then `ADD ECX,param_3`. Miss lane:
/// `len=param_3`. Final `JMP 404dd4` is a tail call.
///
/// ponytail: direct call to done `fn_00404dd4` (no hook); no
/// new hook — single thin wrapper. `param_3 == 0` wraps to
/// `u32::MAX` on hardware (flag carryover); encoded, uncovered
/// on host — cover n>=1 only.
pub unsafe fn fn_00404e50(param_1: *mut u8, param_2: *mut u16, param_3: u32) {
    let mut u = param_3;
    let mut p = param_2;
    let mut found = true;
    loop {
        if u == 0 {
            break;
        }
        u = u.wrapping_sub(1);
        found = core::ptr::read_unaligned(p) == 0;
        p = p.wrapping_add(1);
        if found {
            break;
        }
    }
    if found {
        u = !u;
    }
    fn_00404dd4(param_1, param_2 as *mut u8, u.wrapping_add(param_3));
}

#[cfg(test)]
mod tests {
    use super::fn_00404e50;
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
    fn bounded_len_then_forward_lanes() {
        // fn_00404e50 → done fn_00404dd4 → done fn_004046c4, which
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
        let base = arena.as_mut_ptr() as *mut u8;
        let obj = unsafe { base.wrapping_byte_add(12) };
        let mut slot: *mut u8 = obj;
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;

        // (wide string, bound, expected len).
        let s_empty: &[u16] = &[0];
        let s_ab: &[u16] = &[0x41, 0x42, 0];
        let s_abc: &[u16] = &[0x41, 0x42, 0x43, 0];
        let s_noterm: &[u16] = &[0x41, 0x42, 0x43, 0x44];
        let cases: &[(&[u16], u32, u32)] = &[
            (s_empty, 4, 0),
            (s_ab, 8, 2),
            (s_abc, 3, 3),
            (s_abc, 4, 3),
            (s_noterm, 2, 2),
            (s_noterm, 4, 4),
        ];
        for (i, (s, bound, expect)) in cases.iter().enumerate() {
            unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
            slot = obj;
            ALLOC_HITS.store(0, Ordering::SeqCst);
            FILL_HITS.store(0, Ordering::SeqCst);
            unsafe { fn_00404e50(slot_ptr, s.as_ptr() as *mut u16, *bound) };
            assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), *expect as usize, "case {i}");
            assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1, "case {i}");
            assert_eq!(FILL_A.load(Ordering::SeqCst), s.as_ptr() as usize, "case {i}");
            assert_eq!(FILL_B.load(Ordering::SeqCst), CANNED as usize, "case {i}");
            assert_eq!(FILL_C.load(Ordering::SeqCst), (*expect * 2) as usize, "case {i}");
            assert_eq!(unsafe { core::ptr::read_unaligned(slot_ptr as *const u32) }, CANNED, "case {i}");
        }
    }
}
