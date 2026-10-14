//! Original procedure `0x00404e04` (15 bytes, `0x00404e04–0x00404e12`).
//! Evidence: `evidence/00404e04_fn_00404e04.md`.

use crate::fn_00404dd4::fn_00404dd4;

/// `copy=param_2; 404dd4(param_1, &copy, 1)`. `param_1` arrives in
/// EAX (untouched), `param_2` in EDX (`PUSH EDX; MOV EDX,ESP`
/// lane), `param_3=1` via `MOV ECX,1`. `POP EDX` restore folded:
/// by-value param, unobservable.
///
/// ponytail: direct call to done `fn_00404dd4` (no hook); no
/// new hook — single thin wrapper.
pub unsafe fn fn_00404e04(param_1: *mut u8, param_2: u32) {
    let mut copy = param_2;
    fn_00404dd4(param_1, &mut copy as *mut u32 as *mut u8, 1);
}

#[cfg(test)]
mod tests {
    use super::fn_00404e04;
    use crate::fn_00404dd4::{HOOK_00402fbc, HOOK_004054b4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FILL_B: AtomicUsize = AtomicUsize::new(0);
    static FILL_C: AtomicUsize = AtomicUsize::new(0);
    static FILL_WORD: AtomicUsize = AtomicUsize::new(0);

    const CANNED: u32 = 0x1122_3344;
    const PARAM: u32 = 0xAABB_CCDD;

    unsafe extern "C" fn alloc(_n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        CANNED
    }

    unsafe extern "C" fn fill(a: *mut u8, b: u32, c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
        FILL_WORD.store(core::ptr::read_unaligned(a as *const u32) as usize, Ordering::SeqCst);
        FILL_B.store(b as usize, Ordering::SeqCst);
        FILL_C.store(c as usize, Ordering::SeqCst);
    }

    #[test]
    fn stack_copy_plus_one_lanes() {
        // fn_00404e04 → done fn_00404dd4 → done fn_004046c4, which
        // reads its hook global: hold the owner lock so its writer
        // test can't race us (same lock fn_00404dd4's test holds).
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
        unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
        let base = arena.as_mut_ptr() as *mut u8;
        let obj = unsafe { base.wrapping_byte_add(12) };
        let mut slot: *mut u8 = obj;
        let slot_ptr = &mut slot as *mut *mut u8 as *mut u8;

        unsafe { fn_00404e04(slot_ptr, PARAM) };
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_WORD.load(Ordering::SeqCst), PARAM as usize);
        assert_eq!(FILL_B.load(Ordering::SeqCst), CANNED as usize);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 2);
        assert_eq!(unsafe { core::ptr::read_unaligned(slot_ptr as *const u32) }, CANNED);
        assert_eq!(unsafe { *arena.as_mut_ptr().wrapping_add(1) }, 0);
    }
}
