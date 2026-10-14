//! Original procedure `0x00404eb8` (16 bytes, `0x00404eb8–0x00404ec7`).
//! Evidence: `evidence/00404eb8_fn_00404eb8.md`.

use crate::fn_00404dd4::fn_00404dd4;

/// `len = p2==0 ? 0 : [p2-4]>>1; 404dd4(p1, p2, len)`.
/// `param_1` arrives in EAX (untouched), `param_2` in EDX
/// (null-tested, header word at `[EDX-4]`). Final `JMP 404dd4`
/// is a tail call.
///
/// ponytail: direct call to done `fn_00404dd4` (no hook); no
/// new hook — single thin wrapper.
pub unsafe fn fn_00404eb8(param_1: *mut u8, param_2: *mut u8) {
    let mut len: u32 = 0;
    if !param_2.is_null() {
        len = core::ptr::read_unaligned(param_2.wrapping_byte_offset(-4) as *const u32) >> 1;
    }
    fn_00404dd4(param_1, param_2, len);
}

#[cfg(test)]
mod tests {
    use super::fn_00404eb8;
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
    fn header_len_then_forward_lanes() {
        // fn_00404eb8 → done fn_00404dd4 → done fn_004046c4, which
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

        // Null lane: len=0, no fill call.
        unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404eb8(slot_ptr, core::ptr::null_mut()) };
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 0);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { core::ptr::read_unaligned(slot_ptr as *const u32) }, CANNED);

        // Header lane: [p2-4]=0x20 → len=0x10, fill (p2, canned, 0x20).
        let mut cell = [0u32; 2];
        cell[0] = 0x20;
        let p2 = unsafe { cell.as_mut_ptr().wrapping_add(1) } as *mut u8;
        unsafe { *arena.as_mut_ptr().wrapping_add(1) = 1 };
        slot = obj;
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00404eb8(slot_ptr, p2) };
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 0x10);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FILL_A.load(Ordering::SeqCst), p2 as usize);
        assert_eq!(FILL_B.load(Ordering::SeqCst), CANNED as usize);
        assert_eq!(FILL_C.load(Ordering::SeqCst), 0x20);
        assert_eq!(unsafe { core::ptr::read_unaligned(slot_ptr as *const u32) }, CANNED);
    }
}
