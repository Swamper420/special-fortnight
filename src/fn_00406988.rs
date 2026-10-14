//! Original procedure `0x00406988` (18 bytes, `0x00406988–0x00406999`).
//! Evidence: `evidence/00406988_fn_00406988.md`.

use crate::fn_00404e14::fn_00404e14;

/// Swap-forwarder: `(EAX=param_1, EDX=param_2)` becomes
/// `fn_00404e14(param_2, param_1)` per observed `MOV EAX,ESI /
/// MOV EDX,EBX` after `ESI=EDX / EBX=EAX`. `param_1` (EAX) is the
/// wide buffer the callee scans; `param_2` (EDX) the slot it
/// fills. Return is `void` per observation.
///
/// ponytail: direct call to done `fn_00404e14` (no hook); no
/// new hook — single thin wrapper.
pub unsafe fn fn_00406988(param_1: *mut u16, param_2: *mut u8) {
    fn_00404e14(param_2, param_1);
}

#[cfg(test)]
mod tests {
    use super::fn_00406988;
    use crate::fn_00404dd4::{HOOK_00402fbc, HOOK_004054b4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static FILL_HITS: AtomicUsize = AtomicUsize::new(0);

    const CANNED: u32 = 0x1122_3344;

    unsafe extern "C" fn alloc(n: u32) -> u32 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        CANNED
    }

    unsafe extern "C" fn fill(_a: *mut u8, _b: u32, _c: u32) {
        FILL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn swap_order_through_real_chain() {
        // fn_00406988 → done fn_00404e14 → done fn_00404dd4 → done
        // fn_004046c4: hold the owner lock like the callees' tests.
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
        // Wide buffer in param_1 position must be scanned (len 2),
        // slot in param_2 position must receive the canned value.
        let wide = [0x41u16, 0x42, 0];
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FILL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00406988(wide.as_ptr() as *mut u16, slot_ptr) };
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 2);
        assert_eq!(FILL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { core::ptr::read_unaligned(slot_ptr as *const u32) }, CANNED);
    }
}
