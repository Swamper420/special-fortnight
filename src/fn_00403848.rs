//! Original procedure `0x00403848` (19 bytes, `0x403848–0x40385a`).
//! Evidence: `evidence/00403848_fn_00403848.md`.

use crate::fn_00402e20::fn_00402e20;
use crate::fn_004038f8::fn_004038f8;

/// `038f8(param); 02e20(param)`. `param_1` arrives in EAX per Ghidra
/// `__register` observation; EBX spill has no host-visible effect.
/// Direct calls to done callees (no hooks).
pub unsafe fn fn_00403848(param_1: *mut u8) {
    fn_004038f8(param_1);
    fn_00402e20(param_1 as u32);
}

#[cfg(test)]
mod tests {
    use super::fn_00403848;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQ: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);
    static TAIL_SEQ: AtomicUsize = AtomicUsize::new(0);
    static CALLEE_SEQ: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn tail(arg: u32) {
        TAIL_ARG.store(arg as usize, Ordering::SeqCst);
        TAIL_SEQ.store(SEQ.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
    }

    /// Probe for the done callee's indirect slot: records lane order,
    /// returns 0 so its tail lane never fires.
    unsafe extern "C" fn indirect() -> u32 {
        CALLEE_SEQ.store(SEQ.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
        0
    }

    #[test]
    fn hook_then_direct_call_same_arg() {
        // Real fn_004038f8 walks *p as a node chain: hold its lock so
        // its hook-writer test can't race us, and restore hooks after.
        let _mid = crate::fn_004038f8::TEST_LOCK.lock().unwrap();
        // Direct call reaches done fn_00402e20, which reads its PTR
        // global: hold the owner lock so its writer test can't race us.
        let _callee = crate::fn_00402e20::TEST_LOCK.lock().unwrap();
        let saved_ptr = unsafe { crate::fn_00402e20::PTR_00412740 };
        let saved_tail = unsafe { crate::fn_004038f8::HOOK_00403a9c };
        unsafe {
            crate::fn_00402e20::PTR_00412740 = indirect;
            crate::fn_004038f8::HOOK_00403a9c = tail;
        }
        SEQ.store(0, Ordering::SeqCst);
        // Single node, value 0 (mid lane skipped), chain ends: tail fires once.
        let mut arena = [0u8; 0x60];
        let mut slot: *mut u8;
        let p: *mut u8;
        unsafe {
            let node = arena.as_mut_ptr().wrapping_byte_add(0x4c);
            core::ptr::write_unaligned(node.wrapping_byte_sub(0x4c) as *mut u32, 0);
            core::ptr::write_unaligned(
                node.wrapping_byte_sub(0x30) as *mut *mut u8,
                core::ptr::null_mut(),
            );
            slot = node;
            p = &mut slot as *mut *mut u8 as *mut u8;
            fn_00403848(p);
        }
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), p as u32 as usize);
        assert_eq!(TAIL_SEQ.load(Ordering::SeqCst), 0);
        assert_eq!(CALLEE_SEQ.load(Ordering::SeqCst), 1);
        unsafe {
            crate::fn_00402e20::PTR_00412740 = saved_ptr;
            crate::fn_004038f8::HOOK_00403a9c = saved_tail;
        }
    }
}
