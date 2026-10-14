//! Original procedure `0x00405ad8` (11 bytes, `0x405ad8–0x405ae2`).
//! Evidence: `evidence/00405ad8_fn_00405ad8.md`.

/// Forward `(slot, desc, depth)` to `fn_00405940`, with the counts
/// pointer as fourth lane. `PUSH ESP; ADD [ESP],4` synthesizes that
/// lane as the caller's first stack word; Rust takes it as an
/// explicit pointer (no host equivalent of the stack-slot trick).
/// Params arrive in EAX/EDX/ECX per Ghidra `__register`
/// observation. Returns void.
pub unsafe fn fn_00405ad8(
    param_1: *mut usize,
    param_2: *const u8,
    param_3: i32,
    param_4: *mut i32,
) {
    crate::fn_00405940::fn_00405940(param_1, param_2, param_3, param_4);
}

#[cfg(test)]
mod tests {
    use super::fn_00405ad8;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HOOK38_HITS: AtomicUsize = AtomicUsize::new(0);
    static HOOK38_A: AtomicUsize = AtomicUsize::new(0);
    static HOOK38_B: AtomicUsize = AtomicUsize::new(0);
    static FAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FAIL_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook_5ae4(a: *mut usize, b: *const u8) {
        HOOK38_HITS.fetch_add(1, Ordering::SeqCst);
        HOOK38_A.store(a as usize, Ordering::SeqCst);
        HOOK38_B.store(b as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn fail_hook(code: u32) {
        FAIL_HITS.fetch_add(1, Ordering::SeqCst);
        FAIL_ARG.store(code as usize, Ordering::SeqCst);
    }

    #[test]
    fn delegates_count_lanes() {
        let _l38 = crate::fn_00405938::TEST_LOCK.lock().unwrap();
        let _l40 = crate::fn_00405940::TEST_LOCK.lock().unwrap();
        let saved_ae4 = unsafe { crate::fn_00405938::HOOK_00405AE4 };
        let saved_fail = unsafe { crate::fn_00405940::HOOK_00402F60 };
        unsafe {
            crate::fn_00405938::HOOK_00405AE4 = hook_5ae4;
            crate::fn_00405940::HOOK_00402F60 = fail_hook;
        }
        let desc = [0u8; 8];
        let mut slot: usize = 0xdead_beef;
        // count == 0: short lane, slot untouched, no fail.
        let zero = Box::leak(Box::new([0i32])).as_mut_ptr();
        HOOK38_HITS.store(0, Ordering::SeqCst);
        FAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00405ad8(&mut slot, desc.as_ptr(), 7, zero) };
        assert_eq!(HOOK38_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(HOOK38_A.load(Ordering::SeqCst), &mut slot as *mut usize as usize);
        assert_eq!(HOOK38_B.load(Ordering::SeqCst), desc.as_ptr() as usize);
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(slot, 0xdead_beef);
        // count < 0: fail with pointer-derived code, then same lane.
        let neg = Box::leak(Box::new([-3i32])).as_mut_ptr();
        HOOK38_HITS.store(0, Ordering::SeqCst);
        FAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_00405ad8(&mut slot, desc.as_ptr(), 7, neg) };
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FAIL_ARG.load(Ordering::SeqCst) & 0xff, 4);
        assert_eq!(
            FAIL_ARG.load(Ordering::SeqCst),
            (((neg as usize as u32) & 0xffffff00) | 4) as usize
        );
        assert_eq!(HOOK38_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(slot, 0xdead_beef);
        unsafe {
            crate::fn_00405938::HOOK_00405AE4 = saved_ae4;
            crate::fn_00405940::HOOK_00402F60 = saved_fail;
        }
    }
}
