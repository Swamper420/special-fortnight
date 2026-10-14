//! Original procedure `0x00403864` (32 bytes, `0x00403864–0x00403883`).
//! Evidence: `evidence/00403864_fn_00403864.md`.

/// Borland SEH link via `fn_004039e4`, then unchecked dispatch via
/// `fn_00403a3c`, then `POP FS:[0]` unlink. `param_1` in EAX,
/// `param_2` in DL, `param_3` in ECX per Ghidra `__register`
/// observation. Both `TEST DL,DL` guards test the same incoming
/// `param_2`: the link call preserves EDX (`PUSH/POP EDX` in
/// `fn_004039e4`), so the two sequential `if`s below are the
/// isomorphic two-branch shape, and the unlink runs exactly when the
/// link happened. Record lives in owner `crate::fn_004039e4` types
/// (no duplicate cell).
pub unsafe fn fn_00403864(param_1: *mut *const u8, param_2: u8, param_3: u32) {
    let mut record: crate::fn_004039e4::SehRecord004039e4 = core::mem::zeroed();
    if param_2 != 0 {
        crate::fn_004039e4::fn_004039e4(param_1 as *const u8, param_2, param_3, &mut record);
    }
    // ponytail: same condition, not a callee return (`fn_004039e4`
    // returns void; DL restored by its PUSH/POP EDX). Kept as a second
    // `if` to match the two-TEST assembly shape.
    if param_2 != 0 {
        crate::fn_00403a3c::fn_00403a3c(param_1);
        crate::fn_004039e4::SEH_HEAD_FS0 = record.prev;
    }
}

#[cfg(test)]
mod tests {
    use super::fn_00403864;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static INNER_HITS: AtomicUsize = AtomicUsize::new(0);
    static INNER_P1: AtomicUsize = AtomicUsize::new(0);
    static INNER_P2: AtomicUsize = AtomicUsize::new(0);
    static INNER_P3: AtomicUsize = AtomicUsize::new(0);
    static OUTER_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn inner(p1: *const u8, p2: u8, p3: u32) {
        INNER_HITS.fetch_add(1, Ordering::SeqCst);
        INNER_P1.store(p1 as usize, Ordering::SeqCst);
        INNER_P2.store(p2 as usize, Ordering::SeqCst);
        INNER_P3.store(p3 as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn outer(_obj: *mut *const u8) {
        OUTER_HITS.fetch_add(1, Ordering::SeqCst);
    }

    fn reset() {
        INNER_HITS.store(0, Ordering::SeqCst);
        OUTER_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn link_dispatch_unlink_lanes() {
        let _guard = crate::fn_004039e4::TEST_LOCK.lock().unwrap();
        // Byte layout mirroring 32-bit original: inner mock 12 below
        // object base (`fn_004039e4` slot), outer mock `0x1c` below
        // fake vtbl (`fn_00403a3c` slot). Works on 64-bit host.
        let inner_ptr = inner as *const core::ffi::c_void;
        let outer_ptr = outer as *const core::ffi::c_void;
        let mut buf = [0u8; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(
                &inner_ptr as *const _ as *const u8,
                buf.as_mut_ptr(),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
            core::ptr::copy_nonoverlapping(
                &outer_ptr as *const _ as *const u8,
                buf.as_mut_ptr().add(0x14),
                core::mem::size_of::<*const core::ffi::c_void>(),
            );
            let vtbl = buf.as_ptr().add(0x30);
            core::ptr::copy_nonoverlapping(
                &vtbl as *const _ as *const u8,
                buf.as_mut_ptr().add(12),
                core::mem::size_of::<*const u8>(),
            );
        }
        let param = unsafe { buf.as_mut_ptr().add(12) as *mut *const u8 };
        // Skip lane: no hits, head untouched.
        reset();
        unsafe {
            crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8;
            fn_00403864(param, 0x00, 0x09);
            assert_eq!(INNER_HITS.load(Ordering::SeqCst), 0);
            assert_eq!(OUTER_HITS.load(Ordering::SeqCst), 0);
            assert_eq!(crate::fn_004039e4::SEH_HEAD_FS0 as usize, 0x777);
        }
        // Taken lane: both dispatch, args pass through, head restored.
        reset();
        unsafe {
            crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8;
            fn_00403864(param, 0x01, 0x09);
            assert_eq!(INNER_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(INNER_P1.load(Ordering::SeqCst), param as usize);
            assert_eq!(INNER_P2.load(Ordering::SeqCst), 0x01);
            assert_eq!(INNER_P3.load(Ordering::SeqCst), 0x09);
            assert_eq!(OUTER_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(crate::fn_004039e4::SEH_HEAD_FS0 as usize, 0x777);
        }
        // Sign-split lane (`0xff` nonzero but signed-negative): inner
        // skipped, outer still runs, head still restored.
        reset();
        unsafe {
            crate::fn_004039e4::SEH_HEAD_FS0 = 0x777 as *mut u8;
            fn_00403864(param, 0xff, 0x09);
            assert_eq!(INNER_HITS.load(Ordering::SeqCst), 0);
            assert_eq!(OUTER_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(crate::fn_004039e4::SEH_HEAD_FS0 as usize, 0x777);
        }
    }
}
