//! Original procedure `0x00402e88` (32 bytes, `0x00402e88–0x00402ea7`).
//! Evidence: `evidence/00402e88_fn_00402e88.md`.

/// Target `0x00406588`, queried twice (null-test, then re-query deref):
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn() -> *const u8`).

/// `p=query(); if *p { q=query(); *(*q+8) } else 0`. Second query
/// re-runs (observable side effects, not cached). Pointer links read
/// pointer-sized (`*const *const u8`, one MOV on the i686 target);
/// flag/field stay `u32` per observed widths.
pub unsafe fn fn_00402e88() -> u32 {
    let p = crate::fn_00406588::fn_00406588();
    if core::ptr::read_unaligned(p as *const u32) != 0 {
        let q = crate::fn_00406588::fn_00406588();
        let inner = core::ptr::read_unaligned(q as *const *const u8);
        core::ptr::read_unaligned(inner.wrapping_byte_add(8) as *const u32)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::fn_00402e88;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test-only serialization for this module's locals.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static RET0: AtomicUsize = AtomicUsize::new(0);
    static RET1: AtomicUsize = AtomicUsize::new(0);
    static FLAG_ZERO: u32 = 0;
    static FLAG_ONE: u32 = 1;
    static PTR_CELL: AtomicUsize = AtomicUsize::new(0);
    static TARGET: [u32; 3] = [0, 0, 0x9e37_79b9];

    /// Stands in for the OS import behind real `fn_00406588`
    /// (`TlsGetValue` slow path); per-call values model re-query.
    unsafe extern "C" fn tls_value(_index: u32) -> *const u8 {
        let n = CALLS.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            RET0.load(Ordering::SeqCst) as *const u8
        } else {
            RET1.load(Ordering::SeqCst) as *const u8
        }
    }

    #[test]
    fn zero_and_requery_deref_lanes() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _tls = crate::fn_00406588::TEST_LOCK.lock().unwrap();
        let (old_flag, old_hook, old_index);
        unsafe {
            old_flag = crate::fn_00406588::FLAG_00415b44;
            old_hook = crate::fn_00406588::TLS_GET_VALUE_00406520;
            old_index = crate::fn_00406588::TLS_INDEX_004127ac;
            crate::fn_00406588::FLAG_00415b44 = 1;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = tls_value;
            crate::fn_00406588::TLS_INDEX_004127ac = 0;
        }
        // Zero lane: one query, returns 0.
        CALLS.store(0, Ordering::SeqCst);
        RET0.store(&FLAG_ZERO as *const u32 as usize, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00402e88() }, 0);
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        // Nonzero lane: re-queries, returns [inner+8].
        CALLS.store(0, Ordering::SeqCst);
        RET0.store(&FLAG_ONE as *const u32 as usize, Ordering::SeqCst);
        PTR_CELL.store(TARGET.as_ptr() as usize, Ordering::SeqCst);
        RET1.store(&PTR_CELL as *const AtomicUsize as usize, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00402e88() }, 0x9e37_79b9);
        assert_eq!(CALLS.load(Ordering::SeqCst), 2);
        unsafe {
            crate::fn_00406588::FLAG_00415b44 = old_flag;
            crate::fn_00406588::TLS_GET_VALUE_00406520 = old_hook;
            crate::fn_00406588::TLS_INDEX_004127ac = old_index;
        }
    }
}
