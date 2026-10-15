//! Original procedure `0x004030bc` (37 bytes, `0x004030bc–0x004030e0`).
//! Evidence: `evidence/004030bc_fn_004030bc.md`.

unsafe extern "C" fn default_qpc(_li: *mut u64) -> i32 {
    0
}

/// Thunk `0x004011a8` (`KERNEL32.DLL::QueryPerformanceCounter`).
///
/// ponytail: hook standing in for OS import (also keeps host tests
/// linkable), rewire to raw `extern "system"` import once
/// Windows-target linkage proven.
pub static mut HOOK_004011a8: unsafe extern "C" fn(*mut u64) -> i32 = default_qpc;

/// Thunk `0x004011b0` (`KERNEL32.DLL::GetTickCount`): direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn() -> u32`).

/// `if QPC(&li) { seed=LowPart } else { seed=GTC() }`. No args, void.
/// Seed cell shared with `fn_004030e4`; written here, never duplicated.
pub unsafe fn fn_004030bc() {
    // ponytail: u64 local stands in for LARGE_INTEGER stack slot; only
    // LowPart (low 32 bits) is read, HighPart ignored per assembly.
    let mut li: u64 = 0;
    if HOOK_004011a8(core::ptr::addr_of_mut!(li)) != 0 {
        crate::fn_004030e4::CELL_00412008 = li as u32;
    } else {
        crate::fn_004030e4::CELL_00412008 = crate::fn_004011b0::fn_004011b0();
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004011a8, fn_004030bc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static QPC_HITS: AtomicUsize = AtomicUsize::new(0);
    static GTC_HITS: AtomicUsize = AtomicUsize::new(0);
    static QPC_RET: AtomicUsize = AtomicUsize::new(0);
    static QPC_VAL: AtomicUsize = AtomicUsize::new(0);
    static GTC_VAL: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn qpc(li: *mut u64) -> i32 {
        QPC_HITS.fetch_add(1, Ordering::SeqCst);
        core::ptr::write_unaligned(li, QPC_VAL.load(Ordering::SeqCst) as u64);
        QPC_RET.load(Ordering::SeqCst) as i32
    }

    unsafe extern "C" fn gtc() -> u32 {
        GTC_HITS.fetch_add(1, Ordering::SeqCst);
        GTC_VAL.load(Ordering::SeqCst) as u32
    }

    #[test]
    fn qpc_lowpart_or_tickcount_seed_lanes() {
        let _guard = crate::fn_004030e4::TEST_LOCK.lock().unwrap();
        let _thunk = crate::fn_004011b0::TEST_LOCK.lock().unwrap();
        unsafe {
            let saved_cell = crate::fn_004030e4::CELL_00412008;
            let saved_qpc = HOOK_004011a8;
            let saved_gtc = crate::fn_004011b0::HOOK_004011B0;
            HOOK_004011a8 = qpc;
            crate::fn_004011b0::HOOK_004011B0 = gtc;
            // QPC-ok lane stores LowPart, skips GTC.
            QPC_HITS.store(0, Ordering::SeqCst);
            GTC_HITS.store(0, Ordering::SeqCst);
            QPC_RET.store(1, Ordering::SeqCst);
            QPC_VAL.store(0x1122_3344_5566_7788u64 as usize, Ordering::SeqCst);
            fn_004030bc();
            assert_eq!(crate::fn_004030e4::CELL_00412008, 0x5566_7788);
            assert_eq!(QPC_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(GTC_HITS.load(Ordering::SeqCst), 0);
            // QPC-fail lane stores GetTickCount.
            QPC_HITS.store(0, Ordering::SeqCst);
            GTC_HITS.store(0, Ordering::SeqCst);
            QPC_RET.store(0, Ordering::SeqCst);
            GTC_VAL.store(0x9e37_79b9, Ordering::SeqCst);
            fn_004030bc();
            assert_eq!(crate::fn_004030e4::CELL_00412008, 0x9e37_79b9);
            assert_eq!(QPC_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(GTC_HITS.load(Ordering::SeqCst), 1);
            crate::fn_004030e4::CELL_00412008 = saved_cell;
            HOOK_004011a8 = saved_qpc;
            crate::fn_004011b0::HOOK_004011B0 = saved_gtc;
        }
    }
}
