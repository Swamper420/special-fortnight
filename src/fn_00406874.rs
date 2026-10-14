//! Original procedure `0x00406874` (6 bytes, `0x00406874–0x00406879`).
//! Evidence: `evidence/00406874_fn_00406874.md`.
//!
//! Import thunk `KERNEL32.DLL::WideCharToMultiByte`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn default_hook(_code_page: u32, _dw_flags: u32, _lp_wide: usize, _cch_wide: i32, _lp_multi: usize, _cb_multi: i32, _lp_def: usize, _lp_used: usize) -> i32 {
    0
}

/// Thunk `KERNEL32.DLL::WideCharToMultiByte` via IAT slot `0x0041940c`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
#[allow(clippy::too_many_arguments)]
pub static mut HOOK_00406874: unsafe extern "C" fn(u32, u32, usize, i32, usize, i32, usize, usize) -> i32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
#[allow(clippy::too_many_arguments)]
pub unsafe fn fn_00406874(code_page: u32, dw_flags: u32, lp_wide: usize, cch_wide: i32, lp_multi: usize, cb_multi: i32, lp_def: usize, lp_used: usize) -> i32 {
    HOOK_00406874(code_page, dw_flags, lp_wide, cch_wide, lp_multi, cb_multi, lp_def, lp_used)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406874, fn_00406874};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);
    static A4: AtomicUsize = AtomicUsize::new(0);
    static A5: AtomicUsize = AtomicUsize::new(0);
    static A6: AtomicUsize = AtomicUsize::new(0);
    static A7: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: u32, a1: u32, a2: usize, a3: i32, a4: usize, a5: i32, a6: usize, a7: usize) -> i32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        A3.store(a3 as usize, Ordering::SeqCst);
        A4.store(a4 as usize, Ordering::SeqCst);
        A5.store(a5 as usize, Ordering::SeqCst);
        A6.store(a6 as usize, Ordering::SeqCst);
        A7.store(a7 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        5
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00406874 = hook };
        assert_eq!(unsafe { fn_00406874(0, 0, 0x1000, -1, 0x2000, 16, 0, 0) }, 5);
        assert_eq!(A0.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(A1.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(A2.load(Ordering::SeqCst), 0x1000 as usize);
        assert_eq!(A3.load(Ordering::SeqCst), (-1i32) as usize);
        assert_eq!(A4.load(Ordering::SeqCst), 0x2000 as usize);
        assert_eq!(A5.load(Ordering::SeqCst), 16 as usize);
        assert_eq!(A6.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(A7.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
