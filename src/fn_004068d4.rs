//! Original procedure `0x004068d4` (6 bytes, `0x004068d4–0x004068d9`).
//! Evidence: `evidence/004068d4_fn_004068d4.md`.
//!
//! Import thunk `USER32.DLL::SetWindowLongW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_h_wnd: usize, _n_index: i32, _dw_new: i32) -> i32 {
    0
}

/// Thunk `USER32.DLL::SetWindowLongW` via IAT slot `0x004193d8`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004068D4: unsafe extern "C" fn(usize, i32, i32) -> i32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004068d4(h_wnd: usize, n_index: i32, dw_new: i32) -> i32 {
    HOOK_004068D4(h_wnd, n_index, dw_new)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004068D4, fn_004068d4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: i32, a2: i32) -> i32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        7
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004068D4 = hook };
        assert_eq!(unsafe { fn_004068d4(0x1000, -21, 7) }, 7);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000 as usize);
        assert_eq!(A1.load(Ordering::SeqCst), (-21i32) as usize);
        assert_eq!(A2.load(Ordering::SeqCst), 7 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
