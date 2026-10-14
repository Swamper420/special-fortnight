//! Original procedure `0x004068bc` (6 bytes, `0x004068bc–0x004068c1`).
//! Evidence: `evidence/004068bc_fn_004068bc.md`.
//!
//! Import thunk `USER32.DLL::MessageBoxW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_h_wnd: usize, _lp_text: usize, _lp_caption: usize, _u_type: u32) -> i32 {
    0
}

/// Thunk `USER32.DLL::MessageBoxW` via IAT slot `0x004193e4`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004068BC: unsafe extern "C" fn(usize, usize, usize, u32) -> i32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004068bc(h_wnd: usize, lp_text: usize, lp_caption: usize, u_type: u32) -> i32 {
    HOOK_004068BC(h_wnd, lp_text, lp_caption, u_type)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004068BC, fn_004068bc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: usize, a2: usize, a3: u32) -> i32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        A3.store(a3 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004068BC = hook };
        assert_eq!(unsafe { fn_004068bc(0, 0x1000, 0x2000, 0) }, 1);
        assert_eq!(A0.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(A1.load(Ordering::SeqCst), 0x1000 as usize);
        assert_eq!(A2.load(Ordering::SeqCst), 0x2000 as usize);
        assert_eq!(A3.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
