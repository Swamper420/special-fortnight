//! Original procedure `0x00406894` (6 bytes, `0x00406894–0x00406899`).
//! Evidence: `evidence/00406894_fn_00406894.md`.
//!
//! Import thunk `USER32.DLL::DestroyWindow`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_h_wnd: usize) -> u32 {
    0
}

/// Thunk `USER32.DLL::DestroyWindow` via IAT slot `0x004193f8`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00406894: unsafe extern "C" fn(usize) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00406894(h_wnd: usize) -> u32 {
    HOOK_00406894(h_wnd)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406894, fn_00406894};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00406894 = hook };
        assert_eq!(unsafe { fn_00406894(0x1000) }, 1);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
