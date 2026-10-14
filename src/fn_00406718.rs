//! Original procedure `0x00406718` (6 bytes, `0x00406718–0x0040671d`).
//! Evidence: `evidence/00406718_fn_00406718.md`.
//!
//! Import thunk `KERNEL32.DLL::GetModuleHandleW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize) -> usize {
    0
}

/// Thunk `KERNEL32.DLL::GetModuleHandleW` via IAT slot `0x00419480`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00406718: unsafe extern "C" fn(usize) -> usize = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00406718(lpModuleName: usize) -> usize {
    HOOK_00406718(lpModuleName)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406718, fn_00406718};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize) -> usize {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x6718
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00406718 = hook };
        assert_eq!(unsafe { fn_00406718(11) }, 0x6718);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
