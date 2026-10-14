//! Original procedure `0x004067dc` (6 bytes, `0x004067dc–0x004067e1`).
//! Evidence: `evidence/004067dc_fn_004067dc.md`.
//!
//! Import thunk `KERNEL32.DLL::LoadLibraryW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize) -> usize {
    0
}

/// Thunk `KERNEL32.DLL::LoadLibraryW` via IAT slot `0x00419458`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004067DC: unsafe extern "C" fn(usize) -> usize = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004067dc(lpLibFileName: usize) -> usize {
    HOOK_004067DC(lpLibFileName)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004067DC, fn_004067dc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize) -> usize {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x67DC
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004067DC = hook };
        assert_eq!(unsafe { fn_004067dc(11) }, 0x67DC);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
