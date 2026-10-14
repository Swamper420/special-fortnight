//! Original procedure `0x00406804` (6 bytes, `0x00406804–0x00406809`).
//! Evidence: `evidence/00406804_fn_00406804.md`.
//!
//! Import thunk `KERNEL32.DLL::RemoveDirectoryW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::RemoveDirectoryW` via IAT slot `0x00419444`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00406804: unsafe extern "C" fn(usize) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00406804(lpPathName: usize) -> u32 {
    HOOK_00406804(lpPathName)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406804, fn_00406804};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x6804
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00406804 = hook };
        assert_eq!(unsafe { fn_00406804(11) }, 0x6804);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
