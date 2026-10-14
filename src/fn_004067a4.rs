//! Original procedure `0x004067a4` (6 bytes, `0x004067a4–0x004067a9`).
//! Evidence: `evidence/004067a4_fn_004067a4.md`.
//!
//! Import thunk `KERNEL32.DLL::GetSystemDirectoryW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize, a1: u32) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::GetSystemDirectoryW` via IAT slot `0x00419474`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004067A4: unsafe extern "C" fn(usize, u32) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004067a4(lpBuffer: usize, uSize: u32) -> u32 {
    HOOK_004067A4(lpBuffer, uSize)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004067A4, fn_004067a4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: u32) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x67A4
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004067A4 = hook };
        assert_eq!(unsafe { fn_004067a4(11, 12) }, 0x67A4);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(A1.load(Ordering::SeqCst), 12);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
