//! Original procedure `0x004010a0` (6 bytes, `0x004010a0–0x004010a5`).
//! Evidence: `evidence/004010a0_fn_004010a0.md`.
//!
//! Import thunk `KERNEL32.DLL::GetStdHandle`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: u32) -> usize {
    0
}

/// Thunk `KERNEL32.DLL::GetStdHandle` via IAT slot `0x004193b0`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004010A0: unsafe extern "C" fn(u32) -> usize = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004010a0(n_std_handle: u32) -> usize {
    HOOK_004010A0(n_std_handle)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004010A0, fn_004010a0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: u32) -> usize {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x50A0
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004010A0 = hook };
        assert_eq!(unsafe { fn_004010a0(11) }, 0x50A0);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
