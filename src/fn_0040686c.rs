//! Original procedure `0x0040686c` (6 bytes, `0x0040686c–0x00406871`).
//! Evidence: `evidence/0040686c_fn_0040686c.md`.
//!
//! Import thunk `KERNEL32.DLL::WaitForSingleObject`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_h_handle: usize, _ms: u32) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::WaitForSingleObject` via IAT slot `0x00419410`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_0040686C: unsafe extern "C" fn(usize, u32) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_0040686c(h_handle: usize, ms: u32) -> u32 {
    HOOK_0040686C(h_handle, ms)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040686C, fn_0040686c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: u32) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_0040686C = hook };
        assert_eq!(unsafe { fn_0040686c(0x1000, 0) }, 0);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000 as usize);
        assert_eq!(A1.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
