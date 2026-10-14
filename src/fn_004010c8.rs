//! Original procedure `0x004010c8` (6 bytes, `0x004010c8–0x0040a5`).
//! Evidence: `evidence/004010c8_fn_004010c8.md`.
//!
//! Import thunk `USER32.DLL::CharNextW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize) -> usize {
    0
}

/// Thunk `USER32.DLL::CharNextW` via IAT slot `0x00419330`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004010C8: unsafe extern "C" fn(usize) -> usize = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004010c8(lpsz: usize) -> usize {
    HOOK_004010C8(lpsz)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004010C8, fn_004010c8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize) -> usize {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x50C8
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004010C8 = hook };
        assert_eq!(unsafe { fn_004010c8(0x1000) }, 0x50C8);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
