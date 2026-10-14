//! Original procedure `0x004010f8` (6 bytes, `0x004010f8–0x0040a5`).
//! Evidence: `evidence/004010f8_fn_004010f8.md`.
//!
//! Import thunk `KERNEL32.DLL::GetCommandLineW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook() -> usize {
    0
}

/// Thunk `KERNEL32.DLL::GetCommandLineW` via IAT slot `0x0041938c`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004010F8: unsafe extern "C" fn() -> usize = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004010f8() -> usize {
    HOOK_004010F8()
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004010F8, fn_004010f8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);


    unsafe extern "C" fn hook() -> usize {
        HITS.fetch_add(1, Ordering::SeqCst);
        0x50F8
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004010F8 = hook };
        assert_eq!(unsafe { fn_004010f8() }, 0x50F8);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
