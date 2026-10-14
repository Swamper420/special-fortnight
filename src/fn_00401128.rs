//! Original procedure `0x00401128` (6 bytes, `0x00401128–0x0040a5`).
//! Evidence: `evidence/00401128_fn_00401128.md`.
//!
//! Import thunk `KERNEL32.DLL::GetThreadLocale`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook() -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::GetThreadLocale` via IAT slot `0x00419374`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00401128: unsafe extern "C" fn() -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00401128() -> u32 {
    HOOK_00401128()
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401128, fn_00401128};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);


    unsafe extern "C" fn hook() -> u32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        0
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00401128 = hook };
        assert_eq!(unsafe { fn_00401128() }, 0);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
