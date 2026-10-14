//! Original procedure `0x00401120` (6 bytes, `0x00401120–0x00401125`).
//! Evidence: `evidence/00401120_fn_00401120.md`.
//!
//! Import thunk `KERNEL32.DLL::GetStartupInfoA`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize) {
    
}

/// Thunk `KERNEL32.DLL::GetStartupInfoA` via IAT slot `0x00419378`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00401120: unsafe extern "C" fn(usize) = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00401120(lp_startup_info: usize) {
    HOOK_00401120(lp_startup_info);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401120, fn_00401120};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static SEEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize) {
        A0.store(a0 as usize, Ordering::SeqCst);
        SEEN.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00401120 = hook };
        unsafe { fn_00401120(0x1000) };
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000);
        assert_eq!(SEEN.load(Ordering::SeqCst), 1);
    }
}
