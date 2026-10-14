//! Original procedure `0x004010d0` (6 bytes, `0x004010d0–0x004010d5`).
//! Evidence: `evidence/004010d0_fn_004010d0.md`.
//!
//! Import thunk `KERNEL32.DLL::ExitProcess`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: u32) {
    
}

/// Thunk `KERNEL32.DLL::ExitProcess` via IAT slot `0x0041939c`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004010D0: unsafe extern "C" fn(u32) = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004010d0(u_exit_code: u32) {
    HOOK_004010D0(u_exit_code);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004010D0, fn_004010d0};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static SEEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: u32) {
        A0.store(a0 as usize, Ordering::SeqCst);
        SEEN.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004010D0 = hook };
        unsafe { fn_004010d0(11) };
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(SEEN.load(Ordering::SeqCst), 1);
    }
}
