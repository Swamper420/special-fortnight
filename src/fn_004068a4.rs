//! Original procedure `0x004068a4` (6 bytes, `0x004068a4–0x004068a9`).
//! Evidence: `evidence/004068a4_fn_004068a4.md`.
//!
//! Import thunk `USER32.DLL::ExitWindowsEx`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_u_flags: u32, _dw_reason: u32) -> u32 {
    0
}

/// Thunk `USER32.DLL::ExitWindowsEx` via IAT slot `0x004193f0`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004068A4: unsafe extern "C" fn(u32, u32) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004068a4(u_flags: u32, dw_reason: u32) -> u32 {
    HOOK_004068A4(u_flags, dw_reason)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004068A4, fn_004068a4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: u32, a1: u32) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004068A4 = hook };
        assert_eq!(unsafe { fn_004068a4(4, 0) }, 1);
        assert_eq!(A0.load(Ordering::SeqCst), 4 as usize);
        assert_eq!(A1.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
