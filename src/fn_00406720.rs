//! Original procedure `0x00406720` (6 bytes, `0x00406720–0x00406725`).
//! Evidence: `evidence/00406720_fn_00406720.md`.
//!
//! Import thunk `KERNEL32.DLL::GetProcAddress`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize, a1: usize) -> usize {
    0
}

/// Thunk `KERNEL32.DLL::GetProcAddress` via IAT slot `0x0041947c`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00406720: unsafe extern "C" fn(usize, usize) -> usize = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00406720(hModule: usize, lpProcName: usize) -> usize {
    HOOK_00406720(hModule, lpProcName)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406720, fn_00406720};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: usize) -> usize {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x6720
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00406720 = hook };
        assert_eq!(unsafe { fn_00406720(11, 12) }, 0x6720);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(A1.load(Ordering::SeqCst), 12);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
