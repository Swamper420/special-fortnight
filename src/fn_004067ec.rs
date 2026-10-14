//! Original procedure `0x004067ec` (6 bytes, `0x004067ec–0x004067f1`).
//! Evidence: `evidence/004067ec_fn_004067ec.md`.
//!
//! Import thunk `KERNEL32.DLL::LockResource`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize) -> usize {
    0
}

/// Thunk `KERNEL32.DLL::LockResource` via IAT slot `0x00419450`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004067EC: unsafe extern "C" fn(usize) -> usize = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004067ec(hResData: usize) -> usize {
    HOOK_004067EC(hResData)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004067EC, fn_004067ec};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize) -> usize {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x67EC
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004067EC = hook };
        assert_eq!(unsafe { fn_004067ec(11) }, 0x67EC);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
