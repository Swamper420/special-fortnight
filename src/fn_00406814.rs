//! Original procedure `0x00406814` (6 bytes, `0x00406814–0x00406819`).
//! Evidence: `evidence/00406814_fn_00406814.md`.
//!
//! Import thunk `KERNEL32.DLL::SetEndOfFile`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::SetEndOfFile` via IAT slot `0x0041943c`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00406814: unsafe extern "C" fn(usize) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00406814(hFile: usize) -> u32 {
    HOOK_00406814(hFile)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406814, fn_00406814};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x6814
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00406814 = hook };
        assert_eq!(unsafe { fn_00406814(11) }, 0x6814);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
