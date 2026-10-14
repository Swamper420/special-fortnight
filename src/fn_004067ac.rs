//! Original procedure `0x004067ac` (6 bytes, `0x004067ac–0x004067b1`).
//! Evidence: `evidence/004067ac_fn_004067ac.md`.
//!
//! Import thunk `KERNEL32.DLL::GetSystemInfo`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize) {
}

/// Thunk `KERNEL32.DLL::GetSystemInfo` via IAT slot `0x00419470`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004067AC: unsafe extern "C" fn(usize) = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004067ac(lpSystemInfo: usize) {
    HOOK_004067AC(lpSystemInfo)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004067AC, fn_004067ac};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn hook(a0: usize) {
        HITS.fetch_add(1, Ordering::SeqCst);
    }
    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004067AC = hook };
        unsafe { fn_004067ac(0) };
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
