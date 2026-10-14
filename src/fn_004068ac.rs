//! Original procedure `0x004068ac` (6 bytes, `0x004068ac–0x004068b1`).
//! Evidence: `evidence/004068ac_fn_004068ac.md`.
//!
//! Import thunk `USER32.DLL::GetSystemMetrics`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_n_index: i32) -> i32 {
    0
}

/// Thunk `USER32.DLL::GetSystemMetrics` via IAT slot `0x004193ec`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004068AC: unsafe extern "C" fn(i32) -> i32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004068ac(n_index: i32) -> i32 {
    HOOK_004068AC(n_index)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004068AC, fn_004068ac};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: i32) -> i32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        640
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004068AC = hook };
        assert_eq!(unsafe { fn_004068ac(0) }, 640);
        assert_eq!(A0.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
