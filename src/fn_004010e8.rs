//! Original procedure `0x004010e8` (6 bytes, `0x004010e8–0x004010ed`).
//! Evidence: `evidence/004010e8_fn_004010e8.md`.
//!
//! Import thunk `KERNEL32.DLL::FindFirstFileW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize, a1: usize) -> usize {
    0
}

/// Thunk `KERNEL32.DLL::FindFirstFileW` via IAT slot `0x00419394`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004010E8: unsafe extern "C" fn(usize, usize) -> usize = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004010e8(lp_file_name: usize, lp_find_data: usize) -> usize {
    HOOK_004010E8(lp_file_name, lp_find_data)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004010E8, fn_004010e8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: usize) -> usize {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x50E8
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004010E8 = hook };
        assert_eq!(unsafe { fn_004010e8(0x1000, 0x1001) }, 0x50E8);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000);
        assert_eq!(A1.load(Ordering::SeqCst), 0x1001);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
