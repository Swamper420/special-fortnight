//! Original procedure `0x00401140` (6 bytes, `0x00401140–0x0040a5`).
//! Evidence: `evidence/00401140_fn_00401140.md`.
//!
//! Import thunk `KERNEL32.DLL::lstrcpynW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize, a1: usize, a2: i32) -> usize {
    0
}

/// Thunk `KERNEL32.DLL::lstrcpynW` via IAT slot `0x0041936c`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00401140: unsafe extern "C" fn(usize, usize, i32) -> usize = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00401140(lp_string1: usize, lp_string2: usize, i_max_length: i32) -> usize {
    HOOK_00401140(lp_string1, lp_string2, i_max_length)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401140, fn_00401140};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: usize, a2: i32) -> usize {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x5040
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00401140 = hook };
        assert_eq!(unsafe { fn_00401140(0x1000, 0x1001, 12) }, 0x5040);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000);
        assert_eq!(A1.load(Ordering::SeqCst), 0x1001);
        assert_eq!(A2.load(Ordering::SeqCst), 12 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
