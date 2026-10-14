//! Original procedure `0x0040682c` (6 bytes, `0x0040682c–0x00406831`).
//! Evidence: `evidence/0040682c_fn_0040682c.md`.
//!
//! Import thunk `KERNEL32.DLL::SetFilePointer`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize, a1: i32, a2: usize, a3: u32) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::SetFilePointer` via IAT slot `0x00419430`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_0040682C: unsafe extern "C" fn(usize, i32, usize, u32) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_0040682c(hFile: usize, lDistanceToMove: i32, lpDistanceToMoveHigh: usize, dwMoveMethod: u32) -> u32 {
    HOOK_0040682C(hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040682C, fn_0040682c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: i32, a2: usize, a3: u32) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        A3.store(a3 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x682C
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_0040682C = hook };
        assert_eq!(unsafe { fn_0040682c(11, 12, 13, 14) }, 0x682C);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(A1.load(Ordering::SeqCst), 12);
        assert_eq!(A2.load(Ordering::SeqCst), 13);
        assert_eq!(A3.load(Ordering::SeqCst), 14);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
