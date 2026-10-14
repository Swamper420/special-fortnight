//! Original procedure `0x004067f4` (6 bytes, `0x004067f4–0x004067f9`).
//! Evidence: `evidence/004067f4_fn_004067f4.md`.
//!
//! Import thunk `KERNEL32.DLL::MultiByteToWideChar`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: u32, a1: u32, a2: usize, a3: i32, a4: usize, a5: i32) -> i32 {
    0
}

/// Thunk `KERNEL32.DLL::MultiByteToWideChar` via IAT slot `0x0041944c`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004067F4: unsafe extern "C" fn(u32, u32, usize, i32, usize, i32) -> i32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004067f4(CodePage: u32, dwFlags: u32, lpMultiByteStr: usize, cbMultiByte: i32, lpWideCharStr: usize, cchWideChar: i32) -> i32 {
    HOOK_004067F4(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004067F4, fn_004067f4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);
    static A4: AtomicUsize = AtomicUsize::new(0);
    static A5: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: u32, a1: u32, a2: usize, a3: i32, a4: usize, a5: i32) -> i32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        A3.store(a3 as usize, Ordering::SeqCst);
        A4.store(a4 as usize, Ordering::SeqCst);
        A5.store(a5 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x67F4
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004067F4 = hook };
        assert_eq!(unsafe { fn_004067f4(11, 12, 13, 14, 15, 16) }, 0x67F4);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(A1.load(Ordering::SeqCst), 12);
        assert_eq!(A2.load(Ordering::SeqCst), 13);
        assert_eq!(A3.load(Ordering::SeqCst), 14);
        assert_eq!(A4.load(Ordering::SeqCst), 15);
        assert_eq!(A5.load(Ordering::SeqCst), 16);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
