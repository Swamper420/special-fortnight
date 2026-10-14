//! Original procedure `0x004066f8` (6 bytes, `0x004066f8–0x004066fd`).
//! Evidence: `evidence/004066f8_fn_004066f8.md`.
//!
//! Import thunk `KERNEL32.DLL::GetFullPathNameW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize, a1: u32, a2: usize, a3: usize) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::GetFullPathNameW` via IAT slot `0x00419490`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004066F8: unsafe extern "C" fn(usize, u32, usize, usize) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004066f8(lpFileName: usize, nBufferLength: u32, lpBuffer: usize, lpFilePart: usize) -> u32 {
    HOOK_004066F8(lpFileName, nBufferLength, lpBuffer, lpFilePart)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004066F8, fn_004066f8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: u32, a2: usize, a3: usize) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        A3.store(a3 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x66F8
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004066F8 = hook };
        assert_eq!(unsafe { fn_004066f8(11, 12, 13, 14) }, 0x66F8);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(A1.load(Ordering::SeqCst), 12);
        assert_eq!(A2.load(Ordering::SeqCst), 13);
        assert_eq!(A3.load(Ordering::SeqCst), 14);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
