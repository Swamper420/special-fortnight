//! Original procedure `0x004067fc` (6 bytes, `0x004067fc–0x00406801`).
//! Evidence: `evidence/004067fc_fn_004067fc.md`.
//!
//! Import thunk `KERNEL32.DLL::ReadFile`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize, a1: usize, a2: u32, a3: usize, a4: usize) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::ReadFile` via IAT slot `0x00419448`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004067FC: unsafe extern "C" fn(usize, usize, u32, usize, usize) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004067fc(hFile: usize, lpBuffer: usize, nNumberOfBytesToRead: u32, lpNumberOfBytesRead: usize, lpOverlapped: usize) -> u32 {
    HOOK_004067FC(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004067FC, fn_004067fc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);
    static A4: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: usize, a2: u32, a3: usize, a4: usize) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        A3.store(a3 as usize, Ordering::SeqCst);
        A4.store(a4 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x67FC
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004067FC = hook };
        assert_eq!(unsafe { fn_004067fc(11, 12, 13, 14, 15) }, 0x67FC);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(A1.load(Ordering::SeqCst), 12);
        assert_eq!(A2.load(Ordering::SeqCst), 13);
        assert_eq!(A3.load(Ordering::SeqCst), 14);
        assert_eq!(A4.load(Ordering::SeqCst), 15);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
