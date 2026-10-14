//! Original procedure `0x004010c0` (6 bytes, `0x004010c0–0x004010c5`).
//! Evidence: `evidence/004010c0_fn_004010c0.md`.
//!
//! Import thunk `KERNEL32.DLL::WriteFile`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize, a1: usize, a2: u32, a3: usize, a4: usize) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::WriteFile` via IAT slot `0x004193a0`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004010C0: unsafe extern "C" fn(usize, usize, u32, usize, usize) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004010c0(h_file: usize, lp_buffer: usize, n_to_write: u32, lp_written: usize, lp_overlapped: usize) -> u32 {
    HOOK_004010C0(h_file, lp_buffer, n_to_write, lp_written, lp_overlapped)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004010C0, fn_004010c0};
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
        0
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004010C0 = hook };
        assert_eq!(unsafe { fn_004010c0(0x1000, 0x1001, 11, 0x1003, 0x1004) }, 0);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000);
        assert_eq!(A1.load(Ordering::SeqCst), 0x1001);
        assert_eq!(A2.load(Ordering::SeqCst), 11);
        assert_eq!(A3.load(Ordering::SeqCst), 0x1003);
        assert_eq!(A4.load(Ordering::SeqCst), 0x1004);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
