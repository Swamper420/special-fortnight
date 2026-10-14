//! Original procedure `0x0040687c` (6 bytes, `0x0040687c–0x00406881`).
//! Evidence: `evidence/0040687c_fn_0040687c.md`.
//!
//! Import thunk `KERNEL32.DLL::WriteFile`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_h_file: usize, _lp_buffer: usize, _n_to_write: u32, _lp_written: usize, _lp_overlapped: usize) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::WriteFile` via IAT slot `0x00419408`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_0040687C: unsafe extern "C" fn(usize, usize, u32, usize, usize) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_0040687c(h_file: usize, lp_buffer: usize, n_to_write: u32, lp_written: usize, lp_overlapped: usize) -> u32 {
    HOOK_0040687C(h_file, lp_buffer, n_to_write, lp_written, lp_overlapped)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040687C, fn_0040687c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);
    static A4: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: usize, a2: u32, a3: usize, a4: usize) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        A3.store(a3 as usize, Ordering::SeqCst);
        A4.store(a4 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_0040687C = hook };
        assert_eq!(unsafe { fn_0040687c(0x1000, 0x2000, 11, 0x3000, 0) }, 1);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000 as usize);
        assert_eq!(A1.load(Ordering::SeqCst), 0x2000 as usize);
        assert_eq!(A2.load(Ordering::SeqCst), 11 as usize);
        assert_eq!(A3.load(Ordering::SeqCst), 0x3000 as usize);
        assert_eq!(A4.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
