//! Original procedure `0x004068c4` (6 bytes, `0x004068c4–0x004068c9`).
//! Evidence: `evidence/004068c4_fn_004068c4.md`.
//!
//! Import thunk `USER32.DLL::MsgWaitForMultipleObjects`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_n_count: u32, _p_handles: usize, _f_wait_all: u32, _ms: u32, _wake_mask: u32) -> u32 {
    0
}

/// Thunk `USER32.DLL::MsgWaitForMultipleObjects` via IAT slot `0x004193e0`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004068C4: unsafe extern "C" fn(u32, usize, u32, u32, u32) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004068c4(n_count: u32, p_handles: usize, f_wait_all: u32, ms: u32, wake_mask: u32) -> u32 {
    HOOK_004068C4(n_count, p_handles, f_wait_all, ms, wake_mask)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004068C4, fn_004068c4};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);
    static A4: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: u32, a1: usize, a2: u32, a3: u32, a4: u32) -> u32 {
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
        unsafe { HOOK_004068C4 = hook };
        assert_eq!(unsafe { fn_004068c4(1, 0x1000, 0, 100, 0xff) }, 0);
        assert_eq!(A0.load(Ordering::SeqCst), 1 as usize);
        assert_eq!(A1.load(Ordering::SeqCst), 0x1000 as usize);
        assert_eq!(A2.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(A3.load(Ordering::SeqCst), 100 as usize);
        assert_eq!(A4.load(Ordering::SeqCst), 0xff as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
