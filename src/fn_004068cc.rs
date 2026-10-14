//! Original procedure `0x004068cc` (6 bytes, `0x004068cc–0x004068d1`).
//! Evidence: `evidence/004068cc_fn_004068cc.md`.
//!
//! Import thunk `USER32.DLL::PeekMessageW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_lp_msg: usize, _h_wnd: usize, _filt_min: u32, _filt_max: u32, _remove: u32) -> u32 {
    0
}

/// Thunk `USER32.DLL::PeekMessageW` via IAT slot `0x004193dc`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004068CC: unsafe extern "C" fn(usize, usize, u32, u32, u32) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004068cc(lp_msg: usize, h_wnd: usize, filt_min: u32, filt_max: u32, remove: u32) -> u32 {
    HOOK_004068CC(lp_msg, h_wnd, filt_min, filt_max, remove)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004068CC, fn_004068cc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);
    static A4: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: usize, a2: u32, a3: u32, a4: u32) -> u32 {
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
        unsafe { HOOK_004068CC = hook };
        assert_eq!(unsafe { fn_004068cc(0x1000, 0, 0, 0, 1) }, 0);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000 as usize);
        assert_eq!(A1.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(A2.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(A3.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(A4.load(Ordering::SeqCst), 1 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
