//! Original procedure `0x004068dc` (6 bytes, `0x004068dc–0x004068e1`).
//! Evidence: `evidence/004068dc_fn_004068dc.md`.
//!
//! Import thunk `USER32.DLL::TranslateMessage`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_lp_msg: usize) -> u32 {
    0
}

/// Thunk `USER32.DLL::TranslateMessage` via IAT slot `0x004193d4`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_004068DC: unsafe extern "C" fn(usize) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_004068dc(lp_msg: usize) -> u32 {
    HOOK_004068DC(lp_msg)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004068DC, fn_004068dc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_004068DC = hook };
        assert_eq!(unsafe { fn_004068dc(0x1000) }, 1);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
