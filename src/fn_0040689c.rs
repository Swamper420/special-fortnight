//! Original procedure `0x0040689c` (6 bytes, `0x0040689c–0x004068a1`).
//! Evidence: `evidence/0040689c_fn_0040689c.md`.
//!
//! Import thunk `USER32.DLL::DispatchMessageW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_lp_msg: usize) -> i32 {
    0
}

/// Thunk `USER32.DLL::DispatchMessageW` via IAT slot `0x004193f4`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_0040689C: unsafe extern "C" fn(usize) -> i32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_0040689c(lp_msg: usize) -> i32 {
    HOOK_0040689C(lp_msg)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040689C, fn_0040689c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize) -> i32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        2
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_0040689C = hook };
        assert_eq!(unsafe { fn_0040689c(0x1000) }, 2);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
