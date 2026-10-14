//! Original procedure `0x0040681c` (6 bytes, `0x0040681c–0x00406821`).
//! Evidence: `evidence/0040681c_fn_0040681c.md`.
//!
//! Import thunk `KERNEL32.DLL::SetErrorMode`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: u32) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::SetErrorMode` via IAT slot `0x00419438`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_0040681C: unsafe extern "C" fn(u32) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_0040681c(uMode: u32) -> u32 {
    HOOK_0040681C(uMode)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040681C, fn_0040681c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: u32) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x681C
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_0040681C = hook };
        assert_eq!(unsafe { fn_0040681c(11) }, 0x681C);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
