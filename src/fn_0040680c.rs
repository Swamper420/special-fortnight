//! Original procedure `0x0040680c` (6 bytes, `0x0040680c–0x00406811`).
//! Evidence: `evidence/0040680c_fn_0040680c.md`.
//!
//! Import thunk `KERNEL32.DLL::ResetEvent`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::ResetEvent` via IAT slot `0x00419440`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_0040680C: unsafe extern "C" fn(usize) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_0040680c(hEvent: usize) -> u32 {
    HOOK_0040680C(hEvent)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040680C, fn_0040680c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x680C
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_0040680C = hook };
        assert_eq!(unsafe { fn_0040680c(11) }, 0x680C);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
