//! Original procedure `0x0040679c` (6 bytes, `0x0040679c–0x004067a1`).
//! Evidence: `evidence/0040679c_fn_0040679c.md`.
//!
//! Import thunk `KERNEL32.DLL::GetStdHandle`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: u32) -> usize {
    0
}

/// Thunk `KERNEL32.DLL::GetStdHandle` via IAT slot `0x00419478`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_0040679C: unsafe extern "C" fn(u32) -> usize = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_0040679c(nStdHandle: u32) -> usize {
    HOOK_0040679C(nStdHandle)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040679C, fn_0040679c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: u32) -> usize {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x679C
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_0040679C = hook };
        assert_eq!(unsafe { fn_0040679c(11) }, 0x679C);
        assert_eq!(A0.load(Ordering::SeqCst), 11);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
