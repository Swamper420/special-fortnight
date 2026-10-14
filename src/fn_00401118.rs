//! Original procedure `0x00401118` (6 bytes, `0x00401118–0x0040a5`).
//! Evidence: `evidence/00401118_fn_00401118.md`.
//!
//! Import thunk `KERNEL32.DLL::GetProcAddress`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize, a1: usize) -> usize {
    0
}

/// Thunk `KERNEL32.DLL::GetProcAddress` via IAT slot `0x0041937c`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00401118: unsafe extern "C" fn(usize, usize) -> usize = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00401118(h_module: usize, lp_proc_name: usize) -> usize {
    HOOK_00401118(h_module, lp_proc_name)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401118, fn_00401118};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: usize) -> usize {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x5018
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00401118 = hook };
        assert_eq!(unsafe { fn_00401118(0x1000, 0x1001) }, 0x5018);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000);
        assert_eq!(A1.load(Ordering::SeqCst), 0x1001);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
