//! Original procedure `0x00401108` (6 bytes, `0x00401108–0x0040110d`).
//! Evidence: `evidence/00401108_fn_00401108.md`.
//!
//! Import thunk `KERNEL32.DLL::GetModuleFileNameW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize, a1: usize, a2: u32) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::GetModuleFileNameW` via IAT slot `0x00419384`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00401108: unsafe extern "C" fn(usize, usize, u32) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00401108(h_module: usize, lp_filename: usize, n_size: u32) -> u32 {
    HOOK_00401108(h_module, lp_filename, n_size)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401108, fn_00401108};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: usize, a2: u32) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00401108 = hook };
        assert_eq!(unsafe { fn_00401108(0x1000, 0x1001, 11) }, 0);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000);
        assert_eq!(A1.load(Ordering::SeqCst), 0x1001);
        assert_eq!(A2.load(Ordering::SeqCst), 11);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
