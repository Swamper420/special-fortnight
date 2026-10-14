//! Original procedure `0x00401130` (6 bytes, `0x00401130–0x0040a5`).
//! Evidence: `evidence/00401130_fn_00401130.md`.
//!
//! Import thunk `KERNEL32.DLL::LoadLibraryExW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize, a1: usize, a2: u32) -> usize {
    0
}

/// Thunk `KERNEL32.DLL::LoadLibraryExW` via IAT slot `0x00419370`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00401130: unsafe extern "C" fn(usize, usize, u32) -> usize = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00401130(lp_lib_file: usize, h_file: usize, dw_flags: u32) -> usize {
    HOOK_00401130(lp_lib_file, h_file, dw_flags)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401130, fn_00401130};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: usize, a2: u32) -> usize {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x5030
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00401130 = hook };
        assert_eq!(unsafe { fn_00401130(0x1000, 0x1001, 11) }, 0x5030);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000);
        assert_eq!(A1.load(Ordering::SeqCst), 0x1001);
        assert_eq!(A2.load(Ordering::SeqCst), 11);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
