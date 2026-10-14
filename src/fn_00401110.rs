//! Original procedure `0x00401110` (6 bytes, `0x00401110–0x00401115`).
//! Evidence: `evidence/00401110_fn_00401110.md`.
//!
//! Import thunk `KERNEL32.DLL::GetModuleHandleW`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(a0: usize) -> usize {
    0
}

/// Thunk `KERNEL32.DLL::GetModuleHandleW` via IAT slot `0x00419380`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00401110: unsafe extern "C" fn(usize) -> usize = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00401110(lp_module_name: usize) -> usize {
    HOOK_00401110(lp_module_name)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00401110, fn_00401110};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static A0: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize) -> usize {
        A0.store(a0 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x5010
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00401110 = hook };
        assert_eq!(unsafe { fn_00401110(0x1000) }, 0x5010);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
