//! Original procedure `0x00406844` (6 bytes, `0x00406844–0x00406849`).
//! Evidence: `evidence/00406844_fn_00406844.md`.
//!
//! Import thunk `KERNEL32.DLL::SizeofResource`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_h_module: usize, _h_res_info: usize) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::SizeofResource` via IAT slot `0x00419424`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00406844: unsafe extern "C" fn(usize, usize) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00406844(h_module: usize, h_res_info: usize) -> u32 {
    HOOK_00406844(h_module, h_res_info)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406844, fn_00406844};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: usize) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        9
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00406844 = hook };
        assert_eq!(unsafe { fn_00406844(0x1000, 0x2000) }, 9);
        assert_eq!(A0.load(Ordering::SeqCst), 0x1000 as usize);
        assert_eq!(A1.load(Ordering::SeqCst), 0x2000 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
