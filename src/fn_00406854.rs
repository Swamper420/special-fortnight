//! Original procedure `0x00406854` (6 bytes, `0x00406854–0x00406859`).
//! Evidence: `evidence/00406854_fn_00406854.md`.
//!
//! Import thunk `KERNEL32.DLL::VirtualFree`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_lp_address: usize, _dw_size: u32, _dw_free_type: u32) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::VirtualFree` via IAT slot `0x0041941c`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_00406854: unsafe extern "C" fn(usize, u32, u32) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_00406854(lp_address: usize, dw_size: u32, dw_free_type: u32) -> u32 {
    HOOK_00406854(lp_address, dw_size, dw_free_type)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00406854, fn_00406854};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: u32, a2: u32) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_00406854 = hook };
        assert_eq!(unsafe { fn_00406854(0x3000, 0, 0x8000) }, 1);
        assert_eq!(A0.load(Ordering::SeqCst), 0x3000 as usize);
        assert_eq!(A1.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(A2.load(Ordering::SeqCst), 0x8000 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
