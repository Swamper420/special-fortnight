//! Original procedure `0x0040684c` (6 bytes, `0x0040684c–0x00406851`).
//! Evidence: `evidence/0040684c_fn_0040684c.md`.
//!
//! Import thunk `KERNEL32.DLL::VirtualAlloc`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_lp_address: usize, _dw_size: u32, _fl_type: u32, _fl_protect: u32) -> usize {
    0
}

/// Thunk `KERNEL32.DLL::VirtualAlloc` via IAT slot `0x00419420`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_0040684C: unsafe extern "C" fn(usize, u32, u32, u32) -> usize = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_0040684c(lp_address: usize, dw_size: u32, fl_type: u32, fl_protect: u32) -> usize {
    HOOK_0040684C(lp_address, dw_size, fl_type, fl_protect)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040684C, fn_0040684c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: u32, a2: u32, a3: u32) -> usize {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        A3.store(a3 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        0x3000
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_0040684C = hook };
        assert_eq!(unsafe { fn_0040684c(0, 0x1000, 0x3000, 4) }, 0x3000);
        assert_eq!(A0.load(Ordering::SeqCst), 0 as usize);
        assert_eq!(A1.load(Ordering::SeqCst), 0x1000 as usize);
        assert_eq!(A2.load(Ordering::SeqCst), 0x3000 as usize);
        assert_eq!(A3.load(Ordering::SeqCst), 4 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
