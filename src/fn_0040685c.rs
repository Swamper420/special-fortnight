//! Original procedure `0x0040685c` (6 bytes, `0x0040685c–0x00406861`).
//! Evidence: `evidence/0040685c_fn_0040685c.md`.
//!
//! Import thunk `KERNEL32.DLL::VirtualProtect`: single `JMP [IAT]` tail jump,
//! modeled as single call+return.

unsafe extern "C" fn default_hook(_lp_address: usize, _dw_size: u32, _fl_new: u32, _lp_old: usize) -> u32 {
    0
}

/// Thunk `KERNEL32.DLL::VirtualProtect` via IAT slot `0x00419418`.
///
/// ponytail: hook standing in for the import thunk, rewire to
/// `windows-sys` once import mapping proven.
pub static mut HOOK_0040685C: unsafe extern "C" fn(usize, u32, u32, usize) -> u32 = default_hook;

/// 1:1 thunk wrapper: forwards args, returns callee result.
pub unsafe fn fn_0040685c(lp_address: usize, dw_size: u32, fl_new: u32, lp_old: usize) -> u32 {
    HOOK_0040685C(lp_address, dw_size, fl_new, lp_old)
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040685C, fn_0040685c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static A0: AtomicUsize = AtomicUsize::new(0);
    static A1: AtomicUsize = AtomicUsize::new(0);
    static A2: AtomicUsize = AtomicUsize::new(0);
    static A3: AtomicUsize = AtomicUsize::new(0);
    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(a0: usize, a1: u32, a2: u32, a3: usize) -> u32 {
        A0.store(a0 as usize, Ordering::SeqCst);
        A1.store(a1 as usize, Ordering::SeqCst);
        A2.store(a2 as usize, Ordering::SeqCst);
        A3.store(a3 as usize, Ordering::SeqCst);
        HITS.fetch_add(1, Ordering::SeqCst);
        1
    }

    #[test]
    fn forwards_args_and_result() {
        unsafe { HOOK_0040685C = hook };
        assert_eq!(unsafe { fn_0040685c(0x3000, 0x1000, 4, 0x4000) }, 1);
        assert_eq!(A0.load(Ordering::SeqCst), 0x3000 as usize);
        assert_eq!(A1.load(Ordering::SeqCst), 0x1000 as usize);
        assert_eq!(A2.load(Ordering::SeqCst), 4 as usize);
        assert_eq!(A3.load(Ordering::SeqCst), 0x4000 as usize);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
    }
}
